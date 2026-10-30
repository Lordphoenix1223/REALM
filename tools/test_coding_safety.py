"""Fault-injection controls for controller I/O and independently reopened results.

These are transport/filesystem tests, never substitutes for the real coding run.
"""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

EXAMPLE = Path(__file__).resolve().parents[1] / 'examples/coding'
sys.path.insert(0, str(EXAMPLE))
import run as coding_run
import verify_coding_development as audit


class WorkerTransportTests(unittest.TestCase):
    def child(self, body):
        p = subprocess.Popen([sys.executable, '-I', '-B', '-c', body],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True)
        def cleanup():
            if p.stdin.closed and p.stdout.closed:
                return
            coding_run.stop_group(p)
            p.stdin.close(); p.stdout.close()
        self.addCleanup(cleanup)
        return p, coding_run.WorkerChannel(p)

    def test_partial_response_cannot_escape_deadline(self):
        _, channel = self.child("import sys,time;sys.stdin.readline();print('{',end='',flush=True);time.sleep(10)")
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'timeout'):
            channel.exchange({'tool': 'list'}, timeout=.2)
        self.assertLess(time.monotonic() - start, 2)

    def test_blocked_request_write_has_a_deadline(self):
        _, channel = self.child('import time;time.sleep(10)')
        with self.assertRaisesRegex(ValueError, 'timeout'):
            channel.exchange({'text': 'x' * 80000}, timeout=.2)

    def test_early_eof_and_non_object_frames_refuse(self):
        for body in ["import sys;sys.stdin.readline()", "import sys;sys.stdin.readline();print('[]',flush=True)"]:
            with self.subTest(body=body):
                _, channel = self.child(body)
                with self.assertRaises(ValueError):
                    channel.exchange({'tool': 'list'}, timeout=1)

    def test_oversize_and_duplicate_key_responses_refuse(self):
        for body in ["import sys;sys.stdin.readline();print('x'*600000,flush=True)",
                     "import sys;sys.stdin.readline();print('{\"x\":1,\"x\":2}',flush=True)"]:
            with self.subTest(body=body):
                _, channel = self.child(body)
                with self.assertRaises(ValueError):
                    channel.exchange({'tool': 'list'}, timeout=2)

    def test_post_terminal_output_refuses(self):
        _, channel = self.child("import sys;sys.stdin.readline();print('{}',flush=True);sys.stdin.read();print('extra',flush=True)")
        self.assertEqual(channel.exchange({'tool': 'finish'}, timeout=1), {})
        with self.assertRaisesRegex(ValueError, 'after terminal'):
            channel.finish(timeout=1)

    def test_inherited_pipe_cannot_hide_missing_eof(self):
        p, channel = self.child("import sys,subprocess;sys.stdin.readline();subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)']);print('{}',flush=True)")
        channel.exchange({'tool': 'finish'}, timeout=1)
        with self.assertRaisesRegex(ValueError, 'EOF timeout'):
            channel.finish(timeout=.2)
        coding_run.stop_group(p)
        with selectors.DefaultSelector() as ready:
            ready.register(p.stdout, selectors.EVENT_READ)
            self.assertTrue(ready.select(2))
            self.assertEqual(os.read(p.stdout.fileno(), 1), b'')
        p.stdin.close(); p.stdout.close()


class ReopenedFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'replay'; self.root.mkdir(mode=0o700)
        self.expected = {}
        for name in audit.FILES:
            p = self.root/name; p.write_bytes(name.encode()); p.chmod(0o600)
            self.expected[name] = audit.sha(p.read_bytes())

    def test_valid_files_are_reopened_without_authority(self):
        self.assertEqual(audit.verify_final_state(self.root, self.expected)['authority'], 'NONE')

    def test_extra_file_wrong_mode_and_changed_bytes_refuse(self):
        extra = self.root/'extra'; extra.touch()
        with self.assertRaises(ValueError): audit.verify_final_state(self.root, self.expected)
        extra.unlink(); p = self.root/'totals.py'; p.chmod(0o644)
        with self.assertRaises(ValueError): audit.verify_final_state(self.root, self.expected)
        p.chmod(0o600); p.write_bytes(b'changed')
        with self.assertRaises(ValueError): audit.verify_final_state(self.root, self.expected)

    def test_symlink_hardlink_and_fifo_refuse_without_blocking(self):
        p = self.root/'totals.py'; original = p.read_bytes(); outside = self.root.parent/'outside'
        outside.write_bytes(original); outside.chmod(0o600)
        for kind in ['symlink', 'hardlink', 'fifo']:
            with self.subTest(kind=kind):
                p.unlink()
                if kind == 'symlink': p.symlink_to(outside)
                elif kind == 'hardlink': os.link(outside, p)
                else: os.mkfifo(p, 0o600)
                with self.assertRaises((ValueError, OSError)):
                    audit.verify_final_state(self.root, self.expected)
        self.assertEqual(outside.read_bytes(), original)

    def test_linked_directory_and_noncanonical_hashes_refuse(self):
        link = self.root.parent/'linked'; link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): audit.verify_final_state(link, self.expected)
        with self.assertRaises(ValueError): audit.verify_final_state(self.root, {'../escape':'0'*64})

    def test_same_byte_replacement_during_read_is_not_adopted(self):
        p = self.root/'totals.py'; raw = p.read_bytes(); inode = p.stat().st_ino
        original_read = os.read; changed = False
        def replace(fd, count):
            nonlocal changed
            chunk = original_read(fd, count)
            if not changed and os.fstat(fd).st_ino == inode:
                changed = True
                other = self.root/'replacement'; other.write_bytes(raw); other.chmod(0o600); other.replace(p)
            return chunk
        with mock.patch.object(audit.os, 'read', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'identity changed|replaced'):
                audit.verify_final_state(self.root, self.expected)
        self.assertTrue(changed)

    def test_fifo_task_input_fails_before_creating_output(self):
        fifo = self.root.parent/'task'; os.mkfifo(fifo, 0o600)
        result = subprocess.run([sys.executable, '-B', str(EXAMPLE/'run.py'), '--task', str(fifo),
            '--checker', sys.executable, '--output', str(self.root.parent/'output')],
            capture_output=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'nonregular', result.stderr)
        self.assertFalse((self.root.parent/'output').exists())


if __name__ == '__main__':
    unittest.main()
