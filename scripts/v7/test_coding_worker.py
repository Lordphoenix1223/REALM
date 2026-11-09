"""Protocol refusals and genuine local kernel-checker regression tests."""
import importlib.util
import json
import os
import pathlib
import platform
import sys
import time
from unittest.mock import patch
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("coding_worker", pathlib.Path(__file__).with_name("coding_worker.py"))
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="realm-coding-test-")
        self.root = pathlib.Path(self.temp.name) / "run"
        self.worker = worker.Worker(self.root, worker.digest(worker.encoded(worker.contract())))

    def tearDown(self):
        self.worker.close()
        self.temp.cleanup()

    def test_scope_and_no_shell(self):
        before = self.worker.tree()
        for request in ({"tool": "shell", "command": "echo hi"},
                        {"tool": "write", "path": "../escaped", "text": "x"},
                        {"tool": "write", "path": "/tmp/escaped", "text": "x"},
                        {"tool": "read", "path": "totals.py", "extra": True}):
            with self.assertRaises(ValueError):
                self.worker.request(request)
        self.assertEqual(self.worker.tree(), before)

    def test_finish_without_current_check_refuses(self):
        with self.assertRaises(ValueError):
            self.worker.request({"tool": "finish"})
        self.worker.last_check = (self.worker.tree(), True)
        self.worker.request({"tool": "write", "path": "totals.py", "text": "changed"})
        with self.assertRaises(ValueError):
            self.worker.request({"tool": "finish"})

    def test_links_refuse(self):
        file = self.worker.candidate / "totals.py"
        file.unlink()
        os.symlink(self.root / "protected-sentinel", file)
        with self.assertRaises((ValueError, OSError)):
            self.worker.tree()
        file.unlink()
        os.link(self.worker.candidate / "report.py", file)
        with self.assertRaises((ValueError, OSError)):
            self.worker.tree()

    def test_fifo_refuses_without_blocking(self):
        file = self.worker.candidate / "totals.py"
        file.unlink()
        os.mkfifo(file)
        with self.assertRaisesRegex(ValueError, "file identity refused"):
            self.worker.tree()

    @unittest.skipUnless(platform.system() == "Darwin", "macOS launcher selection")
    def test_virtual_environment_uses_base_interpreter(self):
        app = pathlib.Path(sys.base_prefix).resolve() / "Resources/Python.app/Contents/MacOS/Python"
        if not app.is_file():
            self.skipTest("Python installation has no app launcher")
        with patch.object(worker.sys, 'prefix', str(self.root / 'virtual-environment')):
            sandbox = worker.Sandbox(self.worker.candidate)
        self.assertEqual(sandbox.python, app.resolve())
        self.assertEqual(sandbox.prefix[3], str(app.resolve()))

    def test_duplicate_keys_refuse(self):
        with self.assertRaises(ValueError):
            worker.parse('{"tool":"read","tool":"write"}')

    def test_journal_reopens_independently(self):
        self.worker.request({"tool": "list"})
        previous = "0" * 64
        for n, line in enumerate((self.root / "events.jsonl").read_bytes().splitlines()):
            row = json.loads(line)
            claimed = row.pop("sha256")
            self.assertEqual(row["sequence"], n)
            self.assertEqual(row["previous"], previous)
            self.assertEqual(claimed, worker.digest(worker.encoded(row)))
            previous = claimed


class TransportDeadlineTests(unittest.TestCase):
    """Actual shared-pipe controls only; no containment/qualification claim."""
    def test_nonreading_child_cannot_block_before_deadline(self):
        with tempfile.TemporaryDirectory(prefix='realm-stdin-deadline-') as root:
            sandbox = object.__new__(worker.Sandbox)
            sandbox.prefix = [sys.executable, '-I', '-B']
            sandbox.candidate = pathlib.Path(root)
            sandbox.backend = platform.system()
            sandbox.evidence_channel_guard = False
            children = []
            original = worker.subprocess.Popen
            def observe(*args, **kwargs):
                child = original(*args, **kwargs); children.append(child); return child
            start = time.monotonic()
            with patch.object(worker.subprocess, 'Popen', side_effect=observe):
                with self.assertRaisesRegex(ValueError, 'candidate timeout'):
                    sandbox.execute('import time;time.sleep(7)', b'x' * (1024 * 1024))
            self.assertLess(time.monotonic()-start, 6)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(all(p.closed for p in (children[0].stdin, children[0].stdout, children[0].stderr)))
            print('SHARED_TRANSPORT_DEADLINE=PASS over_capacity=true child_reaped=true authority=NONE')

    def test_input_and_output_are_drained_together(self):
        with tempfile.TemporaryDirectory(prefix='realm-pipe-drain-') as root:
            sandbox = object.__new__(worker.Sandbox)
            sandbox.prefix = [sys.executable, '-I', '-B']
            sandbox.candidate = pathlib.Path(root)
            sandbox.backend = platform.system()
            sandbox.evidence_channel_guard = False
            code, out, err = sandbox.execute("import sys;sys.stdout.write('x'*12000);sys.stdout.flush();data=sys.stdin.buffer.read();print(len(data))", b'x'*(1024*1024))
            self.assertEqual(code, 0, err)
            self.assertEqual(out, b'x'*12000+b'1048576\n')


if __name__ == "__main__":
    unittest.main()
