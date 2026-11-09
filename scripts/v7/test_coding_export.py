#!/usr/bin/env python3
"""Development export refusal controls. No execution authority is constructed."""
import copy
import os
import sys
import subprocess
import io
import tarfile
import socket
import threading
import time
import pathlib
import tempfile
import types
import unittest
import signal
from unittest import mock
import coding_guest_boot as boot

import coding_export as export
import coding_worker as worker
import receive_coding_raw as raw
import coding_guest_probe as probe
import offline_coding_agent as agent


class ExportControls(unittest.TestCase):
    def body(self):
        return {'schema': 'realm.coding-development-export.v1', 'authority': 'NONE',
                'realm_artifact': None, 'run_id': '1' * 64, 'worker_sha256': '2' * 64,
                'transcript_head': '3' * 64,
                'task_sha256': worker.digest(worker.encoded(worker.contract())),
                'files': [{'path': n, 'text': '# development fixture\n', 'mode': 0o600}
                          for n in worker.FILES]}

    def test_bad_identity_and_projection_refuse_before_quarantine(self):
        body = self.body()
        data = worker.encoded(body)
        pin = worker.digest(data)
        mutations = [dict(run_id='4' * 64), dict(worker_sha256='4' * 64),
                     dict(journal_head='4' * 64), dict(export_sha256='4' * 64)]
        for field in ('path', 'mode', 'text'):
            changed = copy.deepcopy(body)
            changed['files'][1][field] = {'path': '../unauthorized.py', 'mode': True,
                                         'text': 'x' * (worker.MAX_BYTES + 1)}[field]
            mutations.append({'data': worker.encoded(changed)})
        changed = copy.deepcopy(body)
        changed['files'].reverse()
        mutations.append({'data': worker.encoded(changed)})
        changed = copy.deepcopy(body)
        changed['authority'] = 'ACCEPT'
        mutations.append({'data': worker.encoded(changed)})
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            source = base / 'incoming.json'
            for index, change in enumerate(mutations):
                incoming = change.get('data', data)
                source.write_bytes(incoming)
                root = base / f'quarantine-{index}'
                args = types.SimpleNamespace(export=source, root=root, seed=1,
                    export_sha256=worker.digest(incoming) if 'data' in change else pin,
                    run_id='1' * 64, worker_sha256='2' * 64, journal_head='3' * 64)
                for key, value in change.items():
                    if key != 'data':
                        setattr(args, key, value)
                with self.subTest(change=change.keys()), self.assertRaises(ValueError):
                    export.verify(args)
                self.assertFalse(root.exists())
            self.assertEqual([p.name for p in base.iterdir()], ['incoming.json'])

    def test_workflow_guard_rejects_injected_tools_before_any_effect(self):
        # Real worker files/journal and real failed oracle checks. No model,
        # reference patch, successful task fixture or authority is constructed.
        with tempfile.TemporaryDirectory() as directory:
            w = worker.Worker(pathlib.Path(directory) / 'run',
                              worker.digest(worker.encoded(worker.contract())))
            initial = w.tree()
            def refuse(action):
                before = (w.tree(), (w.root / 'events.jsonl').read_bytes(),
                          {p: (w.candidate / p).stat().st_ino for p in worker.FILES})
                with self.assertRaises(ValueError):
                    agent.guarded_request(w, initial, action)
                after = (w.tree(), (w.root / 'events.jsonl').read_bytes(),
                         {p: (w.candidate / p).stat().st_ino for p in worker.FILES})
                self.assertEqual(before, after)
                self.assertFalse(w.done)
            try:
                for action in ({'tool': 'check'}, {'tool': 'finish'},
                               {'tool': 'read', 'path': 'totals.py'},
                               {'tool': 'write', 'path': '../escape', 'text': 'x'},
                               {'tool': 'write', 'path': 'totals.py', 'text': 'x', 'extra': 1},
                               {'tool': 'write', 'path': 'totals.py', 'text': 'x' * 1025}):
                    refuse(action)
                for name in worker.FILES:
                    agent.guarded_request(w, initial, {'tool': 'write', 'path': name,
                        'text': worker.BASELINE[name] + '# changed development bytes\n'})
                    if name != worker.FILES[-1]:
                        refuse({'tool': 'write', 'path': name, 'text': '# out of phase\n'})
                refuse({'tool': 'finish'})
                refuse({'tool': 'write', 'path': 'totals.py', 'text': '# skip check\n'})
                result = agent.guarded_request(w, initial, {'tool': 'check'})
                self.assertFalse(result['passed'])
                refuse({'tool': 'finish'})
                refuse({'tool': 'write', 'path': 'totals.py',
                        'text': worker.regular_read(w.fd, 'totals.py').decode()})
                stale = w.tree()
                agent.guarded_request(w, initial, {'tool': 'write', 'path': 'totals.py',
                    'text': worker.BASELINE['totals.py'] + '# another changed edit\n'})
                refuse({'tool': 'write', 'path': 'report.py', 'text': '# skip recheck\n'})
                w.last_check = (stale, True)  # stale-check adversarial fixture only
                refuse({'tool': 'finish'})
                result = agent.guarded_request(w, initial, {'tool': 'check'})
                self.assertFalse(result['passed'])
                self.assertFalse((pathlib.Path(directory) / 'escape').exists())
            finally:
                w.close()

    def test_unfinished_run_cannot_freeze(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            launch = worker.encoded({'authority': 'NONE',
                                     'source_files': {'coding_worker.py': '2' * 64}})
            (root / 'launch.json').write_bytes(launch)
            (root / 'agent-report.json').write_bytes(worker.encoded({
                'status': 'NOT_COMPLETE', 'authority': 'NONE', 'realm_artifact': None}))
            output = root / 'export.json'
            args = types.SimpleNamespace(agent_root=root, run_id=worker.digest(launch),
                worker_sha256='2' * 64, output=output)
            with self.assertRaisesRegex(ValueError, 'did not finish'):
                export.freeze(args)
            self.assertFalse(output.exists())

    def test_received_raw_validates_all_objects_before_any_creation(self):
        def archive(extra):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
                rows = [('launch.json', worker.encoded({'authority': 'NONE', 'challenge': 'bound'})),
                        ('agent-report.json', worker.encoded({'authority': 'NONE', 'realm_artifact': None})),
                        *extra]
                for name, content in rows:
                    item = tarfile.TarInfo(name)
                    item.size, item.mode = len(content), 0o600
                    if name == 'run/candidate/totals.py':
                        item.type, item.linkname, item.size = tarfile.SYMTYPE, '/outside', 0
                    tar.addfile(item, io.BytesIO(content))
            return buffer.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            for index, extra in enumerate([[('../escape', b'x')], [('launch.json', b'{}')],
                                            [('run/candidate/totals.py', b'')]]):
                data = archive(extra)
                source = base / f'{index}.gz'
                source.write_bytes(data)
                args = types.SimpleNamespace(raw=source, raw_sha256=worker.digest(data),
                                             challenge='bound', root=base / f'q{index}')
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    raw.receive(args)
                self.assertFalse(args.root.exists())
            data = archive([])
            source = base / 'valid.gz'
            source.write_bytes(data)
            args = types.SimpleNamespace(raw=source, raw_sha256=worker.digest(data),
                                         challenge='wrong', root=base / 'valid')
            with self.assertRaisesRegex(ValueError, 'challenge differs'):
                raw.receive(args)
            self.assertFalse(args.root.exists())
            args.challenge = 'bound'
            self.assertEqual(raw.receive(args)['authority'], 'NONE')
            self.assertEqual(set(p.name for p in args.root.iterdir()),
                             {'launch.json', 'agent-report.json', 'raw-custody.json'})

    def test_api_204_does_not_wait_for_persistent_connection_close(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'api.sock'
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen()
            done = threading.Event()
            def respond():
                with server.accept()[0] as connection:
                    connection.recv(4096)
                    connection.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n')
                    done.wait(3)
            thread = threading.Thread(target=respond)
            thread.start()
            started = time.monotonic()
            try:
                self.assertIsNone(probe.api(path, 'PUT', '/boot-source', {}))
                self.assertLess(time.monotonic() - started, 1)
            finally:
                done.set()
                thread.join(timeout=4)
                server.close()
            self.assertFalse(thread.is_alive())

    @unittest.skipUnless(sys.platform == 'linux', 'actual Linux fd flags required')
    def test_python_timeout_descriptor_is_restored_before_native_custody_handoff(self):
        import fcntl
        from coding_native_probe import blocking_handoff
        client, server = socket.socketpair()
        try:
            client.settimeout(10)
            self.assertTrue(fcntl.fcntl(client.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
            observed = blocking_handoff(client)
            self.assertTrue(observed['before_flags'] & os.O_NONBLOCK)
            self.assertFalse(observed['after_flags'] & os.O_NONBLOCK)
            self.assertEqual(observed['authority'], 'NONE')
            client.sendall(b'actual blocking custody descriptor')
            self.assertEqual(server.recv(100), b'actual blocking custody descriptor')
        finally:
            client.close(); server.close()

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfd required')
    def test_actual_pidfd_distinguishes_live_child_from_exited_incarnation(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        fd = os.pidfd_open(child.pid)
        try:
            self.assertFalse(probe.pidfd_exited(fd))
            self.assertFalse(probe.process_observation(child.pid, fd)['pidfd_exited'])
            child.kill()
            self.assertEqual(child.wait(timeout=3), -signal.SIGKILL)
            self.assertTrue(probe.pidfd_exited(fd))
            self.assertTrue(probe.process_observation(child.pid, fd)['pidfd_exited'])
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            os.close(fd)

    @unittest.skipUnless(hasattr(os, 'pidfd_open') and pathlib.Path('/dev/full').exists(),
                         'Linux pidfd and ENOSPC device required')
    def test_diagnostic_enospc_cannot_prevent_actual_owned_child_cleanup(self):
        pid = os.fork()
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        fd = os.pidfd_open(pid)
        result = {'authority': 'NONE'}
        def disk_full(*_args):
            with open('/dev/full', 'wb', buffering=0) as stream:
                stream.write(b'owned diagnostic control')
        try:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(probe, 'save', disk_full):
                probe.cleanup_owned_process(pathlib.Path(directory), pid, fd, None, None, result)
            self.assertTrue(result['owned_vmm_exited'])
            self.assertEqual(result['kill_syscall_result'], 'SENT')
            self.assertEqual(result['kill_intent']['pid'], pid)
            self.assertLessEqual(result['cleanup_begin_monotonic_ns'], result['kill_intent']['monotonic_ns'])
            self.assertLessEqual(result['kill_intent']['monotonic_ns'], result['kill_syscall_return_monotonic_ns'])
            self.assertLessEqual(result['kill_syscall_return_monotonic_ns'], result['cleanup_end_monotonic_ns'])
            self.assertEqual(result['owned_vmm_wait']['signal'], signal.SIGKILL)
            self.assertTrue(any('No space left on device' in e for e in result['cleanup_errors']))
            self.assertEqual(result['authority'], 'NONE')
        finally:
            try:
                reaped, _ = os.waitpid(pid, os.WNOHANG)
                if reaped == 0:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass

    def test_raw_progress_cannot_reset_absolute_handoff_deadline(self):
        client, server = socket.socketpair(); errors = []
        def trickle():
            try:
                for _ in range(4):
                    client.sendall(b'\x00'); time.sleep(.1)
            except OSError: pass
        thread = threading.Thread(target=trickle); thread.start()
        begin = time.monotonic()
        try:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(TimeoutError):
                probe.receive_raw_handoff(server, pathlib.Path(directory), 'a' * 64,
                                          deadline=begin + .15)
            self.assertLess(time.monotonic() - begin, .8)
        finally: server.close(); client.close(); thread.join(2)

    def test_zero_vmm_exit_cannot_hide_forced_or_incomplete_whole_run_cleanup(self):
        good = {'raw_ack_sent': True, 'owned_vmm_exited': True,
                'owned_vmm_wait': {'raw_status': 0, 'exit_code': 0, 'signal': None},
                'precleanup_cgroup_empty': True, 'cgroup_empty': True,
                'forced_vmm_cleanup': False, 'forced_cgroup_cleanup': False,
                'source_rootfs_unchanged': True, 'protected_rootfs_unchanged': True,
                'jailer_exit': 0, 'native_owned_processes': [
                    {'role': 'broker', 'exit': 0, 'forced_owned_cleanup': False},
                    {'role': 'custodian', 'exit': 0, 'forced_owned_cleanup': False}]}
        self.assertTrue(probe.clean_retirement_observed(good, True))
        changes = [{'precleanup_cgroup_empty': False}, {'precleanup_cgroup_empty': None},
                   {'forced_cgroup_cleanup': True}, {'cleanup_errors': ['io failure']},
                   {'planner_cleanup_failure': 'closed failed'}, {'native_cleanup_failure': 'missing'},
                   {'resource_observation_errors': ['ENOSPC']}, {'source_rootfs_unchanged': False},
                   {'native_owned_processes': []}, {'jailer_exit': True},
                   {'native_owned_processes': [good['native_owned_processes'][0],
                    {'role': 'custodian', 'exit': 0, 'forced_owned_cleanup': True}]}]
        for change in changes:
            with self.subTest(change=change):
                row = copy.deepcopy(good); row.update(change)
                self.assertTrue(probe.vmm_zero_exit_observed(row))
                self.assertFalse(probe.clean_retirement_observed(row, True))
        row = copy.deepcopy(good); del row['precleanup_cgroup_empty']
        self.assertFalse(probe.clean_retirement_observed(row, True))
        row['owned_vmm_wait']['exit_code'] = False
        self.assertFalse(probe.vmm_zero_exit_observed(row))

    def test_raw_ack_matches_durable_bytes_and_rejects_foreign_or_lost_reply(self):
        import host_planned_coding as tools
        import struct
        data = b'raw handoff control, not an artifact'
        header = {'schema': 'realm.coding-guest-development-raw.v2', 'authority': 'NONE',
                  'realm_artifact': None, 'challenge': 'a' * 64,
                  'size': len(data), 'sha256': worker.digest(data)}
        client, server = socket.socketpair()
        client.settimeout(3); server.settimeout(3)
        errors = []
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            def receiver():
                try: probe.receive_raw_handoff(server, root, header['challenge'])
                except Exception as error: errors.append(error)
            thread = threading.Thread(target=receiver); thread.start()
            try:
                encoded = worker.encoded(header)
                client.sendall(struct.pack('!I', len(encoded)) + encoded + data)
                boot.require_raw_ack(client, header)
                self.assertEqual((root / 'guest-raw.tar.gz').read_bytes(), data)
                self.assertEqual(worker.parse((root / 'raw-header.json').read_bytes()), header)
                self.assertEqual((root / 'guest-raw.tar.gz').stat().st_mode & 0o777, 0o600)
                thread.join(3)
                self.assertFalse(thread.is_alive()); self.assertFalse(errors)
                for change in ({'challenge': 'b' * 64}, {'sha256': 'c' * 64},
                               {'size': True}, {'authority': 'ACCEPT'}):
                    ack = {'schema': 'realm.coding-raw-received.v1', 'authority': 'NONE',
                           'challenge': header['challenge'], 'sha256': header['sha256'],
                           'size': header['size'], **change}
                    tools.send(server, ack)
                    with self.assertRaises(ValueError): boot.require_raw_ack(client, header)
                server.close()
                with self.assertRaises(ValueError): boot.require_raw_ack(client, header)
            finally:
                client.close(); server.close(); thread.join(3)

    def test_foreign_raw_identity_refuses_before_persistence_or_ack(self):
        import host_planned_coding as tools
        header = {'schema': 'realm.coding-guest-development-raw.v2', 'authority': 'NONE',
                  'realm_artifact': None, 'challenge': 'a' * 64,
                  'size': 1, 'sha256': worker.digest(b'x')}
        client, server = socket.socketpair()
        try:
            with tempfile.TemporaryDirectory() as directory:
                tools.send(client, header)
                with self.assertRaises(ValueError):
                    probe.receive_raw_handoff(server, pathlib.Path(directory), 'b' * 64)
                self.assertEqual(list(pathlib.Path(directory).iterdir()), [])
        finally: client.close(); server.close()

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfd required')
    def test_exited_child_is_reaped_without_forced_signal(self):
        import select
        pid = os.fork()
        if pid == 0: os._exit(0)
        fd = os.pidfd_open(pid)
        try:
            poller = select.poll(); poller.register(fd, select.POLLIN); poller.poll(3000)
            result = {'authority': 'NONE'}
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                    signal, 'pidfd_send_signal', side_effect=AssertionError('must not kill exited child')):
                probe.cleanup_owned_process(pathlib.Path(directory), pid, fd, None, None, result)
            self.assertEqual(result['owned_vmm_wait']['exit_code'], 0)
            self.assertIsNone(result['owned_vmm_wait']['signal'])
            self.assertFalse(result['forced_vmm_cleanup'])
            self.assertNotIn('cleanup_errors', result)
        finally:
            try: os.close(fd)
            except OSError: pass
            try: os.waitpid(pid, os.WNOHANG)
            except ChildProcessError: pass

    def test_guest_deadline_escapes_request_retry_and_restores_timer(self):
        previous = signal.getsignal(signal.SIGALRM)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        def request_retry_loop():
            while True:
                try:
                    time.sleep(1)
                except TimeoutError:
                    continue
        with mock.patch.object(boot.agent, 'inside', request_retry_loop):
            with self.assertRaises(boot.GuestDeadline):
                boot.bounded_agent(0.02)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)

    def test_guest_stop_signal_unwinds_and_restores_handlers(self):
        previous_alarm = signal.getsignal(signal.SIGALRM)
        previous_stop = signal.getsignal(signal.SIGINT)
        def actual_owned_stop():
            os.kill(os.getpid(), signal.SIGINT)
            raise AssertionError('stop signal did not unwind')
        with mock.patch.object(boot.agent, 'inside', actual_owned_stop):
            with self.assertRaisesRegex(boot.GuestDeadline, 'stop signal received'):
                boot.bounded_agent(10)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous_alarm)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous_stop)

    def test_json_type_and_duplicate_key_are_semantically_distinct(self):
        self.assertTrue(export.matches(0, b'{"amount":1}', {'amount': 1}))
        self.assertFalse(export.matches(0, b'{"amount":true}', {'amount': 1}))
        self.assertFalse(export.matches(0, b'{"amount":1.0}', {'amount': 1}))
        self.assertFalse(export.matches(0, b'{"amount":2,"amount":1}', {'amount': 1}))
        self.assertFalse(export.matches(0, b'{"amount":NaN}', {'amount': 1}))


if __name__ == '__main__':
    unittest.main()
