"""Real local pipe controls for the native adapter; never VM qualification."""
import array
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

import coding_native_run as native


class NativePhaseControls(unittest.TestCase):
    def control(self, program, operation):
        with tempfile.TemporaryDirectory(prefix='r7-native-phase-') as temp:
            child = subprocess.Popen([sys.executable, '-c', program], stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)
            try:
                operation(native.NativeLines(child, Path(temp)))
            finally:
                child.stdout.close()
                if child.poll() is None: child.kill()
                child.wait(timeout=5)

    def test_actual_partial_pipe_frames_and_native_eof_refuse(self):
        def verify(lines):
            row = lines.next(time.monotonic() + 5)
            self.assertEqual(row, {'phase': 'BINDING', 'authority': 'NONE'})
            self.assertTrue((lines.root / 'native-phase-01.json').is_file())
            with self.assertRaisesRegex(ValueError, 'closed phase stream|exited before phase'):
                lines.next(time.monotonic() + 5)
        self.control("import os,time;os.write(1,b'{\\\"phase\\\":\\\"BINDING\\\",');time.sleep(.02);os.write(1,b'\\\"authority\\\":\\\"NONE\\\"}\\n')", verify)

    def test_duplicate_json_and_actual_oversized_pipe_refuse(self):
        for program in ["print('{\\\"authority\\\":\\\"NONE\\\",\\\"authority\\\":\\\"NONE\\\"}')",
                        "import os;os.write(1,b'x'*(129*1024))"]:
            def verify(lines):
                with self.assertRaises(ValueError): lines.next(time.monotonic() + 5)
            self.control(program, verify)


class QualifiedDriverControls(unittest.TestCase):
    def test_retained_installed_admission_survives_without_single_run_publication(self):
        import coding_native_run as driver
        birth={'runtime_admission_id':'a'*64}
        self.assertEqual(driver.native_admission_identity(birth,required=True),'a'*64)
        self.assertEqual(driver.native_admission_identity(birth,required=False),'a'*64)
        self.assertIsNone(driver.native_admission_identity({},required=False))
        for value in (None,'',True,'A'*64):
            with self.assertRaises(ValueError):
                driver.native_admission_identity({'runtime_admission_id':value},required=True)

    def test_frozen_approval_plan_binds_application_mode(self):
        args = self.args()
        args.run = 'TEST_ONLY'; args.native_sha256 = '1'*64
        args.owned_referee_python_sha256 = '2'*64; args.custodian_sha256 = '3'*64
        args.base = Path('/base'); args.base_sha256 = '4'*64; args.assets = Path('/assets')
        args.publication_only = False
        legacy = native.plan(args)
        args.publication_only = True
        deferred = native.plan(args)
        self.assertEqual(deferred['application_mode'], 'INDEPENDENT_STAGE8')
        self.assertEqual(legacy['application_mode'], 'LEGACY_INSTALLED_RECEIVER')
        self.assertNotEqual(native.worker.digest(native.worker.encoded(legacy)),
                            native.worker.digest(native.worker.encoded(deferred)))
        self.assertIn('no host application', deferred['approval_scope'])

    def test_publication_only_does_not_accept_application_or_grant_authority(self):
        args = self.args(); args.publication_only = True
        command = native.native_launch(args, Path('/state'), 7)
        self.assertEqual(command[:4], ['/realm', 'task', 'run-coding-native', '--publication-only'])
        deferred = {'status':'NOT_RUN', 'application_authorization':'NONE',
                    'application_dispatched':False, 'receiver_profile':'realm.stage8.ordered-create.v1'}
        self.assertEqual(native.application_disposition(args, {'application_handoff':deferred}), deferred)
        for key, value in [('status','APPLIED_AND_FINAL_VERIFIED'),
                           ('application_authorization','AUTHORIZED_INSTALLED_GRANT'),
                           ('application_dispatched',True), ('receiver_profile','foreign')]:
            changed = dict(deferred, **{key:value})
            with self.assertRaises(ValueError): native.application_disposition(args, {'application_handoff':changed})
        applied = {'status':'APPLIED_AND_FINAL_VERIFIED', 'execution_qualification':'QUALIFIED',
                   'application_authorization':'AUTHORIZED_INSTALLED_GRANT'}
        with self.assertRaises(ValueError): native.application_disposition(args, {'application_handoff':applied})
        args.publication_only = False
        with self.assertRaises(ValueError): native.application_disposition(args, {'application_handoff':deferred})
        self.assertEqual(native.application_disposition(args, {'application_handoff':applied}), applied)
        args.publication_only = True
        for key in ('publication_world','publication_evidence','publication_trust','publication_trust_sha256'):
            setattr(args, key, None)
        with self.assertRaises(ValueError): native.publication_options(args)

    def args(self):
        return SimpleNamespace(native_binary=Path('/realm'), custodian=Path('/custodian'),
            native_relay=True, owned_referee_python=Path('/usr/bin/python3'),
            publication_world=Path('/worker-world'), publication_evidence=Path('/publisher') / ('a' * 64),
            publication_trust=Path('/trust.json'), publication_trust_sha256='a'*64,
            source_commit='b'*40)

    def test_qualified_mode_uses_original_cli_and_actual_admission_binding(self):
        args = self.args()
        command = native.native_launch(args, Path('/state'), 19)
        self.assertEqual(command[:9], ['/realm', 'task', 'run-coding-native', '/worker-world',
            str(args.publication_evidence), '/trust.json', '--native-referee-launch', '--installed-runtime-admission', '/state'])
        self.assertEqual(command[-2:], ['19', '/usr/bin/python3'])
        scope = native.prelaunch_scope(args, {'run_id':'c'*64}, 'd'*64)
        self.assertEqual(scope['runtime_admission_id'], 'd'*64)
        self.assertNotIn('runtime_admission_id', native.prelaunch_scope(args, None))
        with self.assertRaises(ValueError): native.prelaunch_scope(args, None, 'caller-label')
        for name in ('publication_world','publication_evidence','publication_trust','publication_trust_sha256'):
            broken = self.args(); setattr(broken, name, None)
            with self.assertRaises(ValueError): native.publication_options(broken)
        overlap = self.args(); overlap.publication_trust = Path('/worker-world/trust.json')
        with self.assertRaises(ValueError): native.publication_options(overlap)
        args.native_relay = False
        with self.assertRaises(ValueError): native.publication_options(args)

    def test_terminal_publication_requires_bounded_actual_eof(self):
        with tempfile.TemporaryDirectory(prefix='r7-publication-stream-') as temp:
            for program, succeeds in [
                ("print('{\"state\":\"VALID\"}')", True),
                ("import json;print(json.dumps({'state':'VALID','padding':'x'*70000}))", True),
                ("import sys;print('{\"state\":\"VALID\"}');sys.exit(7)", False),
                ("print('{\"state\":\"INCOMPLETE\"}')", False),
                ("print('{\"state\":\"VALID\"}');print('{}')", False),
                ("import time;print('{\"state\":\"VALID\"}',flush=True);time.sleep(2)", False),
            ]:
                child = subprocess.Popen([sys.executable,'-c',program], stdout=subprocess.PIPE)
                try:
                    case = Path(temp) / str(time.monotonic_ns()); case.mkdir()
                    lines = native.NativeLines(child,case)
                    if succeeds:
                        self.assertEqual(native.finish_native_owner(lines,time.monotonic()+1,publication=True)['state'],'VALID')
                    else:
                        with self.assertRaises((ValueError, subprocess.TimeoutExpired)): native.finish_native_owner(lines,time.monotonic()+.5,publication=True)
                    if 'sys.exit(7)' in program:
                        retained = native.worker.parse((case / 'canonical-publication-result.json').read_bytes())
                        self.assertEqual(retained['state'], 'VALID')
                finally:
                    if child.poll() is None: child.kill()
                    child.wait();child.stdout.close()


class AuxiliaryHandoffControls(unittest.TestCase):
    def test_native_relay_handoff_transfers_only_raw_descriptors(self):
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        pairs = [socket.socketpair() for _ in range(2)]
        received = []
        try:
            native.transfer_auxiliary(tx, [p[0] for p in pairs], native_control=True)
            frame, ancillary, flags, _ = rx.recvmsg(64, socket.CMSG_SPACE(8))
            self.assertEqual((frame, flags), (b'R7RAW1', 0))
            self.assertTrue(all(p[0].fileno() == -1 for p in pairs))
            fds = array.array('i'); fds.frombytes(ancillary[0][2])
            received = [socket.socket(fileno=fd) for fd in fds]
            self.assertEqual(len(received), 2)
            self.assertEqual(rx.recv(16), b'DONE')
            for index, (_, peer) in enumerate(pairs):
                peer.sendall(bytes([index]))
                self.assertEqual(received[index].recv(1), bytes([index]))
        finally:
            for pair in pairs:
                for sock in pair: sock.close()
            for sock in received: sock.close()
            tx.close(); rx.close()

    def test_real_descriptor_transfer_drops_sender_aliases_before_done(self):
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        pairs = [socket.socketpair() for _ in range(4)]
        originals = [pair[0] for pair in pairs]
        received = []
        try:
            native.transfer_auxiliary(tx, originals)
            self.assertTrue(all(s.fileno() == -1 for s in originals))
            frame, ancillary, flags, _ = rx.recvmsg(64, socket.CMSG_SPACE(16))
            self.assertEqual((frame, flags), (b'R7AUX1', 0))
            self.assertEqual(len(ancillary), 1)
            level, kind, data = ancillary[0]
            self.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
            fds = array.array('i'); fds.frombytes(data)
            self.assertEqual(len(fds), 4)
            received = [socket.socket(fileno=fd) for fd in fds]
            self.assertEqual(rx.recv(16), b'DONE')
            for index, (_, peer) in enumerate(pairs):
                peer.sendall(bytes([index]))
                self.assertEqual(received[index].recv(1), bytes([index]))
        finally:
            for pair in pairs:
                for sock in pair: sock.close()
            for sock in received: sock.close()
            tx.close(); rx.close()


if __name__ == '__main__':
    unittest.main()
