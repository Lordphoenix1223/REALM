#!/usr/bin/env python3
"""Real persistent native-process refusal controls, without root/KVM/guest.

These tests do NOT fabricate NativeCodingAttempt owners. Success/retirement and
interrupted VM closure require the separately approved x86 native experiment.
Every subprocess and evidence directory belongs solely to this test run.
"""
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import time
import sys
import hashlib
import unittest

BINARY = Path(os.environ.get('REALM_NATIVE_BINARY', 'target/debug/coding_submission_probe')).resolve()
ROOT = Path(os.environ.get('REALM_NATIVE_RETENTION_EVIDENCE') or
            tempfile.mkdtemp(prefix='realm-native-retention-interface-'))


class NativeRetentionProcessTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.uname().sysname, 'Linux')
        self.assertNotEqual(os.geteuid(), 0, 'this interface campaign must run unprivileged')
        self.root = ROOT / self._testMethodName
        self.root.mkdir(parents=True, mode=0o700)
        self.children = []
        self.channels = []
        self.streams = []
        self.frames = []

    def launch(self):
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.channels += [tx, rx]
        tasks = [{'task_sha256': 'a'*64, 'worker_sha256': 'b'*64,
                  'source_commit': 'd'*40, 'checker_sha256': 'e'*64,
                  'checker_scope_sha256': 'f'*64}]*2
        argv = [str(BINARY), '--retain-native-attempts', str(self.root), 'c'*64,
                json.dumps(tasks, separators=(',', ':')), str(rx.fileno())]
        log = (self.root / ('process-'+str(len(self.children))+'.stderr')).open('xb')
        self.streams.append(log)
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=log, pass_fds=(rx.fileno(),), start_new_session=True)
        self.children.append(child)
        return child

    def send(self, child, row):
        child.stdin.write(json.dumps(row, separators=(',', ':')).encode()+b'\n')
        child.stdin.flush()

    def read(self, child):
        # Read a byte at a time: no userspace buffered reader can hide the next
        # response from select or silently reassign it to another attempt.
        raw = bytearray()
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            ready, _, _ = select.select([child.stdout], [], [], max(0, deadline-time.monotonic()))
            if ready:
                part = os.read(child.stdout.fileno(), 1)
                if not part:
                    self.fail('native owner EOF before response')
                raw += part
                if part == b'\n':
                    row = json.loads(raw)
                    self.frames.append(row)
                    return row
                self.assertLessEqual(len(raw), 65536)
        self.fail('native owner response deadline')

    def attempt(self, child, task=0, pin='a'*64):
        args = [str(BINARY), '--native-referee-launch', str(self.root/'unused-native-state'),
                pin, 'b'*64, '/not-executed-custodian', '996', '980', '-1', '/not-executed-python']
        self.send(child, {'phase': 'ATTEMPT', 'task': task, 'args': args})

    def rows(self):
        return [json.loads(x) for x in (self.root/'native-attempts.jsonl').read_text().splitlines()]

    def test_stage7_publish_refuses_missing_original_owners(self):
        child = self.launch()
        self.read(child)
        self.send(child, {'phase':'PUBLISH'})
        child.stdin.close()
        self.assertNotEqual(child.wait(timeout=10), 0)
        self.assertFalse((self.root/'accepted.realm').exists())
        self.assertEqual([row['body']['phase'] for row in self.rows()], ['OPEN'])

    def test_original_root_arch_guard_is_retained_and_cannot_retry(self):
        child = self.launch()
        birth = self.read(child)
        self.assertEqual(birth['owner_pid'], child.pid)
        self.attempt(child)
        result = self.read(child)
        self.assertEqual(result['phase'], 'ATTEMPT_INCOMPLETE')
        self.assertIn('Requires root Linux x86_64', result['error'])
        self.assertIsNone(child.poll())  # The ORIGINAL owner process persists.
        self.send(child, {'phase': 'INSPECT'})
        retained = self.read(child)
        self.assertEqual(retained['owner_nonce'], birth['owner_nonce'])
        self.assertEqual(retained['attempts'], [{'attempt': 0, 'task': 0, 'outcome': 'INCOMPLETE'}])
        self.assertEqual(retained['ownership_status'], 'INCOMPLETE')
        self.assertEqual(retained['authority'], 'NONE')
        self.assertFalse(retained['publication_authority'])
        self.attempt(child)
        self.assertEqual(child.wait(timeout=10), 2)
        self.assertEqual([r['body']['phase'] for r in self.rows()], ['OPEN', 'BEGIN', 'INCOMPLETE'])
        self.assertFalse((self.root/'unused-native-state').exists())

    def test_cross_task_substitution_is_preserved_and_refused(self):
        child = self.launch(); self.read(child)
        self.attempt(child, pin='d'*64)
        self.assertEqual(child.wait(timeout=10), 2)
        rows = self.rows()
        self.assertEqual([r['body']['phase'] for r in rows], ['OPEN', 'BEGIN', 'REJECTED'])
        self.assertEqual(rows[1]['body']['data']['argv'][3], 'd'*64)

    def test_dependent_task_cannot_run_without_owned_predecessor(self):
        child = self.launch(); self.read(child)
        self.attempt(child, task=1)
        self.assertEqual(child.wait(timeout=10), 2)
        self.assertEqual(self.rows()[-1]['body']['phase'], 'REJECTED')

    def test_killed_original_cannot_be_resurrected_from_json(self):
        child = self.launch(); birth = self.read(child)
        self.attempt(child); self.read(child)
        os.kill(child.pid, signal.SIGKILL)
        self.assertEqual(child.wait(timeout=10), -signal.SIGKILL)
        before = (self.root/'native-attempts.jsonl').read_bytes()
        replacement = self.launch()
        self.assertEqual(replacement.wait(timeout=10), 2)
        self.assertEqual((self.root/'native-attempts.jsonl').read_bytes(), before)
        self.assertNotIn('RELEASE', [r['body']['phase'] for r in self.rows()])
        self.assertEqual(self.rows()[0]['body']['owner_nonce'], birth['owner_nonce'])

    def test_changed_journal_cannot_become_live_owner_evidence(self):
        child = self.launch(); self.read(child)
        with (self.root/'native-attempts.jsonl').open('ab') as f:
            f.write(b'{}\n'); f.flush(); os.fsync(f.fileno())
        self.send(child, {'phase': 'INSPECT'})
        self.assertEqual(child.wait(timeout=10), 2)

    def test_release_explicitly_ends_retention_without_transfer(self):
        child = self.launch(); self.read(child)
        self.send(child, {'phase': 'RELEASE'})
        released = self.read(child)
        self.assertEqual(child.wait(timeout=10), 0)
        self.assertEqual(released['phase'], 'OWNERS_RELEASED')
        self.assertEqual(released['owner_retention'], 'ENDED')
        self.assertEqual(released['audit']['ownership_status'], 'INCOMPLETE')
        self.assertEqual(released['audit']['authority'], 'NONE')

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.kill(); child.wait(timeout=10)
            child.stdin.close(); child.stdout.close()
        for channel in self.channels:
            channel.close()
        for stream in self.streams:
            stream.flush(); os.fsync(stream.fileno()); stream.close()
        (self.root/'observed-frames.json').write_text(json.dumps(self.frames, indent=2)+'\n')


class NativeKeeperTransportTests(unittest.TestCase):
    def setUp(self):
        ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.assertEqual(os.uname().sysname,'Linux')
        self.assertNotEqual(os.geteuid(),0)
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        import coding_native_run
        self.native = coding_native_run
        self.root = ROOT / self._testMethodName
        self.keeper = self.native.NativeAttemptKeeper(BINARY,hashlib.sha256(BINARY.read_bytes()).hexdigest(),
            self.root,'c'*64,[{'task_sha256':'a'*64,'worker_sha256':'b'*64,'source_commit':'d'*40,
                               'checker_sha256':'e'*64,'checker_scope_sha256':'f'*64}]*2)

    def tearDown(self):
        k=self.keeper
        if not k.closed:
            # These unprivileged tests only opened the audit transport or hit
            # the original prelaunch root/architecture guard. No VM exists.
            if k.child.poll() is None:
                if k.active is None:
                    k.close();return
                k.child.kill();k.child.wait(timeout=10)
            k.child.stdin.close();k.child.stdout.close();k.auxiliary.close()
            os.close(k.pidfd);k.stderr.flush();os.fsync(k.stderr.fileno());k.stderr.close()

    def test_python_transport_retains_same_kernel_observed_process(self):
        k=self.keeper
        pid=k.child.pid
        a=k.inspect(time.monotonic()+10);b=k.inspect(time.monotonic()+10)
        self.assertEqual(k.child.pid,pid)
        self.assertEqual(a['owner_nonce'],b['owner_nonce'])
        self.assertEqual(a['attempts'],[])
        self.assertEqual(a['authority'],'NONE')
        self.assertEqual(a['qualification'],'NOT_ESTABLISHED')
        self.assertFalse(a['publication_authority'])

    def test_real_prelaunch_failure_is_poisoned_without_json_owner_restore(self):
        k=self.keeper
        attempt=self.root/'attempt';attempt.mkdir(mode=0o700)
        argv=[str(BINARY),'--native-referee-launch',str(attempt/'state'),'a'*64,'b'*64,
              '/not-run-custodian','996','980','-1','/not-run-python']
        child,lines,aux=k.begin(0,argv,attempt);aux.close()
        failure=lines.next(time.monotonic()+10)
        self.assertEqual(failure['phase'],'ATTEMPT_INCOMPLETE')
        self.assertIn('Requires root Linux x86_64',failure['error'])
        self.assertIsNone(child.poll())
        k.poison('actual unprivileged launch refusal')
        evidence=k.inspect(time.monotonic()+10)
        self.assertEqual(evidence['ownership_status'],'INCOMPLETE')
        self.assertEqual(evidence['attempts'],[{'attempt':0,'task':0,'outcome':'INCOMPLETE'}])
        with self.assertRaisesRegex(ValueError,'poisoned'):
            k.begin(0,argv,attempt)
        rows=[json.loads(x)['body'] for x in (self.root/'native-attempts.jsonl').read_text().splitlines()]
        self.assertEqual([r['phase'] for r in rows],['OPEN','BEGIN','INCOMPLETE','ABORT'])

    def borrowed_process(self,fd,pass_fds):
        program=("import sys,json,time;sys.path.insert(0,sys.argv[1]);import coding_native_run as n;"
                 "k,t=n.attach_native_keeper(int(sys.argv[2]));"
                 "print(json.dumps(k.inspect(time.monotonic()+10)),flush=True)")
        return subprocess.run([sys.executable,'-I','-B','-c',program,
                    str(Path(__file__).resolve().parent),str(fd)],
                    pass_fds=pass_fds,capture_output=True,text=True,timeout=20)

    def test_sealed_kernel_descriptor_loan_reuses_original_process(self):
        k=self.keeper
        fd,fds=k.lend(0)
        try:
            with self.assertRaises(OSError):os.write(fd,b'tamper')
            observed=self.borrowed_process(fd,fds)
            self.assertEqual(observed.returncode,0,observed.stderr)
            data=json.loads(observed.stdout)
            self.assertEqual(data['owner_nonce'],k.nonce)
            self.assertEqual(data['attempts'],[])
            self.assertEqual(data['authority'],'NONE')
            self.assertIsNone(k.child.poll())
            with self.assertRaisesRegex(ValueError,'original attempt missing'):
                k.complete_loan(None,time.monotonic()+10)
        finally:os.close(fd)

    def test_unsealed_descriptor_manifest_is_rejected(self):
        fd=os.memfd_create('unsealed-test',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            os.write(fd,b'{}');os.lseek(fd,0,os.SEEK_SET)
            observed=self.borrowed_process(fd,(fd,))
            self.assertNotEqual(observed.returncode,0)
            self.assertIn('sealed native descriptor handoff required',observed.stderr)
            self.assertEqual(self.keeper.inspect(time.monotonic()+10)['attempts'],[])
        finally:os.close(fd)

    def test_cross_process_pipe_pidfd_substitution_is_rejected(self):
        import fcntl
        k=self.keeper
        other=self.native.NativeAttemptKeeper(BINARY,hashlib.sha256(BINARY.read_bytes()).hexdigest(),
            self.root/'other','d'*64,k.tasks)
        fd,fds=k.lend(0);mixed=None
        try:
            body=json.loads(os.pread(fd,65536,0))
            body['pid']=other.child.pid;body['fds']['pidfd']=other.pidfd
            mixed=os.memfd_create('mixed-owner-descriptors',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            os.write(mixed,json.dumps(body).encode());os.lseek(mixed,0,os.SEEK_SET)
            fcntl.fcntl(mixed,fcntl.F_ADD_SEALS,fcntl.F_SEAL_SEAL|fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK)
            observed=self.borrowed_process(mixed,tuple([mixed,*body['fds'].values()]))
            self.assertNotEqual(observed.returncode,0)
            self.assertIn('control pipe identifies another process',observed.stderr)
            with self.assertRaisesRegex(ValueError,'original attempt missing'):
                k.complete_loan(None,time.monotonic()+10)
            self.assertEqual(other.inspect(time.monotonic()+10)['attempts'],[])
        finally:
            os.close(fd)
            if mixed is not None:os.close(mixed)
            other.close()

    def test_development_session_cannot_adopt_native_transport(self):
        from vm_session import Session,SessionRequest,SessionError
        import coding_worker
        request=SessionRequest('development-kernel-child',coding_worker.digest(coding_worker.encoded(coding_worker.contract())))
        with self.assertRaisesRegex(SessionError,'development Session cannot consume'):
            Session.start(request,self.root/'forbidden-development',native_keeper=self.keeper,native_task=0)
        self.assertFalse((self.root/'forbidden-development').exists())
        self.assertEqual(self.keeper.inspect(time.monotonic()+10)['attempts'],[])

    def test_original_session_host_guard_prevents_native_substitution(self):
        from vm_session import Session,SessionRequest,SessionError,host_support
        import coding_worker
        support=host_support('firecracker-measured')
        (self.root/'actual-host-support.json').write_text(json.dumps({**support,'uid':os.geteuid(),
            'gid':os.getegid(),'kernel':list(os.uname()),'kvm_exists':Path('/dev/kvm').exists(),
            'kvm_read_write':os.access('/dev/kvm',os.R_OK|os.W_OK),
            'actual_native_attempt_owners':0},indent=2)+'\n')
        self.assertEqual(support['status'],'UNSUPPORTED')
        request=SessionRequest('firecracker-measured',coding_worker.digest(coding_worker.encoded(coding_worker.contract())))
        with self.assertRaisesRegex(SessionError,'UNSUPPORTED'):
            Session.start(request,self.root/'blocked-native',native_keeper=self.keeper,native_task=0)
        self.assertFalse((self.root/'blocked-native').exists())
        self.assertEqual(self.keeper.inspect(time.monotonic()+10)['attempts'],[])


if __name__ == '__main__':
    unittest.main()
