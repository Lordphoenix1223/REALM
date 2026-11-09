"""Actual local session/lifecycle controls; never simulated Firecracker PASS."""
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest

import coding_worker as worker
from vm_session import Session, SessionRequest, SessionError, host_support

PIN = worker.digest(worker.encoded(worker.contract()))


class SessionControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='realm-stage23-controls-')
        self.root = Path(self.temp.name)
        self.sessions = []

    def tearDown(self):
        for session in self.sessions:
            session.close()
        self.temp.cleanup()  # Only newly allocated test-owned scratch.

    def start(self, name='session', lifetime=120):
        s = Session.start(SessionRequest('development-kernel-child', PIN, lifetime), self.root/name)
        self.sessions.append(s)
        return s

    def test_real_worker_authorized_files_and_no_arbitrary_tools(self):
        s = self.start()
        before = s.execute({'tool': 'read', 'path': 'totals.py'})['text']
        self.assertEqual(before, worker.BASELINE['totals.py'])
        self.assertIn('written', s.execute({'tool':'write','path':'totals.py','text':before+'\n'}))
        canary = self.root/'canary'; canary.write_bytes(b'unchanged')
        for action in ({'tool':'read','path':str(canary)},
                       {'tool':'write','path':'../canary','text':'bad'},
                       {'tool':'shell','command':'touch /tmp/escape'},
                       {'tool':'network','url':'https://example.com'},
                       {'tool':'write','path':'totals.py','text':'x'*(worker.MAX_BYTES+1)}):
            self.assertEqual(s.execute(action)['status'],'REFUSED_BEFORE_DISPATCH')
        self.assertEqual(canary.read_bytes(),b'unchanged')
        result=s.close()
        self.assertEqual(result['terminal']['status'],'PASS')
        self.assertTrue(result['terminal']['owned_processes_closed'])
        self.assertEqual(result['actual_vm'],'NOT_RUN')
        self.assertEqual(result['qualification'],'NOT_RUN')

    def test_actual_candidate_kernel_denial_network_files_and_fork(self):
        s = self.start()
        candidate=s.evidence/'worker/candidate'
        sandbox=worker.Sandbox(candidate)
        sentinel=self.root/'secret'; sentinel.write_text('sentinel')
        for code in (f"open({str(sentinel)!r}).read()", 'import socket; socket.socket().connect(("192.0.2.1",80))',
                     'import os; os.fork()', 'open("/tmp/realm-stage23-forbidden-write","w").write("x")',
                     'import subprocess; subprocess.run(["/bin/sh","-c","true"],check=True)'):
            exitcode, out, err=sandbox.execute(code,b'')
            self.assertNotEqual(exitcode,0,(code,out,err))
        self.assertEqual(sentinel.read_text(),'sentinel')

    def test_task_check_and_finish_through_actual_session(self):
        s=self.start()
        actions=json.loads((Path(__file__).parent/'vertical_task/actions.json').read_text())
        for action in actions:
            result=s.execute(action)
        self.assertEqual(result['status'],'DEVELOPMENT_TASK_CHECKED')
        final=s.close()
        self.assertTrue(final['task_finished'])
        self.assertEqual(final['terminal']['status'],'PASS')
        with self.assertRaises(SessionError): s.execute({'tool':'list'})

    def test_agent_disconnect_and_forced_close_preserve_records(self):
        s=self.start()
        s.execute({'tool':'list'})
        pid=s.child.pid
        result=s.close()
        self.assertEqual(result['terminal']['status'],'PASS')
        self.assertIsNotNone(s.child.poll())
        with self.assertRaises(ProcessLookupError): os.kill(pid,0)
        self.assertTrue(Path(result['journal']).is_file())
        self.assertEqual(s.close(),result)

    def test_real_worker_crash_fails_without_retry(self):
        s=self.start(); s.child.kill(); s.child.wait(timeout=5)
        with self.assertRaises((SessionError,BrokenPipeError)):
            s.execute({'tool':'list'})
        self.assertTrue(s.closed)
        self.assertEqual(s.collect()['terminal']['status'],'INCOMPLETE')

    def test_absolute_lifetime_without_controller_activity(self):
        s=self.start(lifetime=1)
        deadline=time.monotonic()+7
        while not s.closed and time.monotonic()<deadline:
            time.sleep(.05)
        self.assertTrue(s.closed)
        self.assertIn('expired',s.failure)
        self.assertIsNotNone(s.child.poll())
        self.assertEqual(s.collect()['terminal']['status'],'INCOMPLETE')

    def test_host_deadline_survives_absent_controller_timer(self):
        s=self.start(lifetime=1)
        s.timer.cancel()  # Host retains its independent absolute alarm.
        s.child.wait(timeout=4)
        self.assertNotEqual(s.child.returncode,0)
        result=s.close()
        self.assertEqual(result['terminal']['status'],'INCOMPLETE')
        self.assertTrue(result['terminal']['owned_processes_closed'])

    def test_fresh_restart_never_reuses_failed_attempt_state(self):
        a=self.start('a'); a.execute({'tool':'write','path':'totals.py','text':'bad'})
        a.close()
        with self.assertRaises(FileExistsError): self.start('a')
        b=self.start('b')
        self.assertNotEqual(a.id,b.id)
        self.assertEqual(b.execute({'tool':'read','path':'totals.py'})['text'],worker.BASELINE['totals.py'])

    def test_actual_candidate_resource_and_child_exhaustion(self):
        s=self.start(); sandbox=worker.Sandbox(s.evidence/'worker/candidate')
        # Original Worker enforces CPU2s/wall3s/output bounds and kills owned
        # process group in finally. A refused fork is not simulated exhaustion.
        for code in ('while True: pass', 'print("x"*100000)'):
            try:
                result=sandbox.execute(code,b'')
                self.assertNotEqual(result[0],0)
            except ValueError as e:
                self.assertRegex(str(e),'timeout|output limit')
        self.assertIn('files',s.execute({'tool':'list'}))

    def test_invalid_request_and_unsupported_native_fail_before_effects(self):
        for profile, state, pin in [('unknown','fresh',PIN),('development-kernel-child','rollback',PIN),
                                    ('development-kernel-child','fresh','0'*64)]:
            with self.assertRaises(SessionError):
                Session.start(SessionRequest(profile,pin,state=state),self.root/'invalid')
        self.assertFalse((self.root/'invalid').exists())
        if host_support('firecracker-measured')['status']=='UNSUPPORTED':
            with self.assertRaisesRegex(SessionError,'UNSUPPORTED'):
                Session.start(SessionRequest('firecracker-measured',PIN),self.root/'vm')
            self.assertFalse((self.root/'vm').exists())

    def test_pinned_fresh_task_reaches_real_session_host(self):
        import importlib.util
        definition=Path(__file__).parent/'fresh_tasks/unicode-runs.definition.json'
        pin=worker.digest(definition.read_bytes())
        spec=importlib.util.spec_from_file_location('isolated_fresh_contract',worker.__file__)
        isolated=importlib.util.module_from_spec(spec); spec.loader.exec_module(isolated)
        isolated.configure_development_task(definition,pin)
        req=SessionRequest('development-kernel-child',worker.digest(worker.encoded(isolated.contract())),
                           development_task=definition,development_task_sha256=pin)
        s=Session.start(req,self.root/'fresh'); self.sessions.append(s)
        self.assertEqual(s.execute({'tool':'read','path':'totals.py'})['text'],isolated.BASELINE['totals.py'])
        self.assertEqual(s.execute({'tool':'list'})['task'],isolated.DESCRIPTION)
        s.close()
        self.assertEqual(worker.digest(worker.encoded(worker.contract())),PIN)

    def test_journal_chain_and_budget_are_session_bound(self):
        s=self.start(); s.execute({'tool':'list'}); s.close()
        previous='0'*64
        rows=[worker.parse(x) for x in (s.evidence/'session.jsonl').read_bytes().splitlines()]
        for index,row in enumerate(rows):
            claimed=row.pop('sha256')
            self.assertEqual(row['session'],s.id)
            self.assertEqual(row['sequence'],index)
            self.assertEqual(row['previous'],previous)
            self.assertEqual(worker.digest(worker.encoded(row)),claimed)
            previous=claimed
        self.assertEqual(previous,s.collect()['journal_head'])


if __name__=='__main__':
    unittest.main()
