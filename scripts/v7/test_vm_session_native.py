"""Runnable real-VM controls. NOT_RUN unless explicitly provisioned and approved.

Use ONE named unittest per approved window. REALM_NATIVE_CASES names a protected
JSON mapping test names to {profile,sha256,evidence}. Each profile is a distinct
fresh installed run; never reuse it. The environment flag is a test selection,
not an admission credential: all production launch/capture gates still apply.
"""
import json
import os
from pathlib import Path
import signal
import time
import unittest

import coding_worker as worker
from vm_session import Session, SessionRequest, SessionError, host_support


@unittest.skipUnless(os.environ.get('REALM_NATIVE_CASES'), 'NOT_RUN: separately approved supported host and protected case profiles required')
class RealVmControls(unittest.TestCase):
    def setUp(self):
        import coding_native_run as native
        manifest=Path(os.environ['REALM_NATIVE_CASES'])
        native.protected(manifest)
        self.case=worker.parse(manifest.read_bytes())[self._testMethodName]
        self.session=None

    def start(self):
        self.session=Session.start(SessionRequest('firecracker-measured',worker.digest(worker.encoded(worker.contract())),180),
            Path(self.case['evidence']),installed_profile=Path(self.case['profile']),profile_sha256=self.case['sha256'])
        return self.session

    def finish(self):
        for action in json.loads((Path(__file__).parent/'vertical_task/actions.json').read_text()):
            result=self.session.execute(action)
        self.assertEqual(result['status'],'DEVELOPMENT_TASK_CHECKED')
        result=self.session.close()
        self.assertTrue(result['terminal']['owned_processes_closed'],result)
        self.assertEqual(result['terminal']['status'],'PASS',result)
        self.assertEqual(result['authority'],'NONE')
        return result

    def tearDown(self):
        if self.session:
            result=self.session.close()
            # Negative task outcomes must still account for processes. Missing
            # held-pidfd/cgroup observations fail this actual native control.
            self.assertTrue(result['terminal']['owned_processes_closed'],result)

    def test_vm_startup(self):
        s=self.start(); self.assertEqual(s.collect()['actual_vm'],'STARTED_UNQUALIFIED'); self.finish()

    def test_agent_connection(self):
        s=self.start(); self.assertIn('files',s.execute({'tool':'list'})); self.finish()

    def test_authorized_files(self):
        s=self.start(); self.assertIn('text',s.execute({'tool':'read','path':'totals.py'})); self.finish()

    def test_unauthorized_files(self):
        s=self.start(); self.assertEqual(s.execute({'tool':'read','path':'/etc/shadow'})['status'],'REFUSED_BEFORE_DISPATCH'); self.finish()

    def test_unauthorized_network(self):
        s=self.start(); self.assertEqual(s.execute({'tool':'network','url':'https://example.com'})['status'],'REFUSED_BEFORE_DISPATCH')
        result=s.execute({'tool':'check'})
        self.assertTrue(result['development_conformance']['network']); self.finish()

    def test_unauthorized_command(self):
        s=self.start(); self.assertEqual(s.execute({'tool':'shell','command':'id'})['status'],'REFUSED_BEFORE_DISPATCH'); self.finish()

    def test_agent_crash(self):
        s=self.start(); s.execute({'tool':'list'}); result=s.close(); self.assertFalse(result['task_finished'])

    def test_vm_process_crash(self):
        s=self.start()
        # Kill only the exact held VMM incarnation from original prepared data.
        record=worker.parse((Path(s.collect()['native_records'])/'profile.json').read_bytes())['prepared']
        fd=os.pidfd_open(record['vmm_pid'])
        try:
            stat=(Path('/proc')/str(record['vmm_pid'])/'stat').read_text()
            self.assertEqual(int(stat.rsplit(') ',1)[1].split()[19]),record['vmm_start_ticks'])
            signal.pidfd_send_signal(fd,signal.SIGKILL)
        finally: os.close(fd)
        result=s.close(); self.assertEqual(result['terminal']['status'],'INCOMPLETE')

    def test_agent_timeout(self):
        s=self.start()
        # A real absolute lifetime; do not modify clocks or manufacture events.
        deadline=time.monotonic()+190
        while not s.closed and time.monotonic()<deadline: time.sleep(.25)
        self.assertTrue(s.closed); self.assertFalse(s.collect()['task_finished'])

    def test_vm_startup_failure(self):
        # This case must provision a valid protected profile with deliberately
        # unavailable runtime assets. Never replace the VMM with a shim.
        with self.assertRaises((SessionError,ValueError,OSError)):
            self.start()
        self.assertFalse(self.session and self.session.ready)

    def test_resource_exhaustion(self):
        s=self.start(); s.execute({'tool':'write','path':'totals.py','text':'while True: pass\n'})
        result=s.execute({'tool':'check'})
        self.assertFalse(result.get('passed',False)); self.finish()

    def test_unexpected_children(self):
        s=self.start(); s.execute({'tool':'write','path':'totals.py','text':'import os\nos.fork()\n'})
        result=s.execute({'tool':'check'})
        self.assertFalse(result.get('passed',False)); self.finish()

    def test_forced_shutdown(self):
        s=self.start(); result=s.close(); self.assertEqual(result['terminal']['status'],'INCOMPLETE')

    def test_clean_restart(self):
        s=self.start(); self.finish()
        # Second explicit installed profile required; no implicit VM retry.
        self.session=Session.start(SessionRequest('firecracker-measured',worker.digest(worker.encoded(worker.contract())),180),
            Path(self.case['restart_evidence']),installed_profile=Path(self.case['restart_profile']),profile_sha256=self.case['restart_sha256'])
        self.assertEqual(self.session.execute({'tool':'read','path':'totals.py'})['text'],worker.BASELINE['totals.py']); self.finish()

    def test_host_cleanup(self):
        s=self.start(); result=self.finish()
        observation=result['terminal']['native_record']['cleanup_observation']
        self.assertTrue(observation['held_vmm_exited']); self.assertTrue(observation['owned_cgroup_empty'])


if __name__=='__main__':
    unittest.main()
