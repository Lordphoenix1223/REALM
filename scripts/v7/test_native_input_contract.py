"""Immutable rootfs input framing controls; no VM or qualification claim."""
import copy
import socket
import tempfile
import threading
from pathlib import Path
import unittest
import coding_worker as worker
import host_planned_coding as planner
import coding_native_run as driver
import coding_task_verifier as referee

class SeparateInputControls(unittest.TestCase):
    def envelope(self):
        source={name:worker.digest((Path(__file__).parent/name).read_bytes()) for name in
                ('coding_worker.py','host_planned_coding.py','coding_native_client.py','candidate_channel_guard.py')}
        binding={k:'a'*64 for k in ('run_id','execution_id','challenge_root')}
        binding.update(task_sha256=worker.digest(worker.encoded(worker.contract())),worker_sha256=source['coding_worker.py'])
        step={'workflow':'b'*64,'role':'api','attempt':0,'history_prefix_blake3':'c'*64,'predecessor':None}
        envelope={'root':'d'*64,'inputs':{'schema':'realm.native-task-inputs/v1','submission':binding,
                 'native_subtask':step,'runtime_blake3':'e'*64,'policy_blake3':'f'*64}}
        return source,binding,step,envelope

    def test_original_frame_codec_carries_inputs_before_tools(self):
        source,binding,step,envelope=self.envelope()
        left,right=socket.socketpair()
        with left,right:
            thread=threading.Thread(target=planner.send,args=(left,envelope));thread.start()
            actual=planner.receive(right);thread.join(timeout=2);self.assertFalse(thread.is_alive())
        self.assertEqual(actual,envelope)
        launch=planner.launch_document(binding['challenge_root'],source,binding,step,actual)
        self.assertEqual(launch['native_inputs'],envelope)
        for kind in ('submission','native_subtask','runtime_blake3'):
            bad=copy.deepcopy(envelope)
            if kind=='submission':bad['inputs'][kind]['run_id']='f'*64
            elif kind=='native_subtask':bad['inputs'][kind]['history_prefix_blake3']='f'*64
            else:bad['inputs'][kind]='invalid'
            with self.assertRaises(ValueError):planner.launch_document(binding['challenge_root'],source,binding,step,bad)

    def test_input_commitment_is_preserved_in_existing_configure_scope(self):
        from types import SimpleNamespace
        source,binding,step,envelope=self.envelope()
        args=SimpleNamespace(source_commit='1'*40,native_task_role='api')
        task={'task_sha256':binding['task_sha256'],'worker_sha256':binding['worker_sha256'],
              'source_commit':args.source_commit,'checker_sha256':referee.native_api_scope()['checker_sha256'],
              'checker_scope_sha256':worker.digest(worker.encoded(referee.native_api_scope())),'role':'api'}
        scope=driver.prelaunch_scope(args,binding,None,task,step,envelope['root'])
        self.assertEqual(scope['task_inputs_blake3'],envelope['root'])
        self.assertNotIn('runtime_admission_id',scope) # Rust issues it after protected image measurement.
        with self.assertRaises(ValueError):driver.prelaunch_scope(args,binding,None,task,None,envelope['root'])

if __name__=='__main__':unittest.main()
