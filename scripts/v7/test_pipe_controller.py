"""Actual Linux kernel/pipe controls. No coding qualification or mocked seccomp."""
import json
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest


@unittest.skipUnless(platform.system() == 'Linux' and os.environ.get('REALM_PIPE_CONTROLLER_BINARY'),
                     'requires the actual Linux coding_controller binary')
class PipeControllerTests(unittest.TestCase):
    def run_child(self, args, data=b'', fds=()):
        result = subprocess.run([os.environ['REALM_PIPE_CONTROLLER_BINARY'], *args], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=fds,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=5)
        return result

    def test_absent_present_alias_fd_subprocess_and_runtime_inputs(self):
        with tempfile.TemporaryDirectory(prefix='r7-pipe-guard-') as name:
            root = Path(name); target = root / 'protected'; secret = root / 'secret'
            secret.write_bytes(b'private data'); alias = root / 'alias'; alias.symlink_to(secret)
            fd = os.open(secret, os.O_RDONLY)
            captures = []
            try:
                for present in (False, True):
                    if present: target.write_bytes(b'present')
                    child = self.run_child(['--probe', str(target), str(alias), str(fd)], fds=(fd,))
                    self.assertEqual(child.returncode, 0, child.stderr)
                    result = json.loads(child.stdout)
                    self.assertTrue(result['inherited_before'])
                    for key, row in result['observations'].items():
                        self.assertEqual(row, {'return': -1, 'errno': 1}, (key, row))
                    self.assertIsNotNone(result['vdso_time'], 'retain the unmediated vDSO counterexample')
                    self.assertEqual(result['complete_observation_admission'], 'REFUSE')
                    captures.append({'present': present, 'stdout_hex': child.stdout.hex(),
                                     'stderr_hex': child.stderr.hex(), 'exit': child.returncode})
                self.assertEqual(json.loads(bytes.fromhex(captures[0]['stdout_hex']))['observations'],
                                 json.loads(bytes.fromhex(captures[1]['stdout_hex']))['observations'])
                output = os.environ.get('REALM_PIPE_CONTROLLER_CAPTURE')
                if output:
                    with Path(output).open('x') as f:
                        json.dump({'authority': 'NONE', 'path_lookup_gate': 'DENIED_BEFORE_VFS',
                                   'binary_sha256': hashlib.sha256(Path(os.environ['REALM_PIPE_CONTROLLER_BINARY']).read_bytes()).hexdigest(),
                                   'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                   'kernel': platform.release(), 'architecture': platform.machine(),
                                   'complete_observation_admission': 'REFUSE', 'captures': captures}, f, indent=2)
            finally:
                os.close(fd)

    def test_actual_relay_only_accepts_ordered_same_run_bounded_tools(self):
        binding = {name: digit * 64 for name, digit in zip(
            ('run_id', 'execution_id', 'challenge_root', 'task_sha256', 'worker_sha256'), '12345')}
        def frame(sequence, request, identity=None):
            return {'binding': identity or binding, 'sequence': sequence, 'request': request}
        good = [frame(0, {'tool': 'read', 'path': 'totals.py'}), frame(1, {'tool': 'finish'})]
        def invoke(frames):
            return self.run_child(['--relay', json.dumps(binding)], b''.join(json.dumps(v).encode() + b'\n' for v in frames))
        child = invoke(good); self.assertEqual(child.returncode, 0, child.stderr)
        rows = [json.loads(v) for v in child.stdout.splitlines()]
        self.assertEqual([r['request'] for r in rows], [r['request'] for r in good])
        self.assertTrue(all(r['authority'] == 'NONE' for r in rows))
        foreign = dict(binding, run_id='f' * 64)
        cases = [[good[0], frame(1, {'tool': 'finish'}, foreign)],
                 [frame(0, {'tool': 'finish'}, foreign)],
                 [good[0], frame(0, {'tool': 'finish'})],
                 [frame(0, {'tool': 'read', 'path': '../secret'})],
                 [frame(0, {'tool': 'exec', 'command': '/bin/sh'})],
                 [frame(0, {'tool': 'write', 'path': 'totals.py', 'text': 'x' * 32769})],
                 [good[0]], good + [frame(2, {'tool': 'list'})]]
        for frames in cases:
            failed = invoke(frames)
            self.assertEqual(failed.returncode, 2, failed.stdout)
        duplicate = self.run_child(['--relay', json.dumps(binding)], b'{"binding":{},"binding":{}}\n')
        self.assertEqual(duplicate.returncode, 2)
        maximum = [frame(i, {'tool': 'list'}) for i in range(127)] + [frame(127, {'tool':'finish'})]
        self.assertEqual(invoke(maximum).returncode, 0)
        self.assertEqual(invoke(maximum + [frame(128, {'tool':'list'})]).returncode, 2)

    def test_same_process_proposals_reach_existing_broker_with_recorded_results(self):
        import coding_worker as worker
        from controller_observations import ObservedBroker
        with tempfile.TemporaryDirectory(prefix='r7-relay-broker-') as name:
            broker = worker.Worker(Path(name) / 'run', worker.digest(worker.encoded(worker.contract())))
            binding = {'run_id':'1'*64, 'execution_id':'2'*64, 'challenge_root':'3'*64,
                       'task_sha256':worker.digest(worker.encoded(worker.contract())),
                       'worker_sha256':worker.digest(Path(worker.__file__).read_bytes())}
            observed = ObservedBroker(broker, binding)
            child = subprocess.Popen([os.environ['REALM_PIPE_CONTROLLER_BINARY'], '--relay', json.dumps(binding)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, close_fds=True)
            requests = [{'tool':'list'}, {'tool':'read','path':'totals.py'},
                        {'tool':'write','path':'report.py','text':'# bounded observation control\n'}, {'tool':'finish'}]
            try:
                for sequence, request in enumerate(requests):
                    raw = json.dumps({'binding':binding,'sequence':sequence,'request':request}).encode()+b'\n'
                    child.stdin.write(raw); child.stdin.flush()
                    reply = child.stdout.readline(131073)
                    decoded = json.loads(reply)
                    self.assertEqual(decoded['binding'], binding)
                    self.assertEqual(decoded['request'], request)
                    self.assertEqual(decoded['complete_observation_admission'], 'REFUSE')
                    broker.event({'controller_pipe_bytes':{'binding':binding,'stdin_hex':raw.hex(),
                                                          'stdout_hex':reply.hex(),'authority':'NONE'}})
                    if request['tool']=='finish':
                        with self.assertRaisesRegex(ValueError,'independent check required'):
                            observed.request(request)
                    else:
                        observed.request(request)
                child.stdin.close(); child.stdin=None
                out,err=child.communicate(timeout=5)
                self.assertEqual((child.returncode,out,err),(0,b'',b''))
                self.assertEqual((broker.candidate/'report.py').read_text(),requests[2]['text'])
                rows=[json.loads(v)['event'] for v in (broker.root/'events.jsonl').read_bytes().splitlines()]
                self.assertEqual(sum('controller_pipe_bytes' in r for r in rows),4)
                self.assertEqual(sum('controller_observation' in r for r in rows),8)
                self.assertFalse(broker.done, 'protocol closure must not invent successful task completion')
            finally:
                if child.poll() is None: child.kill();child.wait()
                for stream in (child.stdin,child.stdout,child.stderr):
                    if stream:stream.close()
                broker.close()


if __name__ == '__main__':
    unittest.main()
