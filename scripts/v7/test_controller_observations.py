import json
from pathlib import Path
import tempfile
import unittest

import coding_worker as worker
from controller_observations import ObservedBroker


class BrokerObservationTests(unittest.TestCase):
    def test_actual_result_denial_and_missing_name_are_bound_to_directory_generation(self):
        with tempfile.TemporaryDirectory(prefix='realm-observation-') as name:
            broker = worker.Worker(Path(name) / 'run', worker.digest(worker.encoded(worker.contract())))
            binding = {'run_id': '1'*64, 'execution_id': '2'*64, 'challenge_root': '3'*64,
                       'task_sha256': worker.digest(worker.encoded(worker.contract())),
                       'worker_sha256': worker.digest(Path(worker.__file__).read_bytes())}
            observed = ObservedBroker(broker, binding)
            try:
                self.assertEqual(observed.request({'tool':'read','path':'totals.py'})['text'], worker.BASELINE['totals.py'])
                with self.assertRaisesRegex(ValueError, 'outside scope'):
                    observed.request({'tool':'read','path':'missing.py'})
                (broker.candidate / 'totals.py').unlink()
                with self.assertRaises(ValueError):
                    observed.request({'tool':'read','path':'totals.py'})
                rows = [json.loads(v)['event']['controller_observation'] for v in
                        (broker.root / 'events.jsonl').read_bytes().splitlines()
                        if 'controller_observation' in json.loads(v)['event']]
                self.assertEqual([r['phase'] for r in rows], ['request','result']*3)
                self.assertEqual(rows[-1]['namespace']['objects']['totals.py']['errno'], 2)
                self.assertNotEqual(rows[0]['namespace']['snapshot_sha256'], rows[-1]['namespace']['snapshot_sha256'])
                self.assertTrue(all(r['binding'] == binding and r['authority'] == 'NONE' for r in rows))
                self.assertEqual(rows[1]['status'], 'TOOL_RESULT')
                self.assertEqual(rows[3]['status'], 'REFUSE')
            finally:
                broker.close()
