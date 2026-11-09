"""Actual bounded API referee executions; no VM owner or qualification claim."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
import coding_worker as worker
import coding_task_verifier as referee

TOTALS = '''def summarize(records):
    if type(records) is not list: raise ValueError()
    totals = {}
    for row in records:
        if type(row) is not dict or set(row) != {'category','amount'}: raise ValueError()
        category, amount = row['category'], row['amount']
        if type(category) is not str or not category.strip() or type(amount) is not int: raise ValueError()
        category = category.strip()
        totals[category] = totals.get(category, 0) + amount
    return totals
'''
TESTS = '''from totals import summarize
assert summarize([{'category':' A ','amount':-3}]) == {'A':-3}
try: summarize([{'category':'A','amount':True}])
except ValueError: pass
else: raise AssertionError('bool accepted')
'''

class NativeSubtaskTests(unittest.TestCase):
    def test_actual_api_referee_failed_attempt_then_repair(self):
        # Both original on-disk results are retained when an evidence root is
        # supplied. These are ordinary checker children, NOT native VM owners.
        with tempfile.TemporaryDirectory(prefix='realm-native-api-check-') as temporary:
            root = Path(os.environ.get('REALM_NATIVE_SUBTASK_EVIDENCE', temporary))
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            candidate = root / 'candidate'; candidate.mkdir(mode=0o700)
            for path in worker.FILES:
                text = worker.BASELINE[path] if path == 'report.py' else (
                    worker.BASELINE[path]+'\n# attempted repair\n')
                (candidate/path).write_text(text); (candidate/path).chmod(0o600)
            pin = worker.digest(worker.encoded(referee.native_api_scope()))
            failed = referee.verify_native_api(candidate, root/'failed', pin, 128, packet_bytes=4096)
            self.assertEqual(failed['status'], 'REFUSE_API_SUBTASK')
            self.assertFalse(failed['baseline_discrimination']['passed'])
            for path,text in [('totals.py', TOTALS), ('test_totals.py', TESTS)]:
                (candidate/path).write_text(text); (candidate/path).chmod(0o600)
            passed = referee.verify_native_api(candidate, root/'passed', pin, 128, packet_bytes=4096)
            self.assertEqual(passed['status'], 'PASS_API_SUBTASK')
            self.assertEqual(len(passed['api_driver_checks']), 17)
            self.assertTrue(all(x['passed'] for x in passed['api_driver_checks']))
            self.assertEqual(worker.parse((root/'failed/result.json').read_bytes()), failed)
            self.assertEqual(passed['authority'], 'NONE')
            self.assertEqual(passed['same_run_native_join'], 'NOT_ESTABLISHED')
            too_large = referee.verify_native_api(candidate,root/'oversize',pin,128,packet_bytes=16385)
            self.assertEqual(too_large['status'],'REFUSE_API_SUBTASK')
            (candidate/'report.py').write_text('# forbidden API effect\n')
            with self.assertRaisesRegex(ValueError,'changed CLI'):
                referee.verify_native_api(candidate, root/'forbidden',pin,128)
            self.assertFalse((root/'forbidden').exists())

    def test_cli_subject_cannot_change_original_api_predecessor(self):
        with tempfile.TemporaryDirectory(prefix='realm-cli-predecessor-') as name:
            binding={k:'a'*64 for k in ('run_id','execution_id','challenge_root')}
            scope=referee.describe()
            binding.update(task_sha256=scope['original_task_sha256'],worker_sha256=scope['oracle_worker_sha256'])
            prior={'schema':'realm.coding-submission.v1','binding':binding,'transcript_head':'b'*64,
                   'files':[{'path':p,'text':worker.BASELINE[p]+'\n# changed\n','mode':0o600} for p in worker.FILES]}
            raw=worker.encoded(prior)
            candidate=Path(name)/'candidate';referee.candidate_from_packet(raw,binding,candidate)
            q={'schema':'realm.owned-coding-referee-request.v2','binding':binding,'packet_hex':raw.hex(),'seed':7,
               'scope':{'submission':binding,'source_commit':'d'*40,'checker_sha256':scope['checker_sha256'],
                        'checker_scope_sha256':worker.digest(worker.encoded(scope)),
                        'native_subtask':{'workflow':'c'*64,'role':'cli','attempt':1,'history_prefix_blake3':'e'*64,
                                          'predecessor':{'submission':binding,'packet_hex':raw.hex()}}}}
            self.assertEqual(referee.owned_request(worker.encoded(q),candidate),q)
            bad=copy.deepcopy(q);bad['scope']['native_subtask']['predecessor']=None
            with self.assertRaises(ValueError):referee.owned_request(worker.encoded(bad),candidate)
            changed=copy.deepcopy(prior);changed['files'][0]['text']+='\n# substituted API\n'
            bad=copy.deepcopy(q);bad['packet_hex']=worker.encoded(changed).hex()
            with self.assertRaisesRegex(ValueError,'original API predecessor'):
                referee.owned_request(worker.encoded(bad),candidate)

if __name__ == '__main__': unittest.main()
