"""Physical semantic counterexample; not a genuine execution/publication fixture."""
import copy
import json
import pathlib
import platform
import shutil
import tempfile
import unittest

import coding_worker as worker
import coding_task_verifier as referee


class OwnedRequestTests(unittest.TestCase):
    def test_actual_subject_exact_packet_and_strict_request_controls(self):
        # Input validation only. This does not run a native child or mint a
        # semantic PASS; all files deliberately remain broken task candidates.
        with tempfile.TemporaryDirectory(prefix='r7-owned-input-') as name:
            root = pathlib.Path(name) / 'subject'
            binding = {k:'a'*64 for k in ('run_id','execution_id','challenge_root')}
            binding.update(task_sha256=worker.digest(worker.encoded(worker.contract())),
                           worker_sha256=worker.digest(pathlib.Path(worker.__file__).read_bytes()))
            packet = {'schema':'realm.coding-submission.v1','binding':binding,
                      'transcript_head':'b'*64,
                      'files':[{'path':p,'text':worker.BASELINE[p]+'\n# changed but not repaired\n','mode':0o600}
                               for p in worker.FILES]}
            raw = worker.encoded(packet)
            referee.candidate_from_packet(raw, binding, root)
            q = {'schema':'realm.owned-coding-referee-request.v2','binding':binding,
                 'packet_hex':raw.hex(),'seed':2**64-1,
                 'scope':{'submission':binding,'source_commit':'d'*40,
                          'checker_sha256':referee.describe()['checker_sha256'],
                          'checker_scope_sha256':worker.digest(worker.encoded(referee.describe()))}}
            self.assertEqual(referee.owned_request(worker.encoded(q), root), q)
            admitted = copy.deepcopy(q)
            admitted['scope']['runtime_admission_id'] = 'f' * 64
            self.assertEqual(referee.owned_request(worker.encoded(admitted), root), admitted)
            for value in (None, True, '', 'F' * 64, '0' * 63, {'authority': 'ACCEPT'}):
                bad = copy.deepcopy(admitted); bad['scope']['runtime_admission_id'] = value
                with self.subTest(admission=value), self.assertRaises(ValueError):
                    referee.owned_request(worker.encoded(bad), root)
            bad = copy.deepcopy(admitted); bad['scope']['qualification'] = 'ACCEPT'
            with self.assertRaises(ValueError):
                referee.owned_request(worker.encoded(bad), root)
            for key, value in [('schema','unknown'),('seed',True),('seed',-1),('seed',2**64),
                               ('packet_hex',raw.hex().upper()),('extra',0)]:
                bad = copy.deepcopy(q); bad[key] = value
                with self.subTest(key=key,value=str(value)[:30]), self.assertRaises(ValueError):
                    referee.owned_request(worker.encoded(bad), root)
            duplicate = json.dumps(q)[:-1]+',"seed":0}'
            with self.assertRaises(ValueError):
                referee.owned_request(duplicate.encode(), root)
            bad = copy.deepcopy(q); bad['binding']['run_id'] = 'c'*64
            with self.assertRaises(ValueError):
                referee.owned_request(worker.encoded(bad), root)
            for field in ('source_commit', 'checker_sha256', 'checker_scope_sha256'):
                bad = copy.deepcopy(q); bad['scope'][field] = '0'*64
                with self.subTest(scope_field=field), self.assertRaises(ValueError):
                    referee.owned_request(worker.encoded(bad), root)
            bad = copy.deepcopy(q); bad['scope']['submission']['execution_id'] = 'e'*64
            with self.assertRaises(ValueError):
                referee.owned_request(worker.encoded(bad), root)
            subject = root / worker.FILES[0]
            subject.write_text('# substituted subject\n'); subject.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'subject differs'):
                referee.owned_request(worker.encoded(q), root)
            subject.unlink(); subject.symlink_to(root / worker.FILES[1])
            with self.assertRaises(ValueError):
                referee.owned_request(worker.encoded(q), root)


class RefereeCounterexample(unittest.TestCase):
    def test_missing_file_and_substituted_checker_scope_refuse_before_candidate_execution(self):
        with tempfile.TemporaryDirectory(prefix='r7-referee-input-control-') as name:
            root = pathlib.Path(name); candidate = root / 'candidate'; candidate.mkdir(mode=0o700)
            for path in worker.FILES[:2]:
                item = candidate / path; item.write_text('raise RuntimeError("must not run")\n'); item.chmod(0o600)
            scope = worker.digest(worker.encoded(referee.describe()))
            for pin in ('0' * 64, scope):
                with self.assertRaises(ValueError):
                    referee.verify(candidate, root / 'independent', pin, 128)
                self.assertFalse((root / 'independent').exists())

    @unittest.skipUnless(platform.system() == 'Darwin' or
                         (platform.system() == 'Linux' and shutil.which('bwrap')),
                         'requires existing Seatbelt or bubblewrap')
    def test_report_only_repair_and_empty_tests_refuse_three_file_obligations(self):
        with tempfile.TemporaryDirectory(prefix='r7-referee-control-') as name:
            root = pathlib.Path(name); candidate = root / 'candidate'; candidate.mkdir(mode=0o700)
            programs = {
                'totals.py': worker.BASELINE['totals.py'] + '\n# changed but broken\n',
                'test_totals.py': '# intentionally no tests\n',
                'report.py': '''import json,sys
try:
 rows=json.load(sys.stdin)
 if not isinstance(rows,list): raise ValueError()
 totals={}
 for row in rows:
  if not isinstance(row,dict) or set(row)!={'category','amount'}: raise ValueError()
  key=row['category']; value=row['amount']
  if not isinstance(key,str) or not key.strip() or type(value) is not int: raise ValueError()
  key=key.strip();totals[key]=totals.get(key,0)+value
 print(json.dumps({'totals':[{'category':k,'amount':totals[k]} for k in sorted(totals)],'net':sum(totals.values())}))
except (ValueError,TypeError): sys.exit(2)
'''}
            for path, text in programs.items():
                item = candidate / path; item.write_text(text); item.chmod(0o600)
            self.assertTrue(worker.check(worker.Sandbox(candidate), 128)['passed'])
            scope = worker.digest(worker.encoded(referee.describe()))
            result = referee.verify(candidate, root / 'independent', scope, 128)
            self.assertEqual(result['status'], 'REFUSE_BOUNDED_PROPERTIES')
            self.assertFalse(all(row['passed'] for row in result['api_driver_checks']))
            self.assertFalse(result['baseline_discrimination']['passed'])
            self.assertTrue(result['subject_unchanged'])
            self.assertEqual(result['same_run_native_join'], 'NOT_ESTABLISHED')
            self.assertEqual(result['authority'], 'NONE')


if __name__ == '__main__':
    unittest.main()
