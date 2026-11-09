"""Independent negative controls for source/evidence joins and bounded intake."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.v7 import qualification as q
from scripts.v7 import verify_coding_development as independent


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'; self.source.mkdir()
        (self.source / 'Cargo.lock').write_text('frozen test dependency identity\n')
        for name, module in [('qualification.py', q), ('coding_worker.py', q.worker),
                             ('verify_coding_development.py', independent)]:
            target = self.source / 'scripts/v7' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(module.__file__, target)
        self.git('init', '-q')
        self.git('add', 'Cargo.lock', 'scripts/v7')
        self.git('-c', 'user.name=QualificationTest', '-c', 'user.email=test@example.invalid',
                 'commit', '-qm', 'frozen qualification fixture')
        self.campaign = self.root / 'campaign'
        q.prepare(self.source, self.campaign)
        self.case = json.loads((self.campaign / 'case.json').read_text())

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.source), *args], stderr=subprocess.PIPE)

    def assess(self, case=None):
        raw = q.canonical(self.case if case is None else case) + b'\n'
        (self.campaign / 'case.json').write_bytes(raw)
        return q.assess(self.campaign, q.sha(raw), self.source)

    def observation(self, step=3, classification='AUTONOMOUS_AGENT', status='PASS'):
        self.case['run_id'] = '1' * 64  # Actual V7 export uses a launch digest, not a UUID.
        data = b'{"claimed_success":true}\n'
        (self.campaign / 'claim.json').write_bytes(data)
        return {'step': step, 'classification': classification, 'status': status,
                'source_commit': self.case['source']['commit'], 'run_id': self.case['run_id'],
                'files': [{'path': 'claim.json', 'sha256': q.sha(data), 'bytes': len(data)}]}

    def test_complete_green_self_reports_cannot_qualify_a_release(self):
        self.case['observations'] = [self.observation(step) for step in range(1, 10)]
        self.case['controls'] = list(q.CONTROLS)
        report = self.assess()
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertFalse(report['release_ready'])
        self.assertFalse(report['execution_authenticated'])
        self.assertEqual(report['verified_controls'], [])
        self.assertEqual(len(report['steps']), 9)
        self.assertTrue(all(s['status'] == 'NOT_QUALIFIED' for s in report['steps']))

    def test_prior_source_and_another_run_cannot_fill_the_join(self):
        for field, value in [('source_commit', '0' * 40), ('run_id', 'another-run')]:
            with self.subTest(field=field):
                row = self.observation(); row[field] = value
                case = copy.deepcopy(self.case); case['observations'] = [row]
                with self.assertRaisesRegex(ValueError, 'cross-source or cross-run'):
                    self.assess(case)

    def test_tampered_truncated_and_missing_evidence_refuse(self):
        row = self.observation()
        for raw in (b'changed', b''):
            (self.campaign / 'claim.json').write_bytes(raw)
            case = copy.deepcopy(self.case); case['observations'] = [row]
            with self.assertRaisesRegex(ValueError, 'evidence pin differs'):
                self.assess(case)
        (self.campaign / 'claim.json').unlink()
        case['observations'] = [row]
        with self.assertRaises(OSError): self.assess(case)

    def test_case_digest_and_unknown_qualification_flags_refuse(self):
        with self.assertRaisesRegex(ValueError, 'case digest differs'):
            q.assess(self.campaign, '0' * 64, self.source)
        case = copy.deepcopy(self.case); case['release_ready'] = True
        with self.assertRaisesRegex(ValueError, 'release_ready flag'):
            self.assess(case)

    def test_legacy_profile_and_changed_predicate_refuse(self):
        for mutation in ('profile', 'task'):
            case = copy.deepcopy(self.case)
            if mutation == 'profile': case['profile'] = 'C0'
            else: case['task']['max_requests'] = 129
            with self.assertRaises(ValueError): self.assess(case)

    def test_dirty_source_or_dependency_change_refuse(self):
        (self.source / 'Cargo.lock').write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'source, tree, lock, verifier or cleanliness'):
            self.assess()

    def test_failures_retained_and_unit_replay_not_promoted(self):
        self.case['failures'] = [{'attempt': 'a', 'status': 'TIMEOUT', 'evidence_missing': True}]
        self.case['observations'] = [self.observation(classification='LOCAL_REPLAY', status='FAIL')]
        report = self.assess()
        self.assertEqual(report['failures'], self.case['failures'])
        self.assertEqual(report['observations'][0]['status'], 'FAIL')
        self.assertFalse(report['release_ready'])

    def test_json_duplicate_keys_nonfinite_and_bool_step_refuse(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"schema":NaN}'):
            (self.campaign / 'case.json').write_bytes(raw)
            with self.assertRaises(ValueError): q.assess(self.campaign, q.sha(raw), self.source)
        row = self.observation(); row['step'] = True
        self.case['observations'] = [row]
        with self.assertRaises(ValueError): self.assess()

    def test_path_escapes_and_symlink_directory_refuse(self):
        for path in ('.', '../secret', '/secret', 'a/../b', 'a//b', './b', 'a\\b'):
            with self.subTest(path=path), self.assertRaises(ValueError): q.relative(path)
        external = self.root / 'external'; external.mkdir(); (external / 'file').write_bytes(b'x')
        (self.campaign / 'link').symlink_to(external, target_is_directory=True)
        with self.assertRaises(OSError): q.evidence_read(self.campaign, 'link/file', 10)

    def test_fifo_and_hard_link_evidence_refuse(self):
        os.mkfifo(self.campaign / 'fifo')
        for reader, args in ((q.evidence_read, (self.campaign, 'fifo', 10)),
                             (independent.read_regular, (self.campaign / 'fifo', 10))):
            with self.assertRaises(ValueError): reader(*args)
        (self.campaign / 'file').write_bytes(b'x')
        os.link(self.campaign / 'file', self.campaign / 'alias')
        with self.assertRaises(ValueError): q.evidence_read(self.campaign, 'alias', 10)
        with self.assertRaises(ValueError): independent.read_regular(self.campaign / 'alias', 10)

    def test_reader_rejects_same_size_mutation_and_leaf_replacement(self):
        path = self.campaign / 'data'; path.write_bytes(b'abc')
        original = independent.os.read
        def changed(fd, size):
            data = original(fd, size)
            if data:
                path.write_bytes(b'xyz')
            return data
        with patch.object(independent.os, 'read', changed):
            with self.assertRaisesRegex(ValueError, 'evidence (bytes|identity) changed during read'):
                independent.read_regular(path, 100)
        self.assertEqual(path.read_bytes(), b'xyz')

    def test_launch_digest_join_is_preserved_and_missing_run_refuses(self):
        self.case['observations'] = [self.observation()]
        self.assertEqual(self.assess()['run_id'], '1' * 64)
        self.case['run_id'] = None
        with self.assertRaisesRegex(ValueError, 'actual producer run ID'):
            self.assess()

    def test_campaign_output_cannot_dirty_frozen_source(self):
        with self.assertRaisesRegex(ValueError, 'outside the source checkout'):
            q.prepare(self.source, self.source / 'campaign')
        self.assertFalse((self.source / 'campaign').exists())

    def test_running_verifier_must_match_the_declared_source(self):
        (self.source / 'scripts/v7/qualification.py').write_text('different verifier\n')
        with self.assertRaisesRegex(ValueError, 'running verifier/worker differs'):
            q.doctor(self.source)

    def test_cli_readiness_is_nonzero_even_with_valid_integrity(self):
        raw = (self.campaign / 'case.json').read_bytes()
        proc = subprocess.run([sys.executable, '-B', '-m', 'scripts.v7.qualification',
                               'assess', '--source', str(self.source), '--case-root',
                               str(self.campaign), '--case-sha256', q.sha(raw)],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['status'], 'INCOMPLETE')
        self.assertFalse(json.loads(proc.stdout)['release_ready'])

    def test_fresh_directory_is_not_overwritten(self):
        before = (self.campaign / 'case.json').read_bytes()
        with self.assertRaises(FileExistsError): q.prepare(self.source, self.campaign)
        self.assertEqual((self.campaign / 'case.json').read_bytes(), before)


class RetainedCodingDiagnosisTests(unittest.TestCase):
    def setUp(self):
        self.source = Path(q.__file__).resolve().parents[2]
        self.archive = self.source / 'evidence/v7/clean-closure-018-20261015/closed-clean-probe-018.tar.gz'
        self.pin = 'c8868997e43698d8c40e9595e76cb24e6229bf071af800995680e8f455a7ddae'

    def test_retained_clean_exit_never_promotes_and_changed_worker_refuses(self):
        import tarfile
        with tarfile.open(self.archive) as bundle:
            retained_worker = bundle.extractfile('executed-source/scripts/v7/coding_worker.py').read()
        if q.sha(retained_worker) != q.sha(Path(q.worker.__file__).read_bytes()):
            # A newer development Worker cannot stand in for the exact executed
            # native source. Assert the actual refusal; never repin or relax the
            # production diagnostic to make an old archive appear qualified.
            with self.assertRaisesRegex(ValueError, 'unsupported retained worker source'):
                q.diagnose_run(self.source, self.archive, self.pin)
            return
        report = q.diagnose_run(self.source, self.archive, self.pin)
        self.assertEqual(report['retained_closure']['status'], 'PASS')
        self.assertEqual(report['native_custody_audit'], 'REFUSE')
        self.assertEqual(list(report['native_record_permissions']['violations'].values()), ['0o646'])
        self.assertTrue(report['transcript']['finished'])
        self.assertFalse(report['release_ready'])
        self.assertFalse(report['actual_coding_realm_works'])
        self.assertFalse(report['execution_authenticated'])
        self.assertEqual(report['authority'], 'NONE')
        self.assertEqual(report['earliest_native_blocking_stage'], 2)
        self.assertEqual([r['status'] for r in report['steps']],
            ['UNKNOWN', 'REFUSE', 'UNKNOWN', 'REFUSE', 'REFUSE',
             'NOT_RUN', 'NOT_RUN', 'NOT_RUN', 'NOT_RUN'])

    def test_substituted_run_and_missing_custody_refuse_even_with_recomputed_archive_pin(self):
        import io
        import tarfile
        with tarfile.open(self.archive) as bundle:
            files = [(m, bundle.extractfile(m).read()) for m in bundle]
        for mutation in ('run', 'missing-custody'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary).resolve() / 'substituted.tar.gz'
                with tarfile.open(path, 'w:gz') as bundle:
                    for member, raw in files:
                        if mutation == 'missing-custody' and member.name == 'run/native/custody/custody.jsonl':
                            continue
                        if mutation == 'run' and member.name == 'run/native/custody/output':
                            body = json.loads(raw); body['binding']['run_id'] = '0' * 64
                            raw = q.canonical(body)
                        record = copy.copy(member); record.size = len(raw)
                        bundle.addfile(record, io.BytesIO(raw))
                with self.assertRaises((ValueError, KeyError)):
                    q.diagnose_run(self.source, path, q.sha(path.read_bytes()))


if __name__ == '__main__':
    unittest.main()
