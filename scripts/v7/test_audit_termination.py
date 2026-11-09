"""Regression checks against the two retained, physically executed V7 runs."""
import hashlib
import io
import json
import tarfile
import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.v7 import audit_termination as auditor
from scripts.v7.audit_termination import inspect


ROOT = Path(__file__).resolve().parents[2] / 'evidence/v7/host-planned-task-20261012'
RUNS = {
    'closed-host-planned-probe-012.tar.gz': '88d378a15b6e86be464594ed571b94b3569ef079a2161245eeea8f7e8802aa8a',
    'reproduction-013.tar.gz': 'daebc4176772afeb49f1f53c93dceddc83f37eb72b72dcefb55bc00be9b2d997',
}


class TerminationAuditTest(unittest.TestCase):
    def test_live_precleanup_distinguishes_run_012(self):
        report = inspect(ROOT / 'closed-host-planned-probe-012.tar.gz', RUNS['closed-host-planned-probe-012.tar.gz'])
        self.assertEqual(report['precleanup_pidfd_exited'], False)
        self.assertEqual(report['cause'], 'CONTROLLER_CLEANUP_SUPPORTED')
        self.assertTrue(report['observed_oom_counters_zero'])
        self.assertFalse(report['exclusive_sender_proven'])
        self.assertFalse(report['release_ready'])

    def test_missing_precleanup_limits_run_013_conclusion(self):
        report = inspect(ROOT / 'reproduction-013.tar.gz', RUNS['reproduction-013.tar.gz'])
        self.assertIsNone(report['precleanup_pidfd_exited'])
        self.assertEqual(report['cause'], 'UNKNOWN_NO_PRECLEANUP_OBSERVATION')
        self.assertTrue(report['observed_oom_counters_zero'])
        self.assertFalse(report['native_terminal_closure'])

    def test_corrupted_retained_archive_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tampered.tar.gz'
            original = (ROOT / 'reproduction-013.tar.gz').read_bytes()
            path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'archive SHA-256 differs'):
                inspect(path, RUNS['reproduction-013.tar.gz'])

    def test_embedded_historical_source_survives_current_probe_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = root / 'scripts/v7/coding_guest_probe.py'
            current.parent.mkdir(parents=True)
            current.write_text('# a different future probe\n')
            with patch.object(auditor, 'SOURCE_ROOT', root), \
                 patch.object(auditor.subprocess, 'check_output', side_effect=AssertionError('unexpected Git lookup')):
                report = inspect(ROOT / 'closed-host-planned-probe-012.tar.gz',
                                 RUNS['closed-host-planned-probe-012.tar.gz'])
            self.assertEqual(report['probe_source_origin'], 'source/coding_guest_probe.py')
            self.assertEqual(report['cause'], 'CONTROLLER_CLEANUP_SUPPORTED')

    def test_hash_only_archive_reads_exact_historical_git_source(self):
        with patch.object(auditor.subprocess, 'check_output', wraps=subprocess.check_output) as git:
            report = inspect(ROOT / 'reproduction-013.tar.gz', RUNS['reproduction-013.tar.gz'])
        commit = '8cdca3d2fc4603583dad5ded1b7bbb803573ac89'
        git.assert_called_once_with(['git', '-C', str(auditor.SOURCE_ROOT), 'show',
                                    commit + ':scripts/v7/coding_guest_probe.py'], stderr=subprocess.PIPE)
        self.assertEqual(report['probe_source_commit'], commit)
        self.assertFalse(report['release_ready'])

    def test_missing_historical_git_object_cannot_fall_back_to_current_source(self):
        with patch.object(auditor.subprocess, 'check_output',
                          side_effect=subprocess.CalledProcessError(128, ['git'])):
            with self.assertRaisesRegex(ValueError, 'retained probe Git source unavailable'):
                inspect(ROOT / 'reproduction-013.tar.gz', RUNS['reproduction-013.tar.gz'])

    def test_rehashed_archive_with_substituted_driver_pin_refuses(self):
        output = io.BytesIO()
        with tarfile.open(ROOT / 'reproduction-013.tar.gz', 'r:gz') as original, \
             tarfile.open(fileobj=output, mode='w:gz') as rewritten:
            for member in original:
                data = original.extractfile(member).read()
                if member.name == 'run/profile.json':
                    profile = json.loads(data)
                    profile['driver_sha256'] = '0' * 64
                    data = json.dumps(profile).encode()
                member.size = len(data)
                rewritten.addfile(member, io.BytesIO(data))
        forged = output.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'forged.tar.gz'
            path.write_bytes(forged)
            with self.assertRaisesRegex(ValueError, 'retained probe/profile source pin differs'):
                inspect(path, hashlib.sha256(forged).hexdigest())


if __name__ == '__main__':
    unittest.main()
