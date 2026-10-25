"""Fast protocol tests use saved Rust output and process stubs, never a verifier."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from realm_client import Checker, CheckerTimeout, CheckerUnavailable, NativeCommandError, ProtocolError, Status
ROOT = Path(__file__).resolve().parents[3]


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.client = Checker(sys.executable)
        self.raw = json.loads((ROOT/'site/evidence/intact.json').read_text())

    def result(self, raw=None, code=0):
        return subprocess.CompletedProcess([], code, json.dumps(self.raw if raw is None else raw).encode(), b'')

    def test_exact_report_and_no_shell_or_relative_flag_injection(self):
        with patch('realm_client.subprocess.run', return_value=self.result()) as call:
            report = self.client.verify('--json')
        self.assertEqual(report.status, Status.VALID)
        self.assertEqual(report.to_dict(), self.raw)
        args, kwargs = call.call_args
        self.assertTrue(Path(args[0][2]).is_absolute())
        self.assertFalse(kwargs['shell'])
        changed = report.metadata; changed['extra'] = 'local edit'
        self.assertNotIn('extra', report.metadata)

    def test_schema_code_authority_and_proof_level_mismatches_fail_closed(self):
        for edit in [lambda r:r.update(schema='future'), lambda r:r.update(status='ACCEPT'),
                     lambda r:r['checks'].update(execution_authorization='ACCEPT'),
                     lambda r:r['checks'].update(observation_completeness='COMPLETE'),
                     lambda r:r['checks'].update(referenced_content='NOT_CHECKED'),
                     lambda r:r.update(metadata=[]), lambda r:r.pop('status')]:
            raw = copy.deepcopy(self.raw); edit(raw)
            with self.subTest(raw=raw), patch('realm_client.subprocess.run', return_value=self.result(raw)):
                with self.assertRaises(ProtocolError):self.client.verify('input')
        with patch('realm_client.subprocess.run', return_value=self.result(code=1)):
            with self.assertRaises(ProtocolError):self.client.inspect('input')

    def test_non_json_duplicate_keys_and_nan_are_not_reports(self):
        for raw in [b'not JSON', b'{"schema":"a","schema":"b"}', b'{"status":NaN}']:
            with patch('realm_client.subprocess.run', return_value=subprocess.CompletedProcess([], 0, raw, b'')):
                with self.assertRaises(ProtocolError):self.client.verify('input')

    def test_launch_timeout_usage_and_signal_failures_remain_distinct(self):
        for error, expected in [(FileNotFoundError('missing'), CheckerUnavailable),
                                (subprocess.TimeoutExpired('checker', 1), CheckerTimeout)]:
            with patch('realm_client.subprocess.run', side_effect=error):
                with self.assertRaises(expected):self.client.verify('input')
        for code in [2, -9, 127]:
            with patch('realm_client.subprocess.run', return_value=self.result(code=code)):
                with self.assertRaises(NativeCommandError) as caught:self.client.verify('input')
                self.assertEqual(caught.exception.returncode, code)

    def test_import_failure_does_not_invent_a_report(self):
        with patch('realm_client.subprocess.run', return_value=subprocess.CompletedProcess([],5,b'',b'output exists')):
            with self.assertRaises(NativeCommandError) as caught:
                self.client.record_observations('run', 'before','after','log','out')
            self.assertEqual(caught.exception.returncode,5)
            self.assertEqual(caught.exception.operation,'record')

    def test_timeout_and_run_id_validation(self):
        for timeout in [0, -1, float('inf'), float('nan')]:
            with self.assertRaises(ValueError):Checker(sys.executable, timeout=timeout)
        for run in ['', 'x'*257, 'é'*129]:
            with self.assertRaises(ValueError):self.client.record_observations(run,'b','a','l','o')

if __name__ == '__main__':unittest.main()
