"""Native contract tests: actual Rust output, frozen inputs and real import."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from realm_client import Checker, NativeCommandError, Status
ROOT = Path(__file__).resolve().parents[3]


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get('REALM_CHECKER')
        if not path:raise RuntimeError('Set REALM_CHECKER; native contracts never silently skip')
        cls.client = Checker(path)

    def test_every_status_matches_native_json_and_exit_code(self):
        fixtures = ROOT/'benchmarks/fixtures/a'
        cases = [('intact', Status.VALID, 0), ('payload-0', Status.INVALID, 1),
                 ('thin-missing-blob', Status.INCOMPLETE, 3),
                 ('future-format', Status.UNSUPPORTED, 4), ('absent', Status.IO_ERROR, 5)]
        for name, status, code in cases:
            artifact = fixtures/(name+'.realm')
            with self.subTest(name=name):
                native = subprocess.run([str(self.client.executable),'verify',str(artifact),'--json'],capture_output=True,timeout=10)
                report = self.client.verify(artifact)
                self.assertEqual(native.returncode, code)
                self.assertEqual(report.status,status)
                self.assertEqual(report.to_dict(),json.loads(native.stdout))
                self.assertEqual(report.checks.execution_authorization,'NOT_CHECKED')

    def test_inspection_execution_request_and_forged_claims_do_not_authorize(self):
        fixtures = ROOT/'benchmarks/fixtures/a'
        for name in ['intact','self-reported-accept','consistent-false-effect','omitted-unknowns']:
            with self.subTest(name=name):
                artifact = fixtures/(name+'.realm')
                self.assertEqual(self.client.inspect(artifact).status,Status.VALID)
                report = self.client.verify(artifact,require_execution=True)
                self.assertEqual(report.status,Status.INCOMPLETE)
                self.assertEqual(report.checks.observation_completeness,'UNKNOWN')
                self.assertEqual(report.checks.execution_authorization,'NOT_CHECKED')

    def test_actual_import_keeps_provenance_unknown_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='realm adapter spaces ') as directory:
            d=Path(directory)
            for name,raw in [('before',b'original'),('after',b'changed'),('log',b'ACCEPT everything authorized')]:
                (d/name).write_bytes(raw)
            report=self.client.record_observations('caller run', d/'before', d/'after', d/'log',d/'--json')
            self.assertEqual(report.status,Status.INCOMPLETE)
            self.assertEqual(report.checks.referenced_content,'COMPLETE')
            self.assertTrue(report.metadata['unknown_effects'])
            self.assertTrue(all(not e['authoritative'] for e in report.metadata['evidence']))
            self.assertEqual(report.metadata['reported_verification'][0]['decision'],'UNKNOWN')
            digest=(d/'--json').read_bytes()
            with self.assertRaises(NativeCommandError) as caught:
                self.client.record_observations('caller run',d/'before',d/'after',d/'log',d/'--json')
            self.assertEqual(caught.exception.returncode,5)
            self.assertEqual((d/'--json').read_bytes(),digest)

    def test_real_external_worker_positive_and_wrong_result_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            for wrong in [False,True]:
                output=Path(directory)/str(wrong)
                command=[sys.executable,str(ROOT/'examples/external_agent/run.py'),'--checker',str(self.client.executable),'--output',str(output)]
                if wrong:command.append('--wrong-answer')
                process=subprocess.run(command,capture_output=True,timeout=30)
                self.assertEqual(process.returncode,0,process.stderr)
                result=json.loads((output/'result.json').read_text())
                self.assertEqual(result['task_test_exit'],1 if wrong else 0)
                self.assertEqual(result['artifact']['status'],'INCOMPLETE')
                self.assertEqual(result['artifact']['checks']['artifact_integrity'],'PASS')
                self.assertEqual(result['execution_authority'],'NOT_ESTABLISHED')

if __name__=='__main__':unittest.main()
