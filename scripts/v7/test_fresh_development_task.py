"""Controls for explicit development task selection, never native admission."""
import importlib
import json
from pathlib import Path
import tempfile
import unittest

import coding_worker as worker
import verify_coding_development as auditor


class FreshTaskControls(unittest.TestCase):
    def setUp(self):
        importlib.reload(worker)

    def tearDown(self):
        importlib.reload(worker)

    def select(self, name):
        p = Path(__file__).parent / 'fresh_tasks' / (name + '.definition.json')
        worker.configure_development_task(p, worker.digest(p.read_bytes()))
        return worker.contract()['development_task']

    def test_default_native_import_retains_original_contract(self):
        self.assertIsNone(worker.DEVELOPMENT_TASK)
        self.assertNotIn('development_task', worker.contract())
        self.assertIn('Repair totals.py', worker.DESCRIPTION)

    def test_wrong_pin_cannot_mutate_task(self):
        old = worker.contract()
        p = Path(__file__).parent / 'fresh_tasks/casefold-clear.definition.json'
        with self.assertRaisesRegex(ValueError, 'pin differs'):
            worker.configure_development_task(p, '0' * 64)
        self.assertEqual(worker.contract(), old)

    def test_casefold_and_zero_semantics_have_independent_oracles(self):
        profile = self.select('casefold-clear')
        rows = [{'category': ' Straße ', 'amount': 5}, {'category': 'STRASSE', 'amount': -5}]
        expected = {'totals': [], 'net': 0}
        self.assertEqual(worker.expected(rows), expected)
        self.assertEqual(auditor.oracle(rows, profile), expected)
        self.assertEqual(len(auditor.cases(7, profile)), 19)

    def test_nfc_preserves_case_and_zero(self):
        profile = self.select('nfc-retain')
        rows = [{'category': 'e\u0301', 'amount': 0}, {'category': 'é', 'amount': 2},
                {'category': 'A', 'amount': 0}, {'category': 'a', 'amount': 3}]
        expected = {'totals': [{'category': 'A', 'amount': 0}, {'category': 'a', 'amount': 3},
                               {'category': 'é', 'amount': 2}], 'net': 5}
        self.assertEqual(worker.expected(rows), expected)
        self.assertEqual(auditor.oracle(rows, profile), expected)

    def test_definition_cannot_select_code_or_paths(self):
        p = Path(__file__).parent / 'fresh_tasks/casefold-clear.definition.json'
        data = json.loads(p.read_bytes()); data['module'] = '/tmp/evil.py'
        with tempfile.TemporaryDirectory() as tmp:
            q = Path(tmp) / 'task.json'; q.write_bytes(worker.encoded(data))
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                worker.configure_development_task(q, worker.digest(q.read_bytes()))
        self.assertIsNone(worker.DEVELOPMENT_TASK)


class FunctionalOracleControls(unittest.TestCase):
    def test_independent_algorithms_match_frozen_valid_and_invalid_cases(self):
        from development_task_oracles import expected
        for kind in ['interval-union', 'dependency-order', 'unicode-runs']:
            p = Path(__file__).parent / 'fresh_tasks' / (kind + '.definition.json')
            d = json.loads(p.read_bytes())
            for value in d['acceptance_inputs']:
                with self.subTest(kind=kind, value=value):
                    self.assertEqual(expected(kind, value), auditor.functional_oracle(kind, value))

    def test_fixed_counterexamples_not_just_oracle_agreement(self):
        from development_task_oracles import expected
        for oracle in [expected, auditor.functional_oracle]:
            self.assertEqual(oracle('interval-union', [[0,2],[2,4]]), {'intervals':[[0,4]],'covered':4})
            self.assertIsNone(oracle('interval-union', [[True,2]]))
            self.assertEqual(oracle('dependency-order', {'nodes':['z','b','a'],'edges':[['a','z']]}), {'order':['a','b','z']})
            self.assertIsNone(oracle('dependency-order', {'nodes':['a'],'edges':[['a','a']]}))
            self.assertEqual(oracle('unicode-runs', 'aab'), {'runs':[{'text':'a','count':2},{'text':'b','count':1}],'length':3})
            self.assertIsNone(oracle('unicode-runs', False))

if __name__ == '__main__':
    unittest.main()
