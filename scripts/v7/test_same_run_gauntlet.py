"""Permanent real-process observation-completeness regression; authority NONE."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from same_run_gauntlet import campaign


class SameRunGauntletTests(unittest.TestCase):
    def test_equal_journals_and_final_files_do_not_establish_complete_histories(self):
        realm = Path(os.environ.get('REALM_GAUNTLET_BINARY', str(Path(__file__).resolve().parents[2] / 'target/debug/realm')))
        self.assertTrue(realm.is_file(), 'build the actual realm CLI before running the gauntlet')
        with TemporaryDirectory(prefix='realm-same-run-gauntlet-') as tmp:
            root = Path(tmp).resolve() / 'retained-during-test'
            report = campaign(root, realm)
            self.assertEqual(report['authority'], 'NONE')
            self.assertIsNone(report['production_artifact'])
            self.assertTrue(report['byte_identical_recorded_journals'])
            self.assertTrue(report['identical_final_files'])
            self.assertEqual({r['next_decision'] for r in report['histories']}, {'publish', 'refuse'})
            self.assertEqual(len(report['negative_controls']), 7)
            for row in report['negative_controls']:
                self.assertEqual(row['status'], 'REFUSE')
            a, b = (json.loads((root / name / 'outside-journal-witness.json').read_bytes()) for name in ['history-a', 'history-b'])
            for key in ['inherited_fd_input', 'unrecorded_positive_read', 'unrecorded_alias_read',
                        'unrecorded_negative_read', 'external_planner_configuration', 'decision_relevant_next_action']:
                self.assertNotEqual(a[key], b[key], key)
            for row in report['histories']:
                admission = json.loads((root / (row['history'] + '.admission.stdout')).read_bytes())
                self.assertEqual(admission['admission'], 'REFUSE')
                self.assertEqual(admission['authority'], 'NONE')
                self.assertEqual(sum(check['status'] == 'MISSING' for check in admission['checks']), 6)
                self.assertNotEqual(row['admission_exit'], 0)


if __name__ == '__main__':
    unittest.main()
