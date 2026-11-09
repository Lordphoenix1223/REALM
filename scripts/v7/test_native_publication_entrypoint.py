"""Actual CLI refusal tests. These create no native owners or qualification."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class NativePublicationEntrypointTests(unittest.TestCase):
    def test_unqualified_runtime_refuses_before_paths_or_vm_start(self):
        binary = Path(os.environ.get('REALM_BINARY', 'target/debug/realm')).resolve()
        self.assertTrue(binary.is_file(), 'build the actual realm CLI before this test')
        with tempfile.TemporaryDirectory(prefix='realm-native-publication-') as temporary:
            root = Path(temporary)
            absent = [root / name for name in ('world', 'evidence', 'trust.json', 'state')]
            command = [str(binary), 'task', 'run-coding-native',
                       *map(str, absent[:3]), '--native-referee-launch', str(absent[3]),
                       'a' * 64, 'b' * 64, str(root / 'custodian'), '996', '980', '9',
                       str(root / 'python')]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('REFUSE_UNVERIFIED_BOUNDARY', result.stderr)
            self.assertEqual(list(root.iterdir()), [])
            self.assertNotIn('BINDING', result.stdout)
            self.assertNotIn('CHECKED_FOR_PUBLICATION', result.stdout)


if __name__ == '__main__':
    unittest.main()
