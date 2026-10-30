"""A source archive must be checkable, including with Python optimization enabled."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'source'; self.root.mkdir(); (self.root/'tools').mkdir()
        shutil.copy2(ROOT/'tools/check_release.py', self.root/'tools/check_release.py')
        for name in ['LICENSE-MIT', 'LICENSE-APACHE', 'NOTICE', 'RIGHTS.md']:
            (self.root/name).write_text('test fixture only\n')
        (self.root/'README.md').write_text('[rights](RIGHTS.md)\n')
        (self.root/'.gitignore').write_text('/target/\n__pycache__/\n*.pyc\n')
        (self.root/'THIRD_PARTY_INVENTORY.json').write_text('{"packages":[]}')
        (self.root/'EXPORT_MANIFEST.json').write_text('{}')
        self.assertEqual(self.run_check('--refresh').returncode, 0)

    def run_check(self, *args):
        return subprocess.run([sys.executable, '-I', '-O', '-B', str(self.root/'tools/check_release.py'), *args],
                              capture_output=True, timeout=5)

    def test_git_free_archive_and_generated_build_outputs(self):
        (self.root/'target').mkdir(); (self.root/'target/cache').write_bytes(b'not source')
        self.assertEqual(self.run_check().returncode, 0)

    def test_optimized_python_still_rejects_tampered_or_extra_files(self):
        (self.root/'README.md').write_text('tampered\n')
        self.assertNotEqual(self.run_check().returncode, 0)
        self.assertEqual(self.run_check('--refresh').returncode, 0)
        (self.root/'unexpected').write_text('extra')
        self.assertNotEqual(self.run_check().returncode, 0)

    def test_broken_symlink_and_nonregular_input_are_not_omitted(self):
        (self.root/'broken').symlink_to(self.root/'absent')
        self.assertNotEqual(self.run_check('--refresh').returncode, 0)
        (self.root/'broken').unlink()
        import os
        os.mkfifo(self.root/'pipe', 0o600)
        self.assertNotEqual(self.run_check('--refresh').returncode, 0)

    def test_refresh_does_not_replace_manifest_for_broken_docs(self):
        before = (self.root/'EXPORT_MANIFEST.json').read_bytes()
        (self.root/'README.md').write_text('[bad](missing.md)')
        self.assertNotEqual(self.run_check('--refresh').returncode, 0)
        self.assertEqual(before, (self.root/'EXPORT_MANIFEST.json').read_bytes())

    def test_derived_hash_refresh_preserves_original_provenance(self):
        origin = 'a'*64
        p = self.root/'PUBLIC_V02_PROVENANCE.json'
        p.write_text(json.dumps({'files':[{'public_file':'README.md','source_sha256':origin,'public_sha256':'b'*64}]}))
        self.assertNotEqual(self.run_check().returncode, 0)
        self.assertEqual(self.run_check('--refresh').returncode, 0)
        entry = json.loads(p.read_text())['files'][0]
        self.assertEqual(entry['source_sha256'], origin)
        self.assertEqual(entry['public_sha256'], hashlib.sha256((self.root/'README.md').read_bytes()).hexdigest())
        self.assertEqual(self.run_check().returncode, 0)
