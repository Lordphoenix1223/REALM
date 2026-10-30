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


class PromotionTests(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('realm_promotion', ROOT/'tools/promote.py')
        self.promotion = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.promotion)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_optimized_python_cannot_disable_private_path_guards(self):
        code = """import importlib.util,pathlib,sys
spec=importlib.util.spec_from_file_location('promotion',sys.argv[1]); p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
for name in ['../escape','/absolute','.GiT/config','.ENV.production']:
    try:p.safe_path(pathlib.Path(sys.argv[2]),name)
    except ValueError:pass
    else:raise SystemExit('unsafe path accepted: '+name)
try:p.require(False,'rights plan not approved')
except ValueError:pass
else:raise SystemExit('rights gate disabled')
"""
        r = subprocess.run([sys.executable,'-I','-O','-B','-c',code,str(ROOT/'tools/promote.py'),str(self.root)],capture_output=True,timeout=5)
        self.assertEqual(r.returncode,0,r.stderr)

    def test_only_frozen_approved_bytes_are_written(self):
        source = self.root/'source'; source.write_bytes(b'approved')
        raw,mode = self.promotion.selected_bytes(source)
        source.write_bytes(b'changed after approval')
        target = self.root/'target'; self.promotion.write_selected(target,raw,mode)
        self.assertEqual(target.read_bytes(),b'approved')

    def test_atomic_replacement_preserves_external_link_targets(self):
        import os
        outside = self.root/'outside'; outside.write_bytes(b'protected')
        for kind in ['symlink','hardlink']:
            target=self.root/kind
            if kind=='symlink':target.symlink_to(outside)
            else:os.link(outside,target)
            self.promotion.write_selected(target,b'approved',0o644)
            self.assertEqual(outside.read_bytes(),b'protected')
            self.assertFalse(target.is_symlink())
            self.assertEqual(target.read_bytes(),b'approved')

    def test_source_fifo_and_leaf_link_refuse_without_blocking(self):
        import os
        source=self.root/'source'; os.mkfifo(source,0o600)
        with self.assertRaises(ValueError):self.promotion.selected_bytes(source)
        source.unlink(); source.symlink_to(self.root/'missing')
        with self.assertRaises(OSError):self.promotion.selected_bytes(source)
