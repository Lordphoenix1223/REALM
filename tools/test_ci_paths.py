import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('ci_paths', Path(__file__).with_name('ci_paths.py'))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class TriggerCoverageTests(unittest.TestCase):
    def test_rust_python_contract_and_workflow_changes_get_runtime_lanes(self):
        for name in ['crates/realm-v6/src/coding_fence.rs', 'scripts/v7/vm_session.py',
                     'scripts/v7/new_controller.py', 'schemas/task.schema.json',
                     'contracts/runtime.json', 'docs/v6/INTEGRATION_LAB_PROFILE_V1.json',
                     '.github/workflows/native.yml', 'integrations/python/realm_v7.py']:
            with self.subTest(path=name):
                self.assertTrue(ci.classify([name])['native'])
                self.assertTrue(ci.classify([name])['v7'])

    def test_doc_only_and_sync_only_changes_keep_security_without_native_build(self):
        for name in ['README.md', 'docs/RAY_TED_QUICKSTART.md', 'CHANGELOG.md',
                     'scripts/public_sync.py', 'scripts/check_source_manifest.py',
                     'scripts/audit_local_source.py', 'SOURCE_MANIFEST.json', 'EXPORT_MANIFEST.json']:
            with self.subTest(path=name):
                result = ci.classify([name])
                self.assertFalse(result['native'])
                self.assertFalse(result['v7'])
                self.assertTrue(result['security_and_manifests'])

    def test_real_git_deletions_and_renames_cannot_hide_old_runtime_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            r = Path(directory)
            def git(*args):
                return subprocess.check_output(['git',*args],cwd=r,stderr=subprocess.DEVNULL).decode().strip()
            git('init','-q'); git('config','user.name','Test Fixture')
            git('config','user.email','fixture@example.invalid')
            (r/'scripts/v7').mkdir(parents=True)
            (r/'scripts/v7/owner.py').write_text('# synthetic\n')
            git('add','scripts'); git('commit','-qm','test: source baseline')
            base = git('rev-parse','HEAD')
            git('mv','scripts/v7/owner.py','README.md'); git('commit','-qm','test: renamed source')
            paths = ci.changed(r,base,'HEAD')
            self.assertIn('scripts/v7/owner.py',paths)
            self.assertTrue(ci.classify(paths)['native'])
            self.assertTrue(ci.classify(paths)['v7'])

    def test_workflow_always_emits_coverage_and_has_read_only_credentials(self):
        root = Path(__file__).resolve().parents[1]
        raw = (root/'.github/workflows/native.yml').read_text()
        self.assertNotIn('    paths:', raw)
        self.assertIn('name: Validation lane coverage', raw)
        self.assertIn('contents: read',raw)
        self.assertNotIn('pull_request_target',raw)
        self.assertNotIn('secrets.',raw)
        self.assertNotIn('--privileged',raw)
        self.assertNotIn('workflow_dispatch:',raw)
