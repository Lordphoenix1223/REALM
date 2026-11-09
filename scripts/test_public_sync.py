"""Security boundaries of reviewed export, using isolated actual Git repositories."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('sync', Path(__file__).with_name('public_sync.py'))
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class ExportBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'private'
        self.public = Path(self.tmp.name) / 'public'
        for root in (self.root, self.public):
            root.mkdir()
            self.git(root, 'init', '-q')
            self.git(root, 'config', 'user.name', 'Test Fixture')
            self.git(root, 'config', 'user.email', 'fixture@example.invalid')
        (self.root / 'crates').mkdir()
        (self.root / 'crates/a.rs').write_text('// reviewed\n')
        self.commit()
        self.rev = self.git(self.root, 'rev-parse', 'HEAD')
        self.m = {'schema':'realm.reviewed-public-export/v1', 'review_basis':'test only',
                  'source_commit':self.rev, 'shared_prefixes':['crates/'], 'excluded_files':{},
                  'files':{'crates/a.rs':hashlib.sha256(b'// reviewed\n').hexdigest()}}
        self.git(self.public, 'remote', 'add', 'origin', sync.PUBLIC)

    def git(self, root, *args):
        return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()

    def commit(self):
        self.git(self.root, 'add', 'crates')
        self.git(self.root, 'commit', '-qm', 'test: fixture')

    def test_unreviewed_changed_and_new_source_is_reported(self):
        (self.root / 'crates/a.rs').write_text('// changed\n')
        (self.root / 'crates/b.rs').write_text('// new\n')
        self.commit()
        r = sync.report(self.root, self.m, 'HEAD', None)
        self.assertEqual(r['unreviewed_changed_files'], ['crates/a.rs'])
        self.assertEqual(r['unreviewed_new_files'], ['crates/b.rs'])
        self.assertEqual(len(r['source_commits_since_review']), 1)

    def test_prepare_uses_committed_bytes_and_imports_no_history(self):
        (self.root / 'crates/a.rs').write_text('// dirty secret\n')
        sync.prepare(self.root, self.m, self.public)
        self.assertEqual((self.public / 'crates/a.rs').read_bytes(), b'// reviewed\n')
        self.assertFalse((self.public / '.git/objects' / self.rev[:2] / self.rev[2:]).exists())

    def test_traversal_restricted_and_symlink_sources_refuse(self):
        for name in ('../secret', '/tmp/secret', 'evidence/raw.log', '.env', 'a/../b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                sync.validate_path(name)
        (self.root / 'crates/link').symlink_to('a.rs')
        self.commit()
        with self.assertRaises(ValueError):
            sync.blob(self.root, 'HEAD', 'crates/link')

    def test_destination_symlink_refuses_before_any_write(self):
        (self.public / 'crates').symlink_to(self.root / 'crates')
        self.git(self.public, 'add', 'crates')
        self.git(self.public, 'commit', '-qm', 'test: symlink')
        with self.assertRaises(ValueError):
            sync.prepare(self.root, self.m, self.public)
        self.assertFalse((self.public / 'SOURCE_MANIFEST.json').exists())

    def test_credential_marker_refuses_without_printing_value(self):
        (self.root / 'crates/a.rs').write_text('ghp_' + 'X'*40)
        self.commit()
        with self.assertRaisesRegex(ValueError, '^credential marker requires review: crates/a.rs$'):
            sync.blob(self.root, 'HEAD', 'crates/a.rs')

    def test_tampered_source_pin_refuses(self):
        self.m['files']['crates/a.rs'] = '0'*64
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps(self.m))
        with self.assertRaises(ValueError):
            sync.load(self.root, manifest)

    def test_wrong_public_remote_refuses(self):
        self.git(self.public, 'remote', 'set-url', 'origin', 'https://example.invalid/private')
        with self.assertRaises(ValueError):
            sync.prepare(self.root, self.m, self.public)

    def test_hardlinked_destination_does_not_change_outside_file(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.write_bytes(b'protected')
        (self.public / 'crates').mkdir()
        import os
        os.link(outside, self.public / 'crates/a.rs')
        self.git(self.public, 'add', 'crates')
        self.git(self.public, 'commit', '-qm', 'test: linked destination')
        sync.prepare(self.root, self.m, self.public)
        self.assertEqual(outside.read_bytes(), b'protected')
        self.assertEqual((self.public / 'crates/a.rs').read_bytes(), b'// reviewed\n')

    def test_manual_publish_reaches_draft_pr_with_actual_source_checker(self):
        # Real local commit/push, actual source checker, and a test-only gh
        # transport. No GitHub account, network, credential or authority is used.
        from unittest.mock import patch
        import os
        tools = self.public / 'tools'
        tools.mkdir()
        (tools / 'check_release.py').write_text("from pathlib import Path\nPath('EXPORT_MANIFEST.json').write_text('{}\\n')\nprint('TEST_ONLY release fixture')\n")
        scripts = self.public / 'scripts'
        scripts.mkdir()
        source_checker = Path(__file__).with_name('check_source_manifest.py')
        (scripts / source_checker.name).write_bytes(source_checker.read_bytes())
        self.git(self.public, 'add', 'tools', 'scripts')
        self.git(self.public, 'commit', '-qm', 'test: public base')
        self.git(self.public, 'branch', '-M', 'main')
        remote = Path(self.tmp.name) / 'remote.git'
        self.git(self.public, 'init', '--bare', str(remote))
        self.git(self.public, 'remote', 'set-url', 'origin', str(remote))
        self.git(self.public, 'push', '-u', 'origin', 'main')
        validation = self.root / 'validation.json'
        validation.write_text(json.dumps({'source_commit':self.rev, 'status':'PASS'}))
        bin_dir = Path(self.tmp.name) / 'bin'
        bin_dir.mkdir()
        gh = bin_dir / 'gh'
        gh.write_text('#!/bin/sh\nif test "$2" = list; then echo "[]"; else echo "https://example.invalid/test-only-pr"; fi\n')
        gh.chmod(0o755)
        with patch.object(sync, 'PUBLIC', str(remote)), patch.dict(os.environ, {'PATH':str(bin_dir)+os.pathsep+os.environ['PATH']}):
            sync.publish(self.root, self.m, self.public, 'codex/sync-test', 'main', validation)
        self.assertEqual(self.git(self.public, 'status', '--porcelain'), '')
        actual = self.git(self.public, 'show', 'origin/codex/sync-test:crates/a.rs')
        self.assertEqual(actual, '// reviewed')


if __name__ == '__main__':
    unittest.main()
