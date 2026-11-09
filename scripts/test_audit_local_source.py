import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('local_audit', Path(__file__).with_name('audit_local_source.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class LocalAuditTests(unittest.TestCase):
    def test_real_modified_untracked_ignored_renamed_and_deleted_files(self):
        with tempfile.TemporaryDirectory() as directory:
            r = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=r, stderr=subprocess.DEVNULL)
            git('init', '-q')
            git('config', 'user.name', 'Test Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (r/'.gitignore').write_text('ignored/\n')
            for name in ['edited.py', 'renamed.py', 'deleted.py']:
                (r/name).write_text('baseline\n')
            git('add', '.gitignore', 'edited.py', 'renamed.py', 'deleted.py')
            git('commit', '-qm', 'test: local audit baseline')
            (r/'edited.py').write_text('changed content never printed\n')
            git('mv', 'renamed.py', 'new-name.py')
            (r/'deleted.py').unlink()
            (r/'new.py').write_text('untracked\n')
            (r/'ignored').mkdir()
            (r/'ignored/valuable.py').write_text('ignored source\n')
            result = audit.inspect(r)
            files = {x['path']:x for x in result['files']}
            self.assertEqual(files['ignored/valuable.py']['state'], 'ignored_source')
            self.assertEqual(files['new.py']['state'], 'untracked')
            self.assertEqual(files['deleted.py']['state'], 'deleted')
            self.assertEqual(files['renamed.py']['state'], 'deleted')
            self.assertIn('new-name.py', files)
            self.assertEqual(len(files['edited.py']['sha256']), 64)
            self.assertNotIn('changed content', str(result))
            self.assertTrue(result['uncommitted_changes'])

    def test_symlink_is_hashed_without_reading_its_target(self):
        with tempfile.TemporaryDirectory() as directory:
            r = Path(directory)
            for args in [('init','-q'), ('config','user.name','Test Fixture'),
                         ('config','user.email','fixture@example.invalid'),
                         ('commit','--allow-empty','-qm','test: empty')]:
                subprocess.run(['git',*args],cwd=r,check=True,capture_output=True)
            (r/'unreadable.py').symlink_to('/nonexistent/private-target')
            row = audit.inspect(r)['files'][0]
            self.assertEqual(row['kind'],'symlink')
            self.assertEqual(len(row['sha256']),64)
