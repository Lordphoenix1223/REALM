"""Test the bundled path with an actual checker and no Cargo in PATH."""
import hashlib,json,os,platform,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class LauncherTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);shutil.copy2(ROOT/'realm',self.root/'realm');(self.root/'bin').mkdir();self.binary=self.root/'bin/realm-artifact';shutil.copy2(os.environ['REALM_CHECKER'],self.binary)
  self.pin={'schema':'realm.preview-binary.v1','system':platform.system(),'machine':platform.machine(),'binary_sha256':hashlib.sha256(self.binary.read_bytes()).hexdigest()};self.save()
 def tearDown(self):self.temp.cleanup()
 def save(self):(self.root/'BINARY_MANIFEST.json').write_text(json.dumps(self.pin))
 def run_launcher(self,*args,force=False):
  env=dict(os.environ,PATH='',REALM_BUILD_FROM_SOURCE='1' if force else '0')
  return subprocess.run([sys.executable,str(self.root/'realm'),*args],cwd=self.root,env=env,capture_output=True,timeout=10)
 def test_demo_without_cargo_or_private_worktree(self):
  result=self.run_launcher('demo');self.assertEqual(result.returncode,0,result.stderr)
  report=json.loads((self.root/'realm-demo/report.json').read_text());self.assertEqual(report['execution_authority'],'NONE');self.assertEqual(len(report['cases']),3)
 def test_help_needs_no_cargo_or_executable(self):
  self.binary.unlink();result=self.run_launcher('--help');self.assertEqual(result.returncode,0,result.stderr);self.assertIn(b'./realm example',result.stdout)
 def test_checksum_mismatch_refuses_before_execution(self):
  self.pin['binary_sha256']='0'*64;self.save();result=self.run_launcher('version');self.assertNotEqual(result.returncode,0);self.assertIn(b'checksum mismatch',result.stderr);self.assertEqual(result.stdout,b'')
 def test_wrong_platform_refuses_before_execution(self):
  self.pin['machine']='unsupported';self.save();result=self.run_launcher('version');self.assertNotEqual(result.returncode,0);self.assertIn(b'different platform',result.stderr)
 def test_forced_source_build_explains_missing_cargo(self):
  result=self.run_launcher('version',force=True);self.assertNotEqual(result.returncode,0);self.assertIn(b'Rust/Cargo',result.stderr)
if __name__=='__main__':unittest.main()
