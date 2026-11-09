"""Actual native ELF dispatch tests. No VMM, publication or qualification."""
import json
import os
import platform
from pathlib import Path
import subprocess
import unittest


@unittest.skipUnless(platform.system() == "Linux", "actual Linux internal relay required")
class InternalRelayEntrypoints(unittest.TestCase):
    def binaries(self):
        target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')) / 'debug'
        paths = [Path(os.environ.get(name, str(target / binary))) for name, binary in
                 (('REALM_BINARY', 'realm'), ('REALM_NATIVE_PROBE', 'coding_submission_probe'))]
        for path in paths:
            self.assertTrue(path.is_file(), 'build both actual Linux entrypoints')
        return paths

    def invoke(self, binary, arguments, data=b''):
        return subprocess.run([str(binary), *arguments], input=data, capture_output=True,
                              env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, timeout=5)

    def test_actual_cli_and_probe_internal_dispatch_is_bounded(self):
        binding = {key: char * 64 for key, char in zip(
            ('run_id','execution_id','challenge_root','task_sha256','worker_sha256'),'abcde')}
        frames = [{'binding':binding,'sequence':n,'request':{'tool':tool}}
                  for n,tool in enumerate(('list','finish'))]
        wire = b''.join(json.dumps(frame).encode() + b'\n' for frame in frames)
        for binary in self.binaries():
            with self.subTest(binary=binary):
                result = self.invoke(binary, ['--internal-coding-relay', json.dumps(binding)], wire)
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual([row['request'] for row in rows], [row['request'] for row in frames])
                self.assertEqual([row['binding'] for row in rows], [binding,binding])
                self.assertTrue(all(row['authority']=='NONE' and
                    row['complete_observation_admission']=='REFUSE' for row in rows))
                for arguments, raw in [
                    (['--internal-coding-relay'], b''),
                    (['--internal-coding-relay',json.dumps(binding),'extra'], b''),
                    (['--internal-coding-relay','{}'], b''),
                    (['--internal-coding-relay',json.dumps(binding)], b'{'),
                    (['--internal-coding-relay',json.dumps(binding)], b'{bad}\n'),
                    (['--internal-coding-relay-unknown'], b'')]:
                    refused = self.invoke(binary,arguments,raw)
                    self.assertNotEqual(refused.returncode,0)
                    self.assertNotIn(b'CHECKED_FOR_PUBLICATION',refused.stdout)
                    self.assertNotIn(b'BINDING',refused.stdout)

    def test_normal_artifact_inspection_keeps_existing_behavior(self):
        binary = self.binaries()[0]
        fixture = Path(__file__).resolve().parents[2] / 'evidence/receiver/20261015-lifecycle/demo/NON_AUTHORIZING.candidate.realm'
        result = self.invoke(binary,['artifact','inspect',str(fixture)])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'authority: external only',result.stdout)
        self.assertNotIn(b'CHECKED_FOR_PUBLICATION',result.stdout)


if __name__=='__main__':
    unittest.main()
