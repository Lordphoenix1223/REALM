"""Real Linux mapping effects; parent reopens the object independently of JSON."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest


@unittest.skipUnless(platform.system() == 'Linux' and os.environ.get('REALM_MAPPING_PROBE_BINARY'),
                     'requires the actual Linux controller_mapping_probe binary')
class ControllerMappingTests(unittest.TestCase):
    def test_shared_mapping_refuses_while_private_and_unmapped_controls_work(self):
        binary = Path(os.environ['REALM_MAPPING_PROBE_BINARY'])
        captures = []
        with tempfile.TemporaryDirectory(prefix='realm-mapping-') as name:
            for mode in ('none', 'private', 'shared'):
                fixture = Path(name) / mode
                child = subprocess.run([str(binary), mode, str(fixture)], input=b'',
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=10)
                # Reopen after process exit: no inherited mapping or child claim
                # decides the parent-observed effect. This is visibility, not
                # a crash-durability qualification.
                physical = fixture.read_bytes()
                captures.append(dict(mode=mode, exit=child.returncode,
                                     stdout_hex=child.stdout.hex(), stderr_hex=child.stderr.hex(),
                                     actual_first_byte_hex=physical[:1].hex(),
                                     fixture_sha256=hashlib.sha256(physical).hexdigest()))
        output = os.environ.get('REALM_MAPPING_CAPTURE')
        if output:
            with Path(output).open('x') as stream:
                json.dump(dict(authority='NONE', qualification='REFUSE',
                               kernel=platform.release(), architecture=platform.machine(),
                               binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                               test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                               captures=captures), stream, indent=2)
        # Retain every real observation before making assertions, including a
        # red run against the previous guard. No baseline failure is relabeled.
        for row in captures:
            self.assertEqual(row['exit'], 0, row)
            result = json.loads(bytes.fromhex(row['stdout_hex']))
            self.assertEqual(result['authority'], 'NONE')
            self.assertEqual(result['complete_observation_admission'], 'REFUSE')
            self.assertEqual(row['actual_first_byte_hex'], '41', row)
            if row['mode'] == 'shared':
                self.assertFalse(result['guard_installed'], row)
                self.assertIn('writable shared mapping', result['error'])
            else:
                self.assertTrue(result['guard_installed'], row)
                self.assertEqual(result['write_return'], -1)
                self.assertEqual(result['write_errno'], 1)


if __name__ == '__main__':
    unittest.main()
