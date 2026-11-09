"""Actual process counterexample: syscall denial is not complete observation."""
import json
import os
from pathlib import Path
import platform
import subprocess
import unittest


@unittest.skipUnless(platform.system() == 'Linux', 'actual Linux kernel required')
class NativeObservationCanary(unittest.TestCase):
    def test_direct_counter_and_actual_vdso_mapping_are_not_inferred_from_boot_text(self):
        binary = Path(os.environ.get('CARGO_TARGET_DIR', 'target')) / 'debug/coding_controller'
        out = subprocess.run([str(binary.resolve()), '--runtime-probe'], input=b'', capture_output=True, timeout=10)
        self.assertEqual(out.returncode, 0, out.stderr)
        result = json.loads(out.stdout)
        self.assertEqual(result['syscall_clock'], {'return':-1,'errno':1})
        self.assertEqual(result['authority'], 'NONE')
        self.assertEqual(result['complete_observation_admission'], 'REFUSE')
        absent = result['auxiliary_vdso'] == 0 and not result['runtime_mappings']
        self.assertEqual(result['vdso_absent_observed'], absent)
        self.assertTrue(result['direct_instructions'])
        # Presence and absence are actual observations. Do not assert that a
        # vdso=0 command-line string implies either one, or a qualified profile.
        if result['libc_clock']['return'] == 0:
            self.assertIsNone(result['libc_clock']['errno'])
        else:
            self.assertEqual(result['libc_clock']['errno'], 1)
