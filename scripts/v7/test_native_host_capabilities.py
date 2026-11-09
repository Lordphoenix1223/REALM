"""Local result-contract controls; never execute kernel or cloud operations."""
import unittest
import hashlib
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

import native_host_capabilities as probe

from native_host_capabilities import classify


def events(name, status, error=0):
    return [{'event': 'capability_started', 'capability': name},
            {'event': 'capability_result', 'capability': name, 'status': status,
             'reason': 'TEST_ONLY result contract', 'errno': error}]


class CapabilityResults(unittest.TestCase):
    def test_unreached_capabilities_are_not_run(self):
        result = classify([], None)
        self.assertEqual(result['status'], 'NOT_RUN')
        self.assertEqual({v['status'] for v in result['capabilities'].values()}, {'NOT_RUN'})

    def test_permission_denial_is_failure_with_errno(self):
        result = classify(events('PIDFD_GETFD', 'FAIL', 1), 1)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['capabilities']['PIDFD_GETFD']['errno'], 1)
        self.assertEqual(result['capabilities']['KCMP']['status'], 'NOT_RUN')

    def test_absent_feature_is_unsupported(self):
        result = classify(events('KVM', 'UNSUPPORTED', 19), 1)
        self.assertEqual(result['status'], 'UNSUPPORTED')
        self.assertEqual(result['capabilities']['KVM']['status'], 'UNSUPPORTED')

    def test_dependency_failure_preserves_prior_pass(self):
        result = classify(events('NAMESPACES', 'PASS') + events('PIVOT_ROOT', 'FAIL', 1), 1)
        self.assertEqual(result['capabilities']['NAMESPACES']['status'], 'PASS')
        self.assertEqual(result['capabilities']['PIVOT_ROOT']['status'], 'FAIL')
        self.assertEqual(result['capabilities']['PRIVILEGE_DROP']['status'], 'NOT_RUN')

    def test_timeout_fails_active_stage_and_never_qualifies(self):
        rows = events('KVM', 'PASS') + [{'event': 'capability_started', 'capability': 'PIDFD_GETFD'}]
        result = classify(rows, None, timed_out=True)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['capabilities']['PIDFD_GETFD']['status'], 'FAIL')
        self.assertEqual(result['capabilities']['KCMP']['status'], 'NOT_RUN')
        self.assertEqual(result['qualification'], 'NOT_RUN')

    def test_signal_is_not_a_missing_pass(self):
        rows = [{'event': 'capability_started', 'capability': 'SECCOMP'},
                {'test': 'isolation', 'status': 'FAIL', 'raw_wait_status': 31}]
        result = classify(rows, 1)
        self.assertEqual(result['capabilities']['SECCOMP']['status'], 'FAIL')
        self.assertEqual(result['capabilities']['SECCOMP']['raw_wait_status'], 31)

    def test_both_closure_components_are_required(self):
        result = classify(events('PTRACE_CLOSURE', 'PASS'), 1)
        self.assertEqual(result['capabilities']['TERMINAL_CLOSURE']['status'], 'NOT_RUN')
        result = classify(events('PTRACE_CLOSURE', 'PASS') + events('CGROUP_CLOSURE', 'FAIL', 1), 1)
        self.assertEqual(result['capabilities']['TERMINAL_CLOSURE']['status'], 'FAIL')

    def test_terminal_labels_without_start_or_observation_refuse(self):
        result = classify([{'event': 'capability_result', 'capability': 'KVM', 'status': 'PASS'}], 0)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['capture_errors'])

    def test_timeout_before_kernel_start_is_recorded_by_main(self):
        """Exercise main's timeout route without executing even uname."""
        source = Path(probe.__file__).resolve()
        pin = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if str(path).endswith('/.git/HEAD'):
                return '1' * 40
            return original_read(path, *args, **kwargs)
        child = Mock(pid=12345, returncode=-9)
        child.poll.return_value = None
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'fresh'
            argv = ['probe', '--source-commit', '1' * 40, '--script-sha256', pin(source),
                    '--c-sha256', pin(source.with_suffix('.c')), '--output', str(out)]
            old_umask = os.umask(0o077)
            try:
                with patch('sys.argv', argv), patch.object(Path, 'read_text', read), \
                     patch.object(probe.os, 'geteuid', return_value=0), \
                     patch.object(probe.platform, 'system', return_value='Linux'), \
                     patch.object(probe.platform, 'machine', return_value='x86_64'), \
                     patch.object(probe.subprocess, 'Popen', return_value=child), \
                     patch.object(probe.time, 'monotonic', side_effect=[0, 10, 10]), \
                     patch.object(probe.os, 'killpg'):
                    self.assertEqual(probe.main(), 1)
                result = json.loads((out / 'RESULT.json').read_text())
                self.assertEqual(result['status'], 'FAIL')
                self.assertTrue(result['diagnostic_timed_out'])
                self.assertEqual({v['status'] for v in result['capabilities'].values()}, {'NOT_RUN'})
                self.assertEqual(result['qualification'], 'NOT_RUN')
            finally:
                os.umask(old_umask)


if __name__ == '__main__':
    unittest.main()
