"""Controlled host-admission fixtures, NOT genuine hosted capability evidence."""
import ctypes
import errno
import unittest
from unittest import mock
import official_host_preflight as host


class HostAdmission(unittest.TestCase):
    def test_only_explicit_images(self):
        for image in host.IMAGES:
            host.identity(image, host.KERNEL, 'Linux', 'x86_64', host.PYTHON_SHA256)
        for image in ('', 'UNKNOWN', '20261108.1', host.IMAGES[1] + '\n'):
            with self.assertRaisesRegex(ValueError, 'unreviewed image'):
                host.identity(image, host.KERNEL, 'Linux', 'x86_64', host.PYTHON_SHA256)

    def test_each_identity_binding_refuses(self):
        valid = [host.IMAGES[1], host.KERNEL, 'Linux', 'x86_64', host.PYTHON_SHA256]
        for index, wrong in ((1, '7.0.0-other'), (2, 'Darwin'), (3, 'aarch64'), (4, '0' * 64)):
            args = valid.copy(); args[index] = wrong
            with self.assertRaises(ValueError):
                host.identity(*args)

    def test_mismatch_precedes_kernel_and_process_effects(self):
        with mock.patch.object(host, 'digest', return_value=host.PYTHON_SHA256), \
             mock.patch.object(host.platform, 'release', return_value=host.KERNEL), \
             mock.patch.object(host.platform, 'system', return_value='Linux'), \
             mock.patch.object(host.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(host.os, 'geteuid', side_effect=AssertionError('effect reached')), \
             mock.patch.object(host, 'stopped_child_probe', side_effect=AssertionError('child reached')):
            with self.assertRaisesRegex(ValueError, 'unreviewed image'):
                host.run('arbitrary')

    def test_denied_syscall_preserves_errno(self):
        libc = mock.Mock()
        def denied(*args):
            ctypes.set_errno(errno.EPERM)
            return -1
        libc.syscall.side_effect = denied
        with self.assertRaises(OSError) as caught:
            host.syscall(libc, 444, None, 0, 1)
        self.assertEqual(caught.exception.errno, errno.EPERM)

    def test_wrong_python_cannot_reach_capabilities(self):
        with mock.patch.object(host, 'digest', return_value='bad'), \
             mock.patch.object(host.platform, 'release', return_value=host.KERNEL), \
             mock.patch.object(host.platform, 'system', return_value='Linux'), \
             mock.patch.object(host.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(host.os, 'geteuid', side_effect=AssertionError('kernel reached')):
            with self.assertRaisesRegex(ValueError, 'Python'):
                host.run(host.IMAGES[1])

    def test_real_local_host_is_not_authorized(self):
        # Executes the actual entry function on this local machine. It must
        # refuse before privileged setup; no pretending fixtures are a host.
        if host.platform.system() == 'Linux' and host.platform.machine() == 'x86_64':
            self.skipTest('local x86 may match: use explicitly wrong image instead')
        with self.assertRaises((ValueError, FileNotFoundError)):
            host.run(host.IMAGES[1])


class ControlledChildCustody(unittest.TestCase):
    """TEST_ONLY syscall fixtures exercise refusal/cleanup, not Linux success."""
    def exercise(self, *, missing_stop=False, wrong_terminal=False, denied_fd=False):
        from contextlib import ExitStack
        from types import SimpleNamespace
        stopped = SimpleNamespace(si_pid=123, si_code=4)
        terminal = mock.Mock(si_pid=123, si_code=2, si_status=9)
        terminal.__iter__ = mock.Mock(return_value=iter([123, 0, 9, 0, 2]))
        if missing_stop:
            stopped.si_code = 1
        if wrong_terminal:
            terminal.si_pid = 999
        libc = mock.Mock()
        libc.ptrace.return_value = 0
        with ExitStack() as stack:
            def patch(target, name, **kwargs):
                return stack.enter_context(mock.patch.object(target, name, create=True, **kwargs))
            patch(host.ctypes, 'CDLL', return_value=libc)
            patch(host.os, 'open', return_value=10)
            patch(host.os, 'pipe', return_value=(11, 12))
            patch(host.os, 'close')
            patch(host.os, 'fork', return_value=123)
            patch(host.os, 'pidfd_open', return_value=13)
            patch(host.os, 'P_PIDFD', new=3)
            patch(host.os, 'CLD_TRAPPED', new=4)
            patch(host.os, 'CLD_KILLED', new=2)
            patch(host.os, 'waitid', side_effect=[stopped, terminal, ChildProcessError()])
            patch(host.os, 'read', return_value=b'{"before":{},"after":{}}')
            patch(host.select, 'select', return_value=([13], [], []))
            kill = patch(host.signal, 'pidfd_send_signal')
            patch(host, 'syscall', side_effect=OSError(errno.EPERM, 'TEST_ONLY') if denied_fd else [14, 0])
            if missing_stop or wrong_terminal or denied_fd:
                with self.assertRaises((ValueError, OSError)):
                    host.stopped_child_probe()
            else:
                self.assertTrue(host.stopped_child_probe()['reaped'])
            self.assertTrue(kill.called)
            for call in libc.ptrace.call_args_list:
                self.assertEqual(call.args[0], 0x4200)  # EXITKILL only, never CONT/DETACH

    def test_original_stop_and_reap_contract(self):
        self.exercise()

    def test_missing_stop_aborts_and_kills_original(self):
        self.exercise(missing_stop=True)

    def test_substituted_terminal_aborts(self):
        self.exercise(wrong_terminal=True)

    def test_cross_process_fd_denial_aborts(self):
        self.exercise(denied_fd=True)

    def test_cross_uid_termination_requires_existing_cap_kill_before_probes(self):
        # TEST_ONLY proc-status fixture. Reproduce the reduced-capability local
        # harness failure without launching a child or changing any capability.
        caps = sum(1 << bit for bit in host.REQUIRED_CAPS if bit != 5)
        with mock.patch.object(host, 'identity'), mock.patch.object(host, 'digest'), \
             mock.patch.object(host.os, 'geteuid', return_value=0), \
             mock.patch.object(host.Path, 'read_text', return_value=f'CapEff:\t{caps:x}\n'), \
             mock.patch.object(host, 'stopped_child_probe', side_effect=AssertionError('child reached')):
            with self.assertRaisesRegex(ValueError, 'capabilities absent'):
                host.run(host.IMAGES[1])


if __name__ == '__main__':
    unittest.main()
