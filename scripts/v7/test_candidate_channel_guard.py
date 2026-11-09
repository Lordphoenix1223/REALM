"""Real Linux syscall and descendant controls; no publication authority."""
import json
import pathlib
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

import coding_worker as worker

SCRIPTS = pathlib.Path(__file__).resolve().parent
LINUX_X86 = (platform.system(), platform.machine()) == ('Linux', 'x86_64')
PROBE = r"""
import ctypes, errno, json, os, socket
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
rows = {}
for name, nr, args in [('vsock', 41, [40, 1, 0]),
                       ('vsock_pair', 53, [40, 1, 0, 0]),
                       ('uring_setup', 425, [0, 0]),
                       ('uring_enter', 426, [-1, 0, 0, 0, 0, 0]),
                       ('uring_register', 427, [-1, 0, 0, 0])]:
    ctypes.set_errno(0)
    result = libc.syscall(nr, *args)
    rows[name] = {'result': result, 'errno': ctypes.get_errno()}
    assert result == -1 and ctypes.get_errno() == errno.EPERM, rows
# Ordinary syscalls with first argument 40 must not accidentally hit AF_VSOCK.
assert libc.syscall(102, 40) == os.getuid()
a, b = socket.socketpair()
a.close(); b.close()
status = open('/proc/self/status').read()
assert 'NoNewPrivs:\t1' in status and 'Seccomp:\t2' in status
print(json.dumps({'denials': rows, 'status': status}), flush=True)
"""


@unittest.skipUnless(LINUX_X86, 'actual Linux x86_64 kernel required')
class KernelControls(unittest.TestCase):
    def guarded(self, code):
        setup = 'import sys;sys.path.insert(0,' + repr(str(SCRIPTS)) + ');import candidate_channel_guard as g;g.install();'
        return subprocess.run([sys.executable, '-I', '-B', '-c', setup + code],
                              capture_output=True, timeout=10)

    def test_actual_denials_survive_exec_and_fork(self):
        # Install only in the child, then exec a fresh interpreter which forks.
        code = 'import os;os.execv(' + repr(sys.executable) + ',[' + repr(sys.executable) + ",'-I','-B','-c'," + repr('import os;pid=os.fork();\nif pid: _,s=os.waitpid(pid,0); assert s==0\nelse:\n' + '\n'.join('    ' + line for line in PROBE.splitlines()) + '\n    os._exit(0)') + '])'
        result = self.guarded(code)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        print('FORK_EXEC_KERNEL_OBSERVATION ' + result.stdout.decode().strip())
        rows = json.loads(result.stdout)['denials']
        self.assertEqual(len(rows), 5)

    def test_x32_and_foreign_abi_are_killed(self):
        result = self.guarded('import ctypes;ctypes.CDLL(None).syscall(0x40000027)')
        self.assertEqual(result.returncode, -signal.SIGSYS)
        # Actual i386 int80 on x86_64 tests the audit-architecture branch.
        result = self.guarded("import mmap,ctypes;m=mmap.mmap(-1,4096,prot=7);m.write(bytes.fromhex('b814000000cd80c3'));ctypes.CFUNCTYPE(ctypes.c_int)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()")
        self.assertEqual(result.returncode, -signal.SIGSYS)

    def test_real_candidate_launcher_closes_inherited_fd_and_hides_devices(self):
        with tempfile.TemporaryDirectory(prefix='realm-channel-control-') as temp:
            candidate = pathlib.Path(temp)
            sandbox = worker.Sandbox(candidate, evidence_channel_guard=True)
            # Trusted controller keeps its socket; deliberately inheritable FD
            # must not reach the candidate. No kernel VSOCK privilege required.
            a, b = socket.socketpair()
            try:
                a.set_inheritable(True)
                code = PROBE + '\nimport os\n' + \
                    'assert not os.path.exists("/dev/vsock")\n' + \
                    'assert not os.path.exists("/dev/kvm")\n' + \
                    'links=[os.readlink("/proc/self/fd/"+n) for n in os.listdir("/proc/self/fd") if os.path.exists("/proc/self/fd/"+n)]\n' + \
                    'assert not any(x.startswith("socket:") for x in links), links\n'
                code, out, err = sandbox.execute(code, b'')
                self.assertEqual(code, 0, err.decode())
                print('CANDIDATE_KERNEL_OBSERVATION ' + out.decode().strip())
                self.assertEqual(len(json.loads(out)['denials']), 5)
                a.sendall(b'controller survives')
                self.assertEqual(b.recv(100), b'controller survives')
            finally:
                a.close(); b.close()


if __name__ == '__main__':
    unittest.main()
