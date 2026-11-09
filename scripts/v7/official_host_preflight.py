#!/usr/bin/python3
"""Bounded host admission for the frozen pre-VMM diagnostic; never authority.

No downloads, compiler, VM creation, mounts, accounts or host policy changes.
A disposable, pidfd-owned child tests changed-host syscall permissions. Actual
isolation and terminal custody still have to pass the unchanged native test.
"""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import stat
import subprocess
import time

IMAGES = ('20261025.353.1', '20261101.360.1')
KERNEL = '7.0.0-1017-azure'
PYTHON_SHA256 = 'e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f'
TOOLS = ('/usr/bin/cc', '/usr/bin/readelf', '/usr/sbin/debugfs', '/usr/bin/curl',
         '/usr/bin/sha256sum', '/usr/bin/timeout', '/usr/bin/ld')
REQUIRED_CAPS = (0, 1, 5, 6, 7, 8, 18, 19, 21, 27)  # DAC, identity, chroot, ptrace, admin, mknod


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(image, kernel, system, machine, python_pin):
    require(image in IMAGES, 'unreviewed image')
    require((system, machine, kernel) == ('Linux', 'x86_64', KERNEL), 'host/kernel mismatch')
    require(python_pin == PYTHON_SHA256, 'unreviewed system Python')


def syscall(libc, number, *args):
    ctypes.set_errno(0)
    value = libc.syscall(ctypes.c_long(number), *args)
    if value < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return value


def stopped_child_probe():
    """One fork, no grandchildren/exec; immutable original pidfd, bounded reap.

    All namespace changes are confined to this child. No mounts, devices, VM,
    external connectivity or payload. An alarm is armed before the child does
    work. Parent-side pidfd deadline handles SIGSTOP (which blocks the alarm).
    """
    libc = ctypes.CDLL(None, use_errno=True)
    held = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(read)
            signal.alarm(2)
            names = ('mnt', 'net', 'ipc')
            before = {n: os.stat('/proc/self/ns/' + n).st_ino for n in names}
            # Only this disposable child enters new namespaces; no PID1 fork.
            # v7.0 pid_for_children may be ENOENT until a first child exists.
            # NEWPID unshare success is checked; actual PID1 is native-owned.
            require(libc.unshare(0x00020000 | 0x40000000 | 0x08000000 | 0x20000000) == 0,
                    'unshare required namespaces denied')
            after = {n: os.stat('/proc/self/ns/' + n).st_ino for n in names}
            require(all(before[n] != after[n] for n in names), 'namespace readback differs')
            # Prove enforcement in this disposable process, not from uname.
            require(libc.prctl(38, 1, 0, 0, 0) == 0, 'no_new_privs denied')
            rights = ctypes.c_uint64(1 << 2)  # LANDLOCK_ACCESS_FS_READ_FILE
            rules = syscall(libc, 444, ctypes.byref(rights), ctypes.sizeof(rights), 0)
            try:
                syscall(libc, 446, rules, 0)  # empty allowlist denies new reads
            finally:
                os.close(rules)
            try:
                os.open('/etc/os-release', os.O_RDONLY)
            except OSError as error:
                require(error.errno == errno.EACCES, 'Landlock wrong denial')
            else:
                raise ValueError('Landlock did not enforce read denial')
            class Filter(ctypes.Structure):
                _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                            ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
            class Program(ctypes.Structure):
                _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
            code = (Filter * 4)(Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, 110),
                                Filter(0x06, 0, 0, 0x00050000 | errno.EPERM),
                                Filter(0x06, 0, 0, 0x7fff0000))
            program = Program(4, code)
            syscall(libc, 317, 1, 0, ctypes.byref(program))
            try:
                syscall(libc, 110)  # getppid, no side effects
            except OSError as error:
                require(error.errno == errno.EPERM, 'seccomp wrong denial')
            else:
                raise ValueError('seccomp did not enforce syscall denial')
            require(libc.ptrace(0, 0, None, None) == 0, 'TRACEME denied')
            os.write(write, json.dumps({'before': before, 'after': after,
                     'landlock_read_denied': True, 'seccomp_getppid_denied': True,
                     'newpid_unshare': True, 'pid1_observation': 'DEFERRED_TO_NATIVE'}).encode())
            os.kill(os.getpid(), signal.SIGSTOP)
            os._exit(71)  # Parent never continues this child.
        except BaseException as error:
            os.write(write, json.dumps({'error': str(error), 'errno': getattr(error, 'errno', None)}).encode())
            os._exit(72)
    os.close(write)
    pidfd = None
    try:
        pidfd = os.pidfd_open(child)
        deadline = time.monotonic() + 3
        stopped = None
        while time.monotonic() < deadline:
            stopped = os.waitid(os.P_PIDFD, pidfd, os.WSTOPPED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if stopped is not None:
                break
            time.sleep(0.002)
        require(stopped is not None and stopped.si_pid == child and stopped.si_code == os.CLD_TRAPPED,
                'original ptrace stop missing')
        # EXITKILL before cross-process inspection. Never CONT or DETACH.
        require(libc.ptrace(0x4200, child, None, ctypes.c_void_p(0x00100000)) == 0,
                'PTRACE_O_EXITKILL denied')
        duplicate = syscall(libc, 438, pidfd, held, 0)  # pidfd_getfd
        try:
            require(syscall(libc, 312, os.getpid(), child, 0, duplicate, held) == 0,
                    'kcmp original open description mismatch')
        finally:
            os.close(duplicate)
        raw = os.read(read, 4096)
        require(raw, 'namespace evidence missing')
        observed = json.loads(raw)
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        require(select.select([pidfd], [], [], 2)[0], 'capability child reap timeout')
        terminal = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
        require(terminal.si_pid == child and terminal.si_code == os.CLD_KILLED
                and terminal.si_status == signal.SIGKILL, 'capability child not SIGKILL-reaped')
        return {'pid': child, 'namespaces': observed, 'terminal': list(terminal),
                'pidfd_getfd_kcmp_ptrace': 'PASS', 'reaped': True}
    finally:
        if pidfd is not None:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Bounded cleanup; an unreaped child is always an error.
            require(select.select([pidfd], [], [], 2)[0], 'capability child cleanup timeout')
            try:
                os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            except ChildProcessError:
                pass
            os.close(pidfd)
        else:
            # fork succeeded but pidfd acquisition failed: original child is
            # still our unreaped child (PID cannot be reused), so kill/reap it.
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass  # Still poll/reap our original child, even if already dead.
            until = time.monotonic() + 2
            while time.monotonic() < until:
                if os.waitpid(child, os.WNOHANG)[0] == child:
                    break
                time.sleep(0.002)
            else:
                raise ValueError('original child fallback reap timeout')
        os.close(read)
        os.close(held)


def run(image):
    # Identity refusal precedes all kernel probes or child creation.
    identity(image, platform.release(), platform.system(), platform.machine(), digest('/usr/bin/python3'))
    require(os.geteuid() == 0, 'approved root preflight required')
    result = {'schema': 'realm.official-host-admission.v1', 'image': image,
              'kernel': platform.release(), 'python_sha256': PYTHON_SHA256,
              'authority': 'NONE', 'qualification': 'NOT_RUN', 'tools': {}}
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps = int(status['CapEff'].strip(), 16)
    require(all(caps & (1 << bit) for bit in REQUIRED_CAPS), 'required root capabilities absent')
    result['cap_eff'] = status['CapEff'].strip()
    require(Path('/proc/self/cgroup').read_text().startswith('0::/'), 'unified cgroup v2 required')
    controllers = Path('/sys/fs/cgroup/cgroup.subtree_control').read_text().split()
    require({'cpu', 'memory', 'pids'} <= set(controllers), 'existing cgroup delegation missing')
    # events/kill are non-root interfaces: the same-host physical control
    # verifies them on its fresh held subtree, never on the hierarchy root.
    for name in ('cgroup.procs', 'cgroup.controllers'):
        require(Path('/sys/fs/cgroup', name).exists(), 'cgroup interface missing: ' + name)
    result['cgroup_root_controllers'] = controllers
    result['ptrace_scope'] = Path('/proc/sys/kernel/yama/ptrace_scope').read_text().strip()
    require(result['ptrace_scope'] in ('0', '1', '2'), 'ptrace administratively disabled')
    require(not os.path.lexists('/var/lib/realm-official-stop-nov01a'), 'stale diagnostic root')
    for tool in TOOLS:
        p = Path(tool)
        require(p.is_file() and os.access(p, os.X_OK), 'required tool missing: ' + tool)
        result['tools'][tool] = {'resolved': str(p.resolve()), 'sha256': digest(p)}
    require(Path('/usr/lib/x86_64-linux-gnu/libc.a').is_file(), 'static libc missing')
    clang = sorted(Path('/usr/lib').glob('llvm-*/lib/libclang.so*'))
    require(clang, 'installed libclang missing')
    for p in (Path('/usr/lib/x86_64-linux-gnu/libc.a'), clang[0]):
        result['tools'][str(p)] = {'resolved': str(p.resolve()), 'sha256': digest(p)}
    # Execute only installed informational tools, with a bounded wait and fixed PATH.
    for tool, flag in (('/usr/bin/cc', '--version'), ('/usr/bin/readelf', '--version'),
                       ('/usr/sbin/debugfs', '-V')):
        info = subprocess.run([tool, flag], capture_output=True, timeout=3,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, check=True)
        result['tools'][tool]['version'] = (info.stdout + info.stderr).decode().strip()
    import shutil
    require(shutil.disk_usage('.').free >= 4 * 1024**3, 'insufficient scratch')
    memory = next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
    require(memory >= 2 * 1024**2, 'insufficient memory')
    require(stat.S_ISCHR(os.stat('/dev/kvm').st_mode), 'KVM character device missing')
    fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    try:
        require(fcntl.ioctl(fd, 0xAE00, 0) == 12, 'KVM API12 required')
    finally:
        os.close(fd)
    result['kvm_api'] = 12  # Deliberately NO KVM_CREATE_VM.
    libc = ctypes.CDLL(None, use_errno=True)
    result['landlock_abi'] = syscall(libc, 444, None, 0, 1)
    require(result['landlock_abi'] >= 3, 'Landlock ABI3 required')
    action = ctypes.c_uint32(0x00050000)  # SECCOMP_RET_ERRNO
    require(syscall(libc, 317, 2, 0, ctypes.byref(action)) == 0, 'seccomp ERRNO unavailable')
    result['seccomp_errno_available'] = True
    result['original_child'] = stopped_child_probe()
    result['status'] = 'PASS_HOST_ADMISSION_ONLY'
    result['enforcement'] = 'native isolation/limits/exec custody NOT_RUN; same-host closure still mandatory'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.image), indent=2), flush=True)
    except BaseException as error:
        print(json.dumps({'status': 'REFUSE_HOST', 'error': str(error),
                          'authority': 'NONE', 'qualification': 'NOT_RUN'}), flush=True)
        raise
