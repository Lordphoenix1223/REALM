"""Inherited Linux x86 syscall policy for candidate/evidence-channel separation.

This blocks candidate vsock/socketpair and io_uring creation before exec. It is
not a general syscall sandbox, a measured launch, or execution authority.
"""
import ctypes
import errno
import platform

POLICY = 'linux-x86-candidate-vsock-uring-deny.v1'


def instructions():
    # seccomp_data: nr at 0, audit architecture at 4, args[0] at 16.
    # Reject foreign ABIs/x32, then socket/socketpair(AF_VSOCK) and all io_uring
    # entry points (asynchronous socket operations must not bypass socket(2)).
    return [
        (0x20, 0, 0, 4),                    # LD arch
        (0x15, 1, 0, 0xc000003e),           # JEQ AUDIT_ARCH_X86_64
        (0x06, 0, 0, 0x80000000),           # KILL_PROCESS foreign ABI
        (0x20, 0, 0, 0),                    # LD nr
        (0x35, 0, 1, 0x40000000),           # JGE x32 bit
        (0x06, 0, 0, 0x80000000),           # KILL_PROCESS x32/invalid nr
        (0x15, 5, 0, 41),                   # socket -> load domain
        (0x15, 4, 0, 53),                   # socketpair -> load domain
        (0x15, 6, 0, 425),                  # io_uring_setup -> EPERM
        (0x15, 5, 0, 426),                  # io_uring_enter -> EPERM
        (0x15, 4, 0, 427),                  # io_uring_register -> EPERM
        (0x06, 0, 0, 0x7fff0000),           # ALLOW ordinary non-socket syscall
        (0x20, 0, 0, 16),                   # LD args[0], low word
        (0x15, 1, 0, 40),                   # AF_VSOCK -> EPERM
        (0x06, 0, 0, 0x7fff0000),           # ALLOW other ordinary syscalls
        (0x06, 0, 0, 0x00050000 | errno.EPERM),
    ]


def require_platform():
    if (platform.system(), platform.machine()) != ('Linux', 'x86_64'):
        raise ValueError('REFUSE: evidence-channel candidate guard requires Linux x86_64')


def install():
    """Call only in the freshly forked candidate child, never the controller."""
    require_platform()
    _install(instructions())


def _install(rows):
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    filters = (Filter * len(rows))(*(Filter(*row) for row in rows))
    program = Program(len(filters), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p,
                           ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, None, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'candidate no_new_privs refused')
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:  # PR_SET_SECCOMP FILTER
        raise OSError(ctypes.get_errno(), 'candidate evidence-channel filter refused')
    if libc.prctl(39, 0, None, 0, 0) != 1 or libc.prctl(21, 0, None, 0, 0) != 2:
        raise ValueError('REFUSE: candidate filter/no_new_privs observation differs')


STAGE8_POLICY = 'linux-stage8-readonly-stdio-seccomp.v1'


def stage8_instructions(machine=None):
    """Immutable post-startup policy. Filesystem visibility comes from bwrap.

    Default EPERM blocks fork/exec/signals/network/IPC, io_uring, pidfd_getfd,
    ptrace, mounting, descriptor duplication and resource-limit changes. Only
    read opens, stdout/stderr writes and process-local Python runtime calls pass.
    The syscall numbers are fixed Linux x86_64/AArch64 ABIs, never caller data.
    """
    machine = platform.machine() if machine is None else machine
    if machine == 'x86_64':
        arch = 0xc000003e
        ordinary = [0, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 17,
                    19, 21, 25, 28, 35, 39, 60, 63, 78, 79, 89, 96, 97,
                    98, 102, 104, 107, 108, 110, 186, 204, 217, 219,
                    228, 230, 231, 262, 267, 269, 318, 332, 439]
        opens, writes, fcntl, prlimit, prctl = [(2, 24), (257, 32)], [1, 20], 72, 302, 157
        futex = 202
    elif machine == 'aarch64':
        arch = 0xc00000b7
        ordinary = [17, 48, 57, 61, 62, 63, 65, 67, 78, 79, 80, 93, 94,
                    101, 113, 115, 123, 128, 134, 135, 139, 160, 163,
                    165, 169, 172, 173, 174, 175, 176, 177, 178, 214,
                    215, 216, 222, 226, 233, 278, 291, 439]
        opens, writes, fcntl, prlimit, prctl = [(56, 32)], [64, 66], 25, 261, 167
        futex = 98
    else:
        raise ValueError('UNSUPPORTED: strict Stage8 syscall ABI')
    allow, deny = (0x06, 0, 0, 0x7fff0000), (0x06, 0, 0, 0x00050000 | errno.EPERM)
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, arch), (0x06, 0, 0, 0x80000000),
            (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    def branch(number, body):
        rows.append((0x15, 0, len(body), number)); rows.extend(body)
    for number, offset in opens:
        branch(number, [(0x20, 0, 0, offset), (0x45, 0, 1, 0x400643), deny, allow])
    for number in writes:
        branch(number, [(0x20, 0, 0, 16), (0x15, 1, 0, 1), (0x15, 0, 1, 2), allow, deny])
    branch(fcntl, [(0x20, 0, 0, 24), (0x15, 1, 0, 1), (0x15, 0, 1, 3), allow, deny])
    branch(prlimit, [(0x20, 0, 0, 32), (0x15, 1, 0, 0), deny,
                     (0x20, 0, 0, 36), (0x15, 0, 1, 0), allow, deny])
    branch(prctl, [(0x20, 0, 0, 16), (0x15, 1, 0, 39), (0x15, 0, 1, 21), allow, deny])
    branch(futex, [(0x20, 0, 0, 24), (0x45, 0, 1, 128), allow, deny])
    for number in ordinary:
        branch(number, [allow])
    rows.append(deny)
    return rows


def install_stage8():
    """Only inside the already isolated executor, before its source executes."""
    import os
    import stat
    import resource
    if platform.system() != 'Linux':
        raise ValueError('UNSUPPORTED: strict Stage8 Linux guard')
    for fd in (0, 1, 2):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise ValueError('REFUSE: strict Stage8 requires pipe-only stdio')
    # No /proc mount or caller-provided descriptor inventory is needed. Require
    # the kernel's complete close of ALL non-stdio descriptors, including those
    # above a lowered RLIMIT_NOFILE, before the untrusted source can execute.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(436, ctypes.c_uint(3), ctypes.c_uint(0xffffffff), 2) != 0:
        raise OSError(ctypes.get_errno(), 'strict Stage8 descriptor sanitation refused')
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    bounded = 64 if hard == resource.RLIM_INFINITY else min(64, hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (bounded, bounded))
    _install(stage8_instructions())
