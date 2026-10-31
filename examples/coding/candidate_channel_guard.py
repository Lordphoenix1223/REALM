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
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    filters = (Filter * len(instructions()))(*(Filter(*row) for row in instructions()))
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
