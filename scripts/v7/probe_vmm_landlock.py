#!/usr/bin/env python3
"""Physical, NON_AUTHORIZING Landlock coverage experiment; never launches a VM.

Only fresh temporary fixtures are modified. This deliberately keeps inherited
capabilities to test what a filesystem fence cannot revoke. It is not a launcher
or a QualifiedFixedRuntime producer. No production module imports this script.
"""
import array
import ctypes
import errno
import json
import mmap
import os
import platform
import signal
import socket
import sys
import tempfile
from pathlib import Path


class Ruleset(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _layout_ = "ms"  # explicit packed layout on Python 3.14+, same Linux UAPI bytes
    _pack_ = 1
    _fields_ = [("access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def syscall(libc, number, *args):
    result = libc.syscall(number, *args)
    if result < 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    return result


def attempted(action):
    try:
        action()
        return 0
    except OSError as error:
        return error.errno


def install(libc, abi, approved):
    # Fixed minimum: no graceful security downgrade. Newer coverage is measured,
    # not silently assumed. syscalls 444..446 are Linux x86_64/aarch64 UAPI.
    if abi < 3:
        raise RuntimeError("ABI < 3 cannot deny truncation")
    if ctypes.sizeof(PathRule) != 12 or PathRule.parent_fd.offset != 8:
        raise RuntimeError("unsupported Landlock path-rule layout")
    fs = (1 << 15) - 1  # all ABI3 filesystem rights, including TRUNCATE
    if abi >= 5:
        fs |= 1 << 15  # IOCTL_DEV
    attr = Ruleset(fs, 3 if abi >= 4 else 0, 3 if abi >= 6 else 0)
    size = 24 if abi >= 6 else 16 if abi >= 4 else 8
    rules = syscall(libc, 444, ctypes.byref(attr), size, 0)
    leaf = os.open(approved, os.O_PATH | os.O_CLOEXEC)
    try:
        rule = PathRule(1 << 2, leaf)  # only READ_FILE on this actual inode
        syscall(libc, 445, rules, 1, ctypes.byref(rule), 0)
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise OSError(ctypes.get_errno(), "no_new_privs")
        syscall(libc, 446, rules, 0)
        return {"handled_access_fs": attr.fs, "handled_access_net": attr.net,
                "scoped": attr.scoped, "ruleset_attr_bytes": size}
    finally:
        os.close(leaf)
        os.close(rules)


def child(libc, abi, base, inherited, mapping, channel):
    installed = install(libc, abi, str(base / "approved"))
    result = {"installed_policy": installed, "uid": os.getuid(), "gid": os.getgid(),
              "effective_uid": os.geteuid(), "effective_gid": os.getegid()}
    def read_approved():
        with open(base / "approved", "rb") as stream:
            if stream.read() != b"approved":
                raise RuntimeError("approved bytes changed")
    def new_write():
        fd = os.open(base / "new-open", os.O_WRONLY)
        os.close(fd)
    result["approved_read_errno"] = attempted(read_approved)
    result["new_write_open_errno"] = attempted(new_write)
    result["inherited_write_errno"] = attempted(lambda: os.pwrite(inherited, b"F", 0))
    mapping[0:1] = b"M"
    mapping.flush()
    result["inherited_shared_mapping_store"] = "completed"
    channel.sendall(b"R")  # request an FD from the unfenced parent AFTER install
    _, controls, flags, _ = channel.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
    if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or len(controls) != 1:
        raise RuntimeError("invalid rights message")
    level, kind, payload = controls[0]
    rights = array.array("i")
    rights.frombytes(payload)
    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(rights) != 1:
        raise RuntimeError("unexpected rights")
    try:
        result["received_after_fence_write_errno"] = attempted(lambda: os.pwrite(rights[0], b"R", 0))
    finally:
        os.close(rights[0])
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        result["outside_pathname_unix_connect_errno"] = attempted(lambda: probe.connect(str(base / "outside.sock")))
        if result["outside_pathname_unix_connect_errno"] == 0:
            probe.sendall(b"U")
    return result


def run():
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64"):
        print(json.dumps({"authority": "NONE", "result": "UNSUPPORTED_HOST"}))
        return 2
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        abi = syscall(libc, 444, 0, 0, 1)
    except OSError as error:
        print(json.dumps({"authority": "NONE", "result": "UNAVAILABLE", "errno": error.errno}))
        return 2
    if abi < 3:
        print(json.dumps({"authority": "NONE", "result": "UNSUPPORTED_ABI", "abi": abi}))
        return 2
    with tempfile.TemporaryDirectory(prefix="realm-landlock-coverage-") as temp:
        base = Path(temp)
        for name in ("new-open", "fd", "map", "received"):
            (base / name).write_bytes(b"0" * mmap.PAGESIZE)
        (base / "approved").write_bytes(b"approved")
        inherited = os.open(base / "fd", os.O_RDWR)
        mapped_fd = os.open(base / "map", os.O_RDWR)
        mapping = mmap.mmap(mapped_fd, mmap.PAGESIZE, flags=mmap.MAP_SHARED)
        received = os.open(base / "received", os.O_RDWR)
        parent, worker = socket.socketpair()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(base / "outside.sock"))
        listener.listen(1)
        parent.settimeout(5)
        listener.settimeout(5)
        pid = os.fork()
        if pid == 0:
            parent.close()
            listener.close()
            os.close(received)
            os.close(mapped_fd)
            try:
                result = child(libc, abi, base, inherited, mapping, worker)
                worker.sendall(json.dumps(result).encode())
                os._exit(0)
            except BaseException as error:
                worker.sendall(json.dumps({"error": str(error)}).encode())
                os._exit(1)
        worker.close()
        status = None
        try:
            if parent.recv(1) != b"R":
                raise RuntimeError("fence installation failed before rights request")
            parent.sendmsg([b"F"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [received]))])
            data = bytearray()
            while True:
                part = parent.recv(4096)
                if not part:
                    break
                data.extend(part)
                if len(data) > 16384:
                    raise RuntimeError("oversized child report")
            _, status = os.waitpid(pid, 0)
            observed = json.loads(data)
            reopened = {name: (base / name).read_bytes()[:1].decode() for name in ("new-open", "fd", "map", "received")}
            if observed.get("outside_pathname_unix_connect_errno") == 0:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(5)
                    unix_byte = peer.recv(1).decode()
            else:
                unix_byte = None
            expected = {"new-open": "0", "fd": "F", "map": "M", "received": "R"}
            valid = (os.waitstatus_to_exitcode(status) == 0 and reopened == expected
                     and observed.get("approved_read_errno") == 0
                     and observed.get("new_write_open_errno") == errno.EACCES
                     and observed.get("inherited_write_errno") == 0
                     and observed.get("received_after_fence_write_errno") == 0
                     and unix_byte == "U")
            print(json.dumps({"authority": "NONE", "result": "OBSERVED_EXPECTED_LIMITS" if valid else "UNEXPECTED_RESULT",
                              "architecture": platform.machine(), "kernel": platform.release(), "landlock_abi": abi,
                              "parent_uid": os.getuid(), "parent_gid": os.getgid(),
                              "handled_policy": "all filesystem rights through ABI5; TCP deny ABI4+; scopes ABI6+; read-only approved leaf",
                              "pathname_resolution_right_handled": False,
                              "native_runtime_qualification": "NOT_ESTABLISHED", "child": observed,
                              "independently_reopened": reopened, "parent_received_unix_byte": unix_byte}, sort_keys=True))
            return 0 if valid else 1
        finally:
            if status is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            parent.close()
            listener.close()
            mapping.close()
            for fd in (inherited, mapped_fd, received):
                os.close(fd)


if __name__ == "__main__":
    raise SystemExit(run())
