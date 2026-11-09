#!/usr/bin/env python3
"""Read-only platform inventory plus a bounded, immediately closed KVM VM fd.
Not a Firecracker boot, lease, containment proof or qualification verdict.
"""
import json
import os
import pathlib
import platform
import shutil
import stat
import subprocess
import time


def main():
    report = {"schema": "realm.compute-probe.v1", "time_unix": int(time.time()),
              "system": platform.system(), "machine": platform.machine(),
              "kernel": platform.release(), "cpus": os.cpu_count(),
              "disk_free_bytes": shutil.disk_usage(pathlib.Path.cwd()).free,
              "qualified": False, "firecracker_boot_tested": False,
              "kvm": {"device_exists": False, "api_version": None, "create_vm": False}}
    if platform.system() == "Linux":
        import fcntl
        mem = pathlib.Path("/proc/meminfo")
        if mem.exists():
            report["memory"] = [line for line in mem.read_text().splitlines()
                                if line.startswith(("MemTotal:", "MemAvailable:"))]
        try:
            info = os.stat("/dev/kvm")
            report["kvm"].update(device_exists=True, mode=oct(stat.S_IMODE(info.st_mode)),
                                 uid=info.st_uid, gid=info.st_gid)
            fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
            try:
                report["kvm"]["api_version"] = fcntl.ioctl(fd, 0xAE00, 0)
                if report["kvm"]["api_version"] != 12:
                    raise ValueError("unexpected KVM API")
                vm = fcntl.ioctl(fd, 0xAE01, 0)
                os.close(vm)
                report["kvm"]["create_vm"] = True
            finally:
                os.close(fd)
        except (OSError, ValueError) as exc:
            report["kvm"]["error"] = str(exc)
    elif platform.system() == "Darwin":
        for name in ("hw.model", "machdep.cpu.brand_string", "hw.memsize"):
            result = subprocess.run(["/usr/sbin/sysctl", "-n", name], capture_output=True, text=True)
            report[name] = result.stdout.strip() if result.returncode == 0 else "unavailable"
        report["macos"] = platform.mac_ver()[0]
        report["nested_framework_probe"] = "Run the separate Apple Virtualization Swift probe; not inferred here"
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
