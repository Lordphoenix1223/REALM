#!/usr/bin/env python3
"""Fresh canonical C0 probe on an explicitly selected, owned Codespace.

This driver cannot issue publication authority. The unchanged production CLI
must obtain it from its actual measured execution. A C0 result is not a coding
agent qualification. Run as root; never use a shared or cloud-billed host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import stat
import subprocess
import tarfile
import time
import urllib.request


LOCK_SHA = "0be85a03e301005ed19f04a4140a192386b3cf23a06eed7a8c1ae709ad528855"


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def trusted(path):
    for part in [path, *path.parents]:
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f"untrusted directory: {part}")


def host_dependencies():
    tools = {}
    for name in ["guestmount", "guestunmount", "debugfs", "mkfs.ext4", "cc", "qemu-system-x86_64", "supermin"]:
        path = Path(shutil.which(name) or "").resolve(strict=True)
        if not path.is_file():
            raise RuntimeError(f"missing host tool: {name}")
        tools[name] = {"path": str(path), "sha256": sha(path)}
    packages = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], text=True)
    return {"tools": tools, "packages": sorted(packages.splitlines())}


def command(root, name, args, timeout=60, env=None):
    started = time.monotonic()
    with (root / (name + ".stdout")).open("xb") as out, (root / (name + ".stderr")).open("xb") as err:
        try:
            result = subprocess.run(args, stdout=out, stderr=err, timeout=timeout, env=env)
            row = {"exit": result.returncode, "timeout": False}
        except subprocess.TimeoutExpired:
            row = {"exit": None, "timeout": True}
    row.update(argv=args, wall_seconds=time.monotonic() - started)
    save(root / (name + ".json"), row)
    return row


def checked(root, name, args, **kwargs):
    result = command(root, name, args, **kwargs)
    if result["exit"] != 0:
        raise RuntimeError(f"{name} failed; retained stdout/stderr")


def account(root, name):
    try:
        found = pwd.getpwnam(name)
    except KeyError:
        checked(root, "create-" + name, ["useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", name])
        found = pwd.getpwnam(name)
    if found.pw_uid == 0 or found.pw_gid == 0 or found.pw_shell != "/usr/sbin/nologin":
        raise RuntimeError("dedicated non-login identity required")
    return found


def fetch(root, name, spec):
    target = root / name
    with urllib.request.urlopen(spec["url"], timeout=60) as response, target.open("xb") as out:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > spec["size_bytes"]:
                raise RuntimeError("download exceeds pinned size")
            out.write(chunk)
    if total != spec["size_bytes"] or sha(target) != spec["sha256"]:
        raise RuntimeError("download differs from external asset pin")
    return target


def run_probe(root, profile, fc, custody, cg, index):
    assets = root / "assets"
    run = root / "runs" / index
    run.mkdir(mode=0o700)
    if host_dependencies() != profile["host_dependencies"]:
        raise RuntimeError("host dependencies changed after profile freeze")
    save(run / "driver.json", {"driver_sha256": sha(Path(__file__)), "frozen_profile_sha256": sha(root / "frozen-profile.json"), "authority": "NONE"})
    world = run / "world"
    world.mkdir(mode=0o700)
    (world / "input.txt").write_bytes(b"abc")
    (world / "input.txt").chmod(0o644)
    backend = {k: str(assets / v) for k, v in {"firecracker": "firecracker", "kernel": "kernel", "rootfs": "rootfs.ext4", "workspace_device": "s0.ext4", "guest_supervisor": "c0"}.items()}
    backend.update(state_dir=str(root / "states"), production_jailer={"jailer": str(assets / "jailer"), "uid": fc.pw_uid, "gid": fc.pw_gid, "chroot_base_dir": profile["jail_base"], "cgroup_parent": cg.name, "memory_max_bytes": 536870912, "pids_max": 16})
    save(run / "backend.json", backend)
    cli = str(assets / "realm")
    checked(run, "draft", [cli, "task", "draft", str(world / "input.txt"), "output.txt", str(run / "task.json"), "Create the C0 XOR-0x20 output for abc in this private test world"])
    approval = (run / "draft.stdout").read_text().split("explicitly on the qualified worker: ")[-1].strip()
    if len(approval) != 64 or any(c not in "0123456789abcdef" for c in approval):
        raise RuntimeError("unexpected draft approval identity")
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LIBGUESTFS_BACKEND": "direct", "REALM_SOURCE_REVISION": profile["source_sha"], "REALM_V6_PROFILE": "1"}
    result = command(run, "production", [cli, "task", "run", str(run / "task.json"), str(run / "backend.json"), str(assets / "c0_output_custodian"), str(custody.pw_uid), str(custody.pw_gid), str(world), str(run / "evidence"), "--approve", approval], timeout=300, env=environment)
    save(run / "result.json", {"production": result, "artifact_present": (run / "evidence/accepted.realm").is_file(), "scope": profile["scope"], "driver_authority": "NONE", "requires_independent_reopen_and_profile_qualification": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codespace", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--built", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--prepared-run", help="fresh three-digit run using an already frozen private profile")
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("requires root on the selected Linux x86_64 Codespace")
    if os.environ.get("CODESPACE_NAME") != args.codespace or not args.codespace:
        parser.error("actual Codespace name differs from explicit owned instance")
    source = args.source.resolve(strict=True)
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)
    if head != args.source_sha or dirty:
        parser.error("source must be clean and exactly pinned")
    lock_path = source / "docs/v6/FIRECRACKER_ACTIONS_SMOKE_LOCK_V1.json"
    if sha(lock_path) != LOCK_SHA:
        parser.error("asset lock differs from external pin")
    root = args.root
    if not root.is_absolute() or root.parent != Path("/var/lib") or not root.name.startswith("realm-v7-c0-"):
        parser.error("use a fresh /var/lib/realm-v7-c0-* root")
    trusted(root.parent)
    longest_socket = root / "j/firecracker" / ("realm-" + "a" * 32) / "root/run/firecracker.socket"
    if len(os.fsencode(longest_socket)) >= 108:
        parser.error("root is too long for the canonical jail's Unix sockets; use a shorter owned name")
    if shutil.disk_usage(root.parent).free < 2 * 1024**3:
        parser.error("insufficient disk headroom")
    if args.prepared_run:
        index = args.prepared_run
        if len(index) != 3 or not index.isascii() or not index.isdecimal() or int(index) < 2:
            parser.error("prepared run index must be 002 through 999")
        trusted(root)
        profile = json.loads((root / "frozen-profile.json").read_text())
        if profile["source_sha"] != head or profile["codespace"] != args.codespace or profile["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
            parser.error("prepared profile source, host or boot differs")
        assets = root / "assets"
        trusted(assets)
        if set(profile["resources"]) != {p.name for p in assets.iterdir()}:
            parser.error("prepared asset inventory differs")
        for name, pin in profile["resources"].items():
            info = (assets / name).lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size != pin["bytes"] or sha(assets / name) != pin["sha256"]:
                parser.error("prepared asset identity differs")
        fc, custody = pwd.getpwnam("realm-fc"), pwd.getpwnam("realm-c0-custody")
        if profile["identities"] != {"jailer": [fc.pw_uid, fc.pw_gid], "custody": [custody.pw_uid, custody.pw_gid]}:
            parser.error("prepared service identity differs")
        cg = Path(profile["cgroup_parent"])
        if cg != Path("/sys/fs/cgroup") / root.name:
            parser.error("prepared cgroup scope differs")
        run_probe(root, profile, fc, custody, cg, index)
        return
    root.mkdir(mode=0o755)
    assets = root / "assets"
    assets.mkdir(mode=0o755)
    for directory in ["states", "runs", "j"]:
        (root / directory).mkdir(mode=0o700 if directory != "j" else 0o755)
    profile = {"schema": "realm.v7.codespace-c0-probe/v1", "source_sha": head,
               "driver_sha256": sha(Path(__file__)), "codespace": args.codespace,
               "host": platform.uname()._asdict(), "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
               "scope": "canonical C0 only; not coding agent qualification", "authority": "NONE_FROM_DRIVER", "jail_base": str(root / "j")}
    try:
        fc = account(root, "realm-fc")
        custody = account(root, "realm-c0-custody")
        if fc.pw_uid == custody.pw_uid:
            raise RuntimeError("jailer and custody identities must differ")
        cg = Path("/sys/fs/cgroup") / root.name
        cg.mkdir(mode=0o755)
        (cg / "cgroup.subtree_control").write_text("+cpu +memory +pids")
        profile["cgroup_parent"] = str(cg)
        profile["identities"] = {"jailer": [fc.pw_uid, fc.pw_gid], "custody": [custody.pw_uid, custody.pw_gid]}
        lock = json.loads(lock_path.read_text())["artifacts"]
        archive = fetch(assets, "release.tgz", lock["release_archive"])
        with tarfile.open(archive) as tar:
            for name in ["firecracker", "jailer"]:
                spec = lock[name]
                member = tar.getmember(spec["archive_member"])
                if not member.isfile() or member.size != spec["size_bytes"]:
                    raise RuntimeError("pinned archive member invalid")
                with tar.extractfile(member) as inp, (assets / name).open("xb") as out:
                    shutil.copyfileobj(inp, out)
                if sha(assets / name) != spec["sha256"]:
                    raise RuntimeError("executable differs from asset pin")
                (assets / name).chmod(0o755)
        fetch(assets, "kernel", lock["guest_kernel"])
        for name in ["realm", "realm-artifact", "v6-production-publish", "c0_output_custodian"]:
            original = args.built / name
            info = original.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("built executable must be regular")
            # Cargo hard-links its top-level bin to deps/. Copy into a fresh
            # inode; never carry those build-directory aliases into production.
            shutil.copyfile(original, assets / name)
            if (assets / name).stat().st_nlink != 1:
                raise RuntimeError("production copy must be single-linked")
            (assets / name).chmod(0o755)
        flags = ["-O2", "-static", "-nostdlib", "-fno-stack-protector", "-fno-pie", "-no-pie", "-fno-builtin", "-Wl,--build-id=none", "-Wl,-z,noexecstack"]
        checked(root, "compiler-version", ["cc", "--version"])
        checked(root, "guest-build", ["cc", *flags, str(source / "workloads/v6-2-narrow/c0_production_x86_64.c"), "-o", str(assets / "c0")])
        for name in ["guest", "baseline"]:
            stage = root / (name + "-stage")
            stage.mkdir(mode=0o755)
            if name == "guest":
                shutil.copyfile(assets / "c0", stage / "c0")
                (stage / "c0").chmod(0o755)
            else:
                (stage / "input.txt").write_bytes(b"abc")
                (stage / "input.txt").chmod(0o644)
            image = assets / ("rootfs.ext4" if name == "guest" else "s0.ext4")
            with image.open("xb") as stream:
                stream.truncate(16 * 1024**2)
            checked(root, "mkfs-" + name, ["mkfs.ext4", "-q", "-F", "-d", str(stage), str(image)])
            checked(root, "remove-lostfound-" + name, ["debugfs", "-w", "-R", "rmdir /lost+found", str(image)])
            image.chmod(0o644)
        profile["resources"] = {p.name: {"bytes": p.stat().st_size, "sha256": sha(p)} for p in assets.iterdir() if p.is_file()}
        profile["guest_source_sha256"] = sha(source / "workloads/v6-2-narrow/c0_production_x86_64.c")
        profile["guest_compiler_flags"] = flags
        profile["host_dependencies"] = host_dependencies()
        save(root / "frozen-profile.json", profile)
        run_probe(root, profile, fc, custody, cg, "001")
    except Exception as error:
        save(root / "driver-failure.json", {"error": str(error), "authority": "NONE", "profile": profile})
        raise


if __name__ == "__main__":
    main()
