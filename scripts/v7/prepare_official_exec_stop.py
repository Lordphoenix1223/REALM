#!/usr/bin/env python3
"""Prepare only the frozen, non-authorizing official exec-stop experiment.

Unpack/build phase is unprivileged. --install is separately approved ephemeral
root setup, never production trust installation and never a launch operation.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import grp
import shutil
import stat
import subprocess
import tarfile

from official_exec_stop import require, save

PAYLOAD_SHA = '4ce9d4e75fe3fe5c4dc135049e3f05286067ed9037b0e7eb0c20462bd8bb03ca'
NATIVE_SOURCE = '719b86519b6600258f388984d95f22fcbf36f90f'
PINS = {
    'offline-bundle.tar.gz': 'caaf94a3723a2f56643f35ce9e6daf7aa7586e823fc9c96f90f4262df2ff0ff6',
    'rootfs.ext4.gz': '24dba60716f33e276663b16681b7a469283f3c83304cd8ccbf2f109eede6d0e0',
    'workspace.ext4.gz': '89d688891dd15b3281086ce8fe27255d62694d9ca9c7bf33a5eae7b5bfbb8cc1',
    'coding-init': '8f502f35d20800cad97c1702675847efb082560b682164cb9fa9c5de713dc2de',
}
FIRECRACKER = '99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5'
JAILER = '65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f'
KERNEL = '9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2'
ROOTFS = '696e8fea93f3f28cb03759c8e09fafb2205173eeb258e30f94894ce5a434f1d6'
WORKSPACE = '0597c8b4135c8c796bdf2f4d469f55e5268259d3c98dd946ee49fc70db94f98a'
ROOT = Path('/var/lib/realm-official-stop-nov01a')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded_read(path, maximum, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and 0 < info.st_size <= maximum, 'input type/size differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and len(raw) <= maximum and sha(raw) == expected,
                'bounded input hash differs')
        return raw
    finally:
        os.close(fd)


def expanded(raw, size, expected):
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        data = stream.read(size + 1)
    require(len(data) == size and sha(data) == expected, 'bounded expanded image differs')
    return data


def unpack(payload, out):
    require(os.geteuid() != 0, 'archive unpacking/build must stay unprivileged')
    require(sha(payload.read_bytes()) == PAYLOAD_SHA, 'transport payload differs')
    out.mkdir(mode=0o700)
    with tarfile.open(payload) as archive:
        members = archive.getmembers()
        require(len(members) == len(PINS) and {m.name for m in members} == set(PINS), 'payload member set differs')
        for member in members:
            require(member.isfile(), 'payload links/devices refused')
            raw = archive.extractfile(member).read()
            require(sha(raw) == PINS[member.name], 'payload member hash differs')
            with (out / member.name).open('xb') as stream:
                stream.write(raw)
    bundle = out / 'bundle'
    bundle.mkdir(mode=0o700)
    with tarfile.open(out / 'offline-bundle.tar.gz') as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and '..' not in path.parts and
                    (member.isfile() or member.isdir()), 'unsafe offline source member')
            target = bundle / path
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    shutil.copyfileobj(archive.extractfile(member), stream)
                target.chmod(member.mode & 0o777)
    metadata = json.loads((bundle / 'INPUTS.json').read_bytes())
    require(metadata['source_commit'] == NATIVE_SOURCE, 'native source differs')
    for name, expected in metadata['source_files'].items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts, 'unsafe source identity path')
        raw = (bundle / 'source' / path).read_bytes()
        require(len(raw) == expected['bytes'] and sha(raw) == expected['sha256'],
                'frozen source input differs: ' + name)
    require(sha((bundle / 'source/.cargo/config.toml').read_bytes()) == metadata['config_sha256'],
            'offline dependency configuration differs')


def install(args):
    require(os.geteuid() == 0, 'separately approved ephemeral root setup required')
    source = Path(args.work)
    ROOT.mkdir(mode=0o700)  # Fresh only; no deletion, mutation or adoption.
    for parent in ROOT.parents:
        info = parent.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and not parent.is_symlink(), 'unsafe root setup parent')
    users, groups = pwd.getpwall(), grp.getgrall()
    require(not any(p.pw_name == 'realm-fc' or p.pw_uid == 62123 for p in users)
            and not any(g.gr_name == 'realm-fc' or g.gr_gid == 62123 for g in groups),
            'dedicated experimental identity occupied; never take over an account')
    subprocess.run(['/usr/sbin/groupadd', '--gid', '62123', 'realm-fc'], check=True)
    subprocess.run(['/usr/sbin/useradd', '--uid', '62123', '--gid', '62123',
                    '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'realm-fc'], check=True)

    def copy(raw, name, expected, mode):
        require(sha(raw) == expected, 'installed input hash differs: ' + name)
        path = ROOT / name
        with path.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        path.chmod(mode)
        return path

    release = bounded_read(source / 'firecracker.tgz', 7464385,
            '06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558')
    with tarfile.open(fileobj=io.BytesIO(release)) as archive:
        for name, pin in [('firecracker', FIRECRACKER), ('jailer', JAILER)]:
            member = archive.getmember('release-v1.17.0-x86_64/' + name + '-v1.17.0-x86_64')
            require(member.isfile(), 'official release member is not a regular file')
            copy(archive.extractfile(member).read(), name, pin, 0o555)
    copy(bounded_read(source / 'kernel', 27846792, KERNEL), 'kernel', KERNEL, 0o444)
    compressed = bounded_read(source / 'rootfs.ext4.gz', 58795752, PINS['rootfs.ext4.gz'])
    copy(expanded(compressed, 295698432, ROOTFS), 'rootfs.ext4', ROOTFS, 0o444)
    init = bounded_read(source / 'coding-init', 830296, PINS['coding-init'])
    copy(init, 'coding-init', PINS['coding-init'], 0o555)
    embedded = subprocess.run(['/usr/sbin/debugfs', '-R', 'cat /coding-init', str(ROOT / 'rootfs.ext4')],
                              check=True, capture_output=True, timeout=10).stdout
    require(embedded == init, 'retained rootfs embedded init differs')
    compressed = bounded_read(source / 'workspace.ext4.gz', 9290, PINS['workspace.ext4.gz'])
    workspace = expanded(compressed, 8388608, WORKSPACE)
    for name in ['workspace.ext4', 'starting.ext4', 'working.ext4']:
        copy(workspace, name, WORKSPACE, 0o600 if name == 'working.ext4' else 0o444)
    for name in ['state', 'jails', 'evidence']:
        (ROOT / name).mkdir(mode=0o700)
    native = bounded_read(args.elf, 67108864, args.elf_sha256)
    copy(native, 'native-test', args.elf_sha256, 0o555)
    inputs = {
        'backend': {'firecracker': str(ROOT / 'firecracker'), 'kernel': str(ROOT / 'kernel'),
                    'rootfs': str(ROOT / 'rootfs.ext4'), 'workspace_device': str(ROOT / 'workspace.ext4'),
                    'guest_supervisor': str(ROOT / 'coding-init'), 'state_dir': str(ROOT / 'state'),
                    'production_jailer': {'jailer': str(ROOT / 'jailer'), 'uid': 62123, 'gid': 62123,
                                          'chroot_base_dir': str(ROOT / 'jails'),
                                          'cgroup_parent': 'realm-exec-stop-nov01a/jailer',
                                          'memory_max_bytes': 134217728, 'pids_max': 64}},
        'starting_workspace_image': str(ROOT / 'starting.ext4'),
        'working_workspace_image': str(ROOT / 'working.ext4'),
        'expected_sha256': {str(ROOT / name): pin for name, pin in {
            'firecracker': FIRECRACKER, 'jailer': JAILER, 'kernel': KERNEL, 'rootfs.ext4': ROOTFS,
            'coding-init': PINS['coding-init'], 'workspace.ext4': WORKSPACE,
            'starting.ext4': WORKSPACE, 'working.ext4': WORKSPACE}.items()},
    }
    save(ROOT / 'inputs.json', inputs)
    save(ROOT / 'prelaunch-pins.json', {'native_sha256': args.elf_sha256,
         'inputs_sha256': sha((ROOT / 'inputs.json').read_bytes()), 'authority': 'NONE',
         'native_source': NATIVE_SOURCE,
         'compiler': 'source-pinned build artifact measured in this job; not production authority'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', type=Path)
    parser.add_argument('--work', required=True)
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--elf')
    parser.add_argument('--elf-sha256')
    args = parser.parse_args()
    if args.install:
        install(args)
    else:
        require(args.payload is not None, 'exact payload required')
        unpack(args.payload, Path(args.work))
