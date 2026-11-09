#!/usr/bin/env python3
"""Snapshot public offline assets and host Python into a DEVELOPMENT guest.

No downloads, host mounts, production profile changes, qualification or issuer.
The image is checksum-pinned after construction, not reproducibly built or
approved for REALM authority. Only a fresh task-owned output directory is used.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import uuid

from fetch_offline_coder import assets_for


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while data := f.read(1024 * 1024):
            h.update(data)
    return h.hexdigest()


def save(path, data):
    with path.open('xb') as f:
        os.chmod(path, 0o600)
        f.write(json.dumps(data, sort_keys=True, indent=2).encode() + b'\n')
        f.flush()
        os.fsync(f.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=pathlib.Path)
    parser.add_argument('--assets', required=True, type=pathlib.Path)
    parser.add_argument('--model', default='coder-7b')
    parser.add_argument('--memory-mib', type=int, choices=(5120, 5632, 6144), default=6144,
                        help='bounded development guest memory; default profile unchanged')
    parser.add_argument("--sealed-model-inputs", type=pathlib.Path,
                        help="reuse only a protected immutable development image as a readonly model disk")
    parser.add_argument("--sealed-model-inputs-sha256")
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('Linux x86_64 required; no compatibility fallback')
    if not args.root.is_absolute() or args.root.exists():
        parser.error('fresh absolute task-owned output directory required')
    assets = args.assets.resolve(strict=True)
    pins = assets_for(args.model)
    if json.loads((assets / 'assets.json').read_text())['assets'] != list(pins):
        parser.error('asset manifest differs')
    model_disk = None
    if args.sealed_model_inputs:
        protected = args.sealed_model_inputs
        if not re.fullmatch(r"/var/lib/realm-v7-coding-inputs-[0-9]{3}", str(protected)):
            parser.error("protected task-owned model input root required")
        image = protected / "rootfs.ext4"
        for path in [image, *image.parents]:
            info = path.lstat()
            if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                parser.error("model input image/parents are not root protected")
        if image.stat().st_mode & 0o777 != 0o444 or not image.is_file():
            parser.error("readonly regular model input image required")
        if sha(protected / "guest-inputs.json") != args.sealed_model_inputs_sha256:
            parser.error("external sealed model manifest pin differs")
        old = json.loads((protected / "guest-inputs.json").read_text())
        model_file = "assets/" + pins[0]["name"]
        if (old["authority"] != "NONE" or old["qualification"] != "NOT_QUALIFIED"
            or old["model_name"] != args.model or old["files"][model_file] !=
                {"sha256": pins[0]["sha256"], "bytes": pins[0]["bytes"]}
            or sha(image) != old["rootfs_sha256"]):
            parser.error("protected model image identity differs")
        # Reopen the exact model from the immutable image, without extracting
        # or allocating another model-sized file. Nothing modifies that image.
        process = subprocess.Popen(["debugfs", "-R", "cat /" + model_file, str(image)],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        h, count = hashlib.sha256(), 0
        with process.stdout:
            while part := process.stdout.read(1024 * 1024):
                count += len(part); h.update(part)
        if process.wait() or count != pins[0]["bytes"] or h.hexdigest() != pins[0]["sha256"]:
            parser.error("embedded protected model bytes differ")
        model_disk = {"image_path": str(image), "sha256": old["rootfs_sha256"],
                      "bytes": image.stat().st_size, "manifest_sha256": args.sealed_model_inputs_sha256,
                      "model_sha256": h.hexdigest(), "scope": "readonly public model inputs; no VM or authority reuse"}
    elif args.sealed_model_inputs_sha256:
        parser.error("sealed model manifest pin requires its protected image root")
    for item in (pins[1:] if model_disk else pins):
        path = assets / item['name']
        if not path.is_file() or path.is_symlink() or path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
            parser.error('public asset pin differs')
    if shutil.disk_usage(args.root.parent).free < (1024**3 if model_disk else pins[0]['bytes'] + 1024**3):
        parser.error('insufficient free space for guest image and margin')
    args.root.mkdir(mode=0o700)
    stage = args.root / 'stage'
    stage.mkdir(mode=0o700)
    for name in ('usr/bin', 'usr/lib', 'usr/lib64', 'proc', 'sys', 'dev', 'run', 'tmp', 'controller', 'assets', 'model-inputs'):
        (stage / name).mkdir(parents=True, exist_ok=True)
    for name, target in [('bin', 'usr/bin'), ('lib', 'usr/lib'), ('lib64', 'usr/lib64')]:
        (stage / name).symlink_to(target)
    sources = {}

    def copy_host(path):
        path = pathlib.Path(path)
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or not str(resolved).startswith('/usr/'):
            raise ValueError('unsupported host runtime input: ' + str(path))
        destination = stage / str(path).lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copyfile(path, destination)
            destination.chmod(0o555)
        expected = sha(resolved)
        if sha(destination) != expected:
            raise ValueError('host runtime changed while copying')
        sources[str(path)] = expected

    python = pathlib.Path('/usr/bin/python3').resolve(strict=True)
    stdlib = pathlib.Path(subprocess.check_output(['/usr/bin/python3', '-I', '-c',
        'import sysconfig; print(sysconfig.get_path("stdlib"))'], text=True).strip())
    if not str(stdlib).startswith('/usr/lib/python3.'):
        raise ValueError('unsupported system Python layout')
    copy_host(python)
    (stage / 'usr/bin/python3').symlink_to(python.name)
    shutil.copytree(stdlib, stage / str(stdlib).lstrip('/'),
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    copy_host('/usr/bin/bwrap')
    runtime = assets / 'runtime/llama-b11541'
    elf_inputs = [python, pathlib.Path('/usr/bin/bwrap'), *stdlib.rglob('*.so'),
                  runtime / 'llama-server', *runtime.glob('*.so*')]
    visited = set()
    while elf_inputs:
        binary = elf_inputs.pop()
        if binary.resolve() in visited:
            continue
        visited.add(binary.resolve())
        output = subprocess.check_output(['/usr/bin/ldd', str(binary)], text=True)
        if 'not found' in output:
            raise ValueError('missing ELF dependency')
        for dependency in re.findall(r'(?:=>\s+|^\s*)(/[^\s]+)\s+\(', output, re.MULTILINE):
            if not pathlib.Path(dependency).resolve().is_relative_to(runtime):
                copy_host(dependency)
            elf_inputs.append(pathlib.Path(dependency))
    scripts = pathlib.Path(__file__).resolve().parent
    for name in ('offline_coding_agent.py', 'coding_worker.py', 'fetch_offline_coder.py', 'coding_guest_boot.py'):
        shutil.copyfile(scripts / name, stage / 'controller' / name)
        sources[name] = sha(scripts / name)
    shutil.copytree(assets / 'runtime', stage / 'assets/runtime', symlinks=False)
    # Temporary hard link avoids a second model-sized staging copy. It is
    # removed after mkfs; the original public asset's bytes/mode are untouched.
    if model_disk:
        (stage / 'assets' / pins[0]['name']).symlink_to('/model-inputs/assets/' + pins[0]['name'])
    else:
        os.link(assets / pins[0]['name'], stage / 'assets' / pins[0]['name'])
    init = args.root / 'coding-init'
    subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                    *(['-DREALM_CODING_MODEL_DISK'] if model_disk else []),
                    str(scripts / 'coding_guest_init.c'), '-o', str(init)], check=True)
    shutil.copyfile(init, stage / 'coding-init')
    (stage / 'coding-init').chmod(0o555)
    sources['coding_guest_init.c'] = sha(scripts / 'coding_guest_init.c')
    sources['build_coding_guest.py'] = sha(pathlib.Path(__file__))
    challenge = os.urandom(32).hex()
    save(stage / 'controller/guest-inputs.json', {'authority': 'NONE',
         'model_name': args.model, 'challenge': challenge, 'raw_handoff_protocol': 'durable-ack-cad-v1'})
    files = {str(p.relative_to(stage)): {'sha256': sha(p), 'bytes': p.stat().st_size}
             for p in stage.rglob('*') if p.is_file()}
    size = ((sum(p['bytes'] for p in files.values()) + (128 if model_disk else 512) * 1024**2 + 1024**2 - 1) // 1024**2) * 1024**2
    image = args.root / 'rootfs.ext4'
    with image.open('xb') as f:
        f.truncate(size)
    image.chmod(0o600)
    subprocess.run(['mkfs.ext4', '-q', '-F', '-U', str(uuid.uuid4()), '-d', str(stage), str(image)], check=True)
    report = {'schema': 'realm.coding-development-guest-inputs.v1', 'authority': 'NONE',
        'realm_artifact': None, 'qualification': 'NOT_QUALIFIED', 'architecture': 'x86_64',
        'model_name': args.model, 'challenge': challenge, 'raw_handoff_protocol': 'durable-ack-cad-v1', 'source_files': sources,
        'rootfs_sha256': sha(image), 'rootfs_bytes': size, 'init_sha256': sha(init),
        'files': files, 'builder_kernel': platform.release(),
        'boot_args': 'console=ttyS0 root=/dev/vda rootfstype=ext4 ro init=/coding-init panic=1',
        'memory_mib': args.memory_mib, 'vcpu_count': 2, 'network_interfaces': [],
        'scope': 'raw guest development only; not the qualified C0 profile or REALM authority'}
    if model_disk:
        if sha(pathlib.Path(model_disk['image_path'])) != model_disk['sha256']:
            raise ValueError('protected model image changed during construction')
        report['model_disk'] = model_disk
        report['construction_scope'] = 'fresh small boot root; preserved readonly public model image'
    save(args.root / 'guest-inputs.json', report)
    os.unlink(stage / 'assets' / pins[0]['name'])
    shutil.rmtree(stage)
    print(json.dumps({'status': 'DEVELOPMENT_GUEST_INPUTS_PINNED', 'authority': 'NONE',
                      'rootfs_sha256': report['rootfs_sha256'], 'rootfs_bytes': size}))


if __name__ == '__main__':
    main()
