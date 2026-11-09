#!/usr/bin/env python3
"""Derive a fresh small DEVELOPMENT tools guest from a protected pinned image.

Old inputs stay immutable. No saved VM/RAM state, model disk, authority, or
host candidate execution. Root operator owns these dedicated input directories.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import uuid


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while part := stream.read(1024 * 1024):
            value.update(part)
    return value.hexdigest()


def save(path, value):
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(json.dumps(value, sort_keys=True, indent=2).encode() + b'\n')
        stream.flush()
        os.fsync(stream.fileno())


def extract(image, name):
    return subprocess.check_output(['debugfs', '-R', 'cat /' + name, str(image)], stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', required=True, type=pathlib.Path)
    ap.add_argument('--source-sha256', required=True)
    ap.add_argument('--root', required=True, type=pathlib.Path)
    ap.add_argument('--ephemeral-input-root', action='store_true',
                    help='fresh private /tmp inputs; preserve evidence before host shutdown')
    ap.add_argument('--native-submission-binding', type=pathlib.Path,
                    help='optional external diagnostic labels; never authority')
    ap.add_argument('--native-subtask',type=pathlib.Path)
    ap.add_argument('--immutable-native',action='store_true',help='build a static boot image once; native task inputs arrive on the original control stream')
    args = ap.parse_args()
    if os.geteuid() != 0 or (platform.system(), platform.machine()) != ('Linux', 'x86_64'):
        ap.error('root operator on actual Linux x86_64 required')
    if not re.fullmatch(r'/var/lib/realm-v7-coding-inputs-[0-9]{3}', str(args.source)):
        ap.error('dedicated protected source input path required')
    prefix = '/tmp' if args.ephemeral_input_root else '/var/lib'
    if not re.fullmatch(prefix + r'/realm-v7-coding-inputs-[0-9]{3}', str(args.root)):
        ap.error('dedicated fresh input path required')
    parent = args.root.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or args.root.parent.is_symlink()
        or (args.ephemeral_input_root and not parent.st_mode & stat.S_ISVTX)
        or (not args.ephemeral_input_root and parent.st_mode & 0o022)):
        ap.error('protected parent or root-owned sticky scratch parent required')
    if args.root.exists() or sha(args.source / 'guest-inputs.json') != args.source_sha256:
        ap.error('fresh root and external predecessor manifest pin required')
    old = json.loads((args.source / 'guest-inputs.json').read_text())
    image = args.source / 'rootfs.ext4'
    for path in [image, *image.parents]:
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            ap.error('protected source image/parents required')
    if (image.stat().st_mode & 0o777 != 0o444 or not image.is_file() or
        old['authority'] != 'NONE' or old['qualification'] != 'NOT_QUALIFIED' or
        image.stat().st_size != old['rootfs_bytes'] or sha(image) != old['rootfs_sha256']):
        ap.error('source image differs')
    if shutil.disk_usage(args.root.parent).free < image.stat().st_size + 512 * 1024**2:
        ap.error('insufficient fresh-image margin')
    if args.immutable_native and (args.native_submission_binding is not None or args.native_subtask is not None):
        ap.error('immutable image cannot embed per-attempt task inputs')
    native_binding = None
    if args.native_submission_binding is not None:
        import coding_native_client as native
        native_binding = native.worker.parse(args.native_submission_binding.read_bytes())
        native.binding(native_binding)
        scripts = pathlib.Path(__file__).resolve().parent
        if native_binding['worker_sha256'] != sha(scripts / 'coding_worker.py') or \
                native_binding['task_sha256'] != native.worker.digest(native.worker.encoded(native.worker.contract())):
            ap.error('native source/task binding differs')
    args.root.mkdir(mode=0o700)
    args.root.chmod(0o700)
    new = args.root / 'rootfs.ext4'
    shutil.copyfile(image, new)
    new.chmod(0o600)
    scripts = pathlib.Path(__file__).resolve().parent
    init = args.root / 'coding-init'
    subprocess.run(['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(scripts / 'coding_guest_init.c'), '-o', str(init)], check=True)
    init.chmod(0o555)
    challenge = os.urandom(32).hex()
    inputs = args.root / 'controller-input.json'
    controller = {'authority': 'NONE', 'execution_mode': 'host-planned',
                  'model_name': None, 'challenge': challenge, 'raw_handoff_protocol': 'durable-ack-cad-v1'}
    if native_binding is not None:
        controller['native_submission_binding'] = native_binding
    if args.native_subtask is not None:
        if native_binding is None:raise ValueError('native binding required for subtask')
        controller['native_subtask']=native.worker.parse(args.native_subtask.read_bytes())
    if args.immutable_native:controller={'authority':'NONE','execution_mode':'immutable-native-bootstrap'}
    save(inputs, controller)
    archive = args.root / 'previous-controller-bytes'
    archive.mkdir(mode=0o700)
    names = ['coding_guest_boot.py', 'coding_worker.py', 'host_planned_coding.py']
    if native_binding is not None or args.immutable_native:
        names += ['coding_native_client.py', 'candidate_channel_guard.py','coding_task_verifier.py','development_task_oracles.py']
    patches = [('controller/' + name, scripts / name) for name in names]
    patches += [('controller/guest-inputs.json', inputs), ('coding-init', init)]
    for name, source in patches:
        if name in old['files']:
            prior = extract(image, name)
            if hashlib.sha256(prior).hexdigest() != old['files'][name]['sha256']:
                raise ValueError('predecessor embedded bytes differ: ' + name)
            retained = archive / name.replace('/', '-')
            retained.write_bytes(prior)
            subprocess.run(['debugfs', '-w', '-R', 'rm /' + name, str(new)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['debugfs', '-w', '-R', 'write ' + str(source) + ' /' + name, str(new)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        actual = extract(new, name)
        if actual != source.read_bytes():
            raise ValueError('new embedded bytes differ: ' + name)
        old['files'][name] = {'bytes': len(actual), 'sha256': sha(source)}
        mode = '0x816d' if name == 'coding-init' else '0x8124'
        subprocess.run(['debugfs', '-w', '-R', 'set_inode_field /' + name + ' mode ' + mode, str(new)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['tune2fs', '-U', str(uuid.uuid4()), str(new)], check=True, stdout=subprocess.DEVNULL)
    old.pop('model_disk', None)
    old.pop('native_submission_binding', None)
    if native_binding is not None:
        old['native_submission_binding'] = native_binding
    old.update(raw_handoff_protocol='durable-ack-cad-v1', execution_mode='host-planned', model_name=None, memory_mib=512, challenge=challenge,
               init_sha256=sha(init), construction_scope='fresh immutable boot disk; no model disk or VM/RAM state',
               rootfs_sha256=sha(new), scope='external Codex planner, restricted in-guest tools; DEVELOPMENT NONE')
    if args.immutable_native:
        old.update(execution_mode='immutable-native-bootstrap',challenge=None)
        old.pop('native_subtask',None)
    old['construction_derivation'] = {'source_manifest_sha256': args.source_sha256,
        'source_rootfs_sha256': sha(image), 'source_retained': True,
        'helper_sha256': sha(pathlib.Path(__file__)), 'fresh_uuid': True,
        'ephemeral_input_root': args.ephemeral_input_root}
    for name in ['coding_guest_init.c', *names]:
        old['source_files'][name] = sha(scripts / name)
    if sha(image) != old['construction_derivation']['source_rootfs_sha256']:
        raise ValueError('predecessor changed')
    with new.open("rb") as finalized:os.fsync(finalized.fileno())
    new.chmod(0o444)
    if args.immutable_native:
        leaf='rootfs-'+old['rootfs_sha256']+'.ext4'
        new.rename(args.root/leaf)
        old['rootfs_file']=leaf
        old['task_input_protocol']='realm.native-task-inputs/v1'
    save(args.root / 'guest-inputs.json', old)
    directory=os.open(args.root,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)
    print(json.dumps({'authority': 'NONE', 'realm_artifact': None, 'inputs_sha256': sha(args.root / 'guest-inputs.json'),
                      'rootfs_sha256': old['rootfs_sha256'], 'rootfs_bytes': (args.root/old.get('rootfs_file','rootfs.ext4')).stat().st_size,
                      'challenge': challenge, 'memory_mib': old['memory_mib']}))


if __name__ == '__main__':
    main()
