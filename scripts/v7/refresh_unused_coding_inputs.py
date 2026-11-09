#!/usr/bin/env python3
"""Replace fixed controller inputs in an UNUSED development image.

The old image must never have executed or qualified. Its manifest and old
controller bytes are retained, but the disposable image itself is moved and
changed. A fresh input identity/challenge is required before any guest run.
Never use this on a qualified profile, accepted artifact or executed capsule.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess

from build_coding_guest import sha, save
from fetch_offline_coder import assets_for

FILES = ('offline_coding_agent.py', 'coding_worker.py', 'fetch_offline_coder.py', 'coding_guest_boot.py')


def cat(image, name):
    return subprocess.check_output(['debugfs', '-R', 'cat /controller/' + name, str(image)],
                                   stderr=subprocess.DEVNULL)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--unused-inputs', required=True, type=pathlib.Path)
    p.add_argument('--inputs-sha256', required=True)
    p.add_argument('--root', required=True, type=pathlib.Path)
    p.add_argument('--attest-unused', action='store_true', required=True)
    args = p.parse_args()
    original = args.unused_inputs
    if sha(original / 'guest-inputs.json') != args.inputs_sha256:
        raise ValueError('external unused input manifest pin differs')
    report = json.loads((original / 'guest-inputs.json').read_text())
    if report['authority'] != 'NONE' or report['qualification'] != 'NOT_QUALIFIED':
        raise ValueError('refuse qualified/authorizing inputs')
    if sha(original / 'rootfs.ext4') != report['rootfs_sha256']:
        raise ValueError('unused image differs')
    if not args.root.is_absolute() or args.root.exists():
        raise ValueError('fresh absolute replacement input root required')
    args.root.mkdir(mode=0o700)
    archived = original / 'unused-controller-bytes'
    archived.mkdir(mode=0o700)
    for name in FILES:
        data = cat(original / 'rootfs.ext4', name)
        if hashlib.sha256(data).hexdigest() != report['files']['controller/' + name]['sha256']:
            raise ValueError('old controller input differs')
        with (archived / name).open('xb') as f:
            f.write(data)
    # This is explicitly disposal of an unexecuted preparation candidate.
    image = args.root / 'rootfs.ext4'
    os.rename(original / 'rootfs.ext4', image)
    shutil.copyfile(original / 'coding-init', args.root / 'coding-init')
    scripts = pathlib.Path(__file__).resolve().parent
    replacements = []
    for name in FILES:
        source = scripts / name
        subprocess.run(['debugfs', '-w', '-R', 'rm /controller/' + name, str(image)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['debugfs', '-w', '-R', 'write ' + str(source) + ' /controller/' + name, str(image)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        data = cat(image, name)
        if data != source.read_bytes():
            raise ValueError('replacement controller differs')
        report['source_files'][name] = sha(source)
        report['files']['controller/' + name] = {'sha256': sha(source), 'bytes': len(data)}
        replacements.append(name)
    report['challenge'] = os.urandom(32).hex()
    spec = args.root / 'controller-input.json'
    save(spec, {'authority': 'NONE', 'model_name': report['model_name'], 'challenge': report['challenge']})
    subprocess.run(['debugfs', '-w', '-R', 'rm /controller/guest-inputs.json', str(image)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['debugfs', '-w', '-R', 'write ' + str(spec) + ' /controller/guest-inputs.json', str(image)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if cat(image, 'guest-inputs.json') != spec.read_bytes():
        raise ValueError('fresh controller challenge differs')
    report['files']['controller/guest-inputs.json'] = {'sha256': sha(spec), 'bytes': spec.stat().st_size}
    # Independently stream the model back from the updated image. No model-sized
    # extraction or second staging copy is created.
    model = assets_for(report['model_name'])[0]
    process = subprocess.Popen(['debugfs', '-R', 'cat /assets/' + model['name'], str(image)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    h, count = hashlib.sha256(), 0
    with process.stdout:
        while part := process.stdout.read(1024 * 1024):
            count += len(part)
            h.update(part)
    if process.wait() or count != model['bytes'] or h.hexdigest() != model['sha256']:
        raise ValueError('model bytes changed during refresh')
    report['construction_refresh'] = {'previous_inputs_sha256': args.inputs_sha256,
        'previous_image_sha256': report['rootfs_sha256'], 'previous_image_retained': False,
        'previous_candidate_status': 'UNUSED_NOT_RUN', 'replacement_sources': replacements,
        'refresh_sha256': sha(pathlib.Path(__file__)), 'model_reopened_sha256': h.hexdigest()}
    report['rootfs_sha256'] = sha(image)
    save(args.root / 'guest-inputs.json', report)
    save(original / 'unused-preparation-disposition.json', report['construction_refresh'])
    print(json.dumps({'status': 'UNUSED_INPUTS_REPLACED', 'authority': 'NONE',
                      'rootfs_sha256': report['rootfs_sha256'], 'inputs_sha256': sha(args.root / 'guest-inputs.json')}))


if __name__ == '__main__':
    main()
