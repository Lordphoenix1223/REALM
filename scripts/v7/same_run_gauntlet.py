#!/usr/bin/env python3
"""Negative observation-completeness campaign over the real development worker.

Two actual controller processes inherit different FDs/configuration and perform
unrecorded positive/negative/alias reads, while producing byte-identical recorded
tools and final files. This never runs a VM/model or issues a production artifact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import coding_worker as worker
from verify_coding_development import audit


def save(path, value):
    path.write_bytes(worker.encoded(value) + b'\n')
    path.chmod(0o600)


def child(root, inherited):
    root.mkdir(mode=0o700)
    secret = os.read(inherited, 64)
    os.close(inherited)
    (root / 'external-policy').write_bytes(secret)
    if secret == b'deny':
        (root / 'unrecorded-future-input').write_bytes(b'present')
    w = worker.Worker(root / 'run', worker.digest(worker.encoded(worker.contract())))
    try:
        w.request({'tool': 'list'})
        # Real unrecorded observations/effects. All aliases are removed before
        # the next tool, so every recorded before/after state still matches.
        symlink = w.candidate / '.unrecorded-symlink'
        symlink.symlink_to(root / 'external-policy')
        positive = symlink.read_bytes()
        symlink.unlink()
        hardlink = w.candidate / '.unrecorded-hardlink'
        os.link(root / 'external-policy', hardlink)
        alias = hardlink.read_bytes()
        hardlink.unlink()
        negative = not (root / 'unrecorded-future-input').exists()
        config = os.environ['REALM_GAUNTLET_EXTERNAL_PLANNER']
        observed_clock = time.time_ns()
        next_decision = 'publish' if positive == alias == secret == b'allow' and negative and config == 'allow' else 'refuse'
        w.request({'tool': 'read', 'path': 'totals.py'})
        w.request({'tool': 'write', 'path': 'report.py', 'text': '# apparently identical final output\n'})
        w.request({'tool': 'read', 'path': 'report.py'})
        truth = {'authority': 'NONE', 'inherited_fd_input': secret.decode(), 'unrecorded_positive_read': positive.decode(),
                 'unrecorded_alias_read': alias.decode(), 'unrecorded_negative_read': negative,
                 'external_planner_configuration': config, 'unrecorded_clock_ns': observed_clock,
                 'decision_relevant_next_action': next_decision}
        save(root / 'outside-journal-witness.json', truth)
    finally:
        w.close()


def cold(root, *, task_pin=None, source_pin=None):
    raw = (root / 'events.jsonl').read_bytes()
    head = json.loads(raw.splitlines()[-1])['sha256']
    return audit(root, worker.contract(), task_pin or worker.digest(worker.encoded(worker.contract())),
                 source_pin or worker.digest(Path(worker.__file__).read_bytes()), '0' * 64, head)


def campaign(output, realm):
    output = output.absolute()
    output.mkdir(mode=0o700)  # Refuse reuse; retain all raw negative evidence.
    rows = []
    for name, observation in [('history-a', 'allow'), ('history-b', 'deny')]:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, observation.encode())
            os.close(write_fd)
            write_fd = None
            env = dict(os.environ, REALM_GAUNTLET_EXTERNAL_PLANNER=observation)
            command = [sys.executable, str(Path(__file__).resolve()), '--child', str(output / name), '--inherited-fd', str(read_fd)]
            process = subprocess.run(command, pass_fds=(read_fd,), env=env, capture_output=True, timeout=30)
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
        (output / f'{name}.stdout').write_bytes(process.stdout)
        (output / f'{name}.stderr').write_bytes(process.stderr)
        if process.returncode:
            raise RuntimeError(f'child {name} failed: {process.stderr.decode(errors="replace")}')
        run = output / name / 'run'
        checked = cold(run)
        save(output / name / 'cold-audit.json', checked)
        # Public admission CLI must refuse this valid but non-authorizing cold
        # audit. It cannot deserialize a report into native opaque capabilities.
        args = [str(realm), 'artifact', 'coding-admission', str(output / name / 'cold-audit.json')]
        gate = subprocess.run(args, capture_output=True, timeout=30)
        (output / f'{name}.admission.stdout').write_bytes(gate.stdout)
        (output / f'{name}.admission.stderr').write_bytes(gate.stderr)
        report = json.loads(gate.stdout)
        assert gate.returncode != 0 and report['authority'] == 'NONE' and report['admission'] == 'REFUSE'
        assert not checked['history_complete'] and not checked['execution_authenticated']
        rows.append({'history': name, 'child_exit': process.returncode, 'admission_exit': gate.returncode,
                     'admission_argv': args, 'journal_sha256': worker.digest((run / 'events.jsonl').read_bytes()),
                     'final_files': checked['files'], 'next_decision': json.loads((output / name / 'outside-journal-witness.json').read_bytes())['decision_relevant_next_action']})
    a, b = (output / name / 'run' for name in ('history-a', 'history-b'))
    assert (a / 'events.jsonl').read_bytes() == (b / 'events.jsonl').read_bytes()
    assert rows[0]['final_files'] == rows[1]['final_files']
    assert rows[0]['next_decision'] != rows[1]['next_decision']
    assert cold(a) == cold(b)
    negatives = []
    for attack in ['wrong-task', 'stale-worker', 'journal-tampering', 'missing-intermediate-effect', 'altered-final-file', 'symlink-alias', 'hardlink-alias']:
        clone = output / f'attack-{attack}'
        shutil.copytree(a, clone)
        kwargs = {}
        if attack == 'wrong-task':
            kwargs['task_pin'] = 'f' * 64
        elif attack == 'stale-worker':
            kwargs['source_pin'] = 'e' * 64
        elif attack == 'journal-tampering':
            raw = (clone / 'events.jsonl').read_bytes()
            (clone / 'events.jsonl').write_bytes(raw.replace(b'"list"', b'"read"', 1))
        elif attack == 'missing-intermediate-effect':
            lines = (clone / 'events.jsonl').read_bytes().splitlines(keepends=True)
            (clone / 'events.jsonl').write_bytes(b''.join(lines[:3] + lines[4:]))
        elif attack == 'altered-final-file':
            (clone / 'candidate/report.py').write_bytes(b'changed')
        else:
            target = clone / 'candidate/report.py'
            content = target.read_bytes()
            target.unlink()
            outside = clone / 'same-bytes-outside'
            outside.write_bytes(content)
            if attack == 'symlink-alias':
                target.symlink_to(outside)
            else:
                os.link(outside, target)
        try:
            cold(clone, **kwargs)
        except (ValueError, OSError, KeyError, TypeError) as error:
            negatives.append({'attack': attack, 'status': 'REFUSE', 'error': str(error)})
        else:
            raise AssertionError(f'{attack} unexpectedly accepted')
    summary = {'schema': 'realm.same-run-two-history-gauntlet.v1', 'authority': 'NONE',
               'evidence_class': 'REAL_LOCAL_NEGATIVE_OBSERVATION_COMPLETENESS',
               'native_vm_execution': 'NOT_RUN', 'production_artifact': None,
               'byte_identical_recorded_journals': True, 'identical_final_files': True,
               'different_unrecorded_observations_and_decisions': True, 'histories': rows,
               'negative_controls': negatives,
               'source_sha256': {str(Path(p).name): hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in [__file__, worker.__file__]}}
    save(output / 'campaign.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--realm', type=Path)
    parser.add_argument('--child', type=Path)
    parser.add_argument('--inherited-fd', type=int)
    args = parser.parse_args()
    if args.child is not None:
        child(args.child, args.inherited_fd)
    else:
        if not args.output or not args.realm or not args.realm.is_absolute():
            parser.error('--output FRESH_DIR --realm ABSOLUTE_REALM_BINARY required')
        print(json.dumps(campaign(args.output, args.realm), indent=2))


if __name__ == '__main__':
    main()
