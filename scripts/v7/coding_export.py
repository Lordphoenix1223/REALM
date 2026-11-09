#!/usr/bin/env python3
"""Freeze/check a development coding output. NEVER produces REALM authority.

This bounded JSON export is not a .realm artifact or an authorized host delta.
Caller-supplied pins must come from the trusted operator channel, not from the
received export. Verification executes code only in a fresh child quarantine.
"""
import argparse
import json
import os
import pathlib
import stat
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import coding_worker as worker
import verify_coding_development as independent

MAX_EXPORT = 1024 * 1024


def require(condition, message):
    independent.require(condition, message)


def valid_digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def read(path, limit=MAX_EXPORT):
    return independent.read_regular(path, limit)


def create(path, data):
    with path.open('xb') as f:
        os.chmod(path, 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def freeze(args):
    root = args.agent_root
    require(root.is_absolute() and not root.is_symlink(), 'unlinked absolute agent root required')
    launch = read(root / 'launch.json')
    require(worker.digest(launch) == args.run_id, 'external run/launch identity differs')
    launch_data = independent.parse(launch)
    require(launch_data['authority'] == 'NONE' and
            launch_data['source_files']['coding_worker.py'] == args.worker_sha256,
            'development launch/worker pin differs')
    report = independent.parse(read(root / 'agent-report.json', 32 * MAX_EXPORT))
    require(report['status'] == 'DEVELOPMENT_TASK_CHECKED' and
            report['authority'] == 'NONE' and report['realm_artifact'] is None,
            'autonomous task did not finish; refuse export')
    task = worker.contract()
    audit = independent.audit(root / 'run', task, worker.digest(worker.encoded(task)),
                              args.worker_sha256, args.interpreter_sha256, args.journal_head)
    require(audit['finished'], 'development transcript is unfinished')
    files = []
    for name in worker.FILES:
        path = root / 'run/candidate' / name
        data = read(path, worker.MAX_BYTES)
        mode = stat.S_IMODE(path.lstat().st_mode)
        require(mode == 0o600 and worker.digest(data) == audit['files'][name], 'frozen file differs')
        require(worker.digest(data) != task['baseline'][name], 'all three files must change')
        files.append({'path': name, 'text': data.decode('utf-8'), 'mode': mode})
    body = {'schema': 'realm.coding-development-export.v1', 'authority': 'NONE',
            'realm_artifact': None, 'run_id': args.run_id,
            'task_sha256': worker.digest(worker.encoded(task)),
            'worker_sha256': args.worker_sha256, 'transcript_head': args.journal_head,
            'files': files}
    data = worker.encoded(body)
    require(len(data) <= MAX_EXPORT, 'export size limit')
    create(args.output, data)
    print(json.dumps({'status': 'DEVELOPMENT_OUTPUT_FROZEN', 'authority': 'NONE',
                      'realm_artifact': None, 'run_id': args.run_id,
                      'export_sha256': worker.digest(data), 'files': audit['files']}))


def decode(data, export_pin, run_pin, worker_pin, head_pin):
    require(all(valid_digest(p) for p in (export_pin, run_pin, worker_pin, head_pin)), 'invalid external pin')
    require(len(data) <= MAX_EXPORT and worker.digest(data) == export_pin, 'external export pin differs')
    body = independent.parse(data)
    require(type(body) is dict and set(body) == {'schema', 'authority', 'realm_artifact', 'run_id',
            'task_sha256', 'worker_sha256', 'transcript_head', 'files'}, 'export fields differ')
    require(body['schema'] == 'realm.coding-development-export.v1' and
            body['authority'] == 'NONE' and body['realm_artifact'] is None, 'unsupported authority/schema')
    require(body['run_id'] == run_pin and body['worker_sha256'] == worker_pin and
            body['transcript_head'] == head_pin and
            body['task_sha256'] == worker.digest(worker.encoded(worker.contract())), 'external task/run/source/head differs')
    require(type(body['files']) is list and len(body['files']) == 3, 'exact three-file export required')
    for row, name in zip(body['files'], worker.FILES):
        require(type(row) is dict and set(row) == {'path', 'text', 'mode'}, 'file fields differ')
        require(row['path'] == name and type(row['text']) is str and
                type(row['mode']) is int and row['mode'] == 0o600 and
                len(row['text'].encode('utf-8')) <= worker.MAX_BYTES, 'unsupported path/order/content/mode')
    return body


def matches(code, out, expected):
    try:
        return code == 2 if expected is None else (
            code == 0 and independent.canonical(independent.parse(out)) == independent.canonical(expected)
        )
    except (ValueError, TypeError):
        return False


def verify(args):
    data = read(args.export)
    body = decode(data, args.export_sha256, args.run_id, args.worker_sha256, args.journal_head)
    require(args.root.is_absolute() and not args.root.exists(), 'fresh absolute quarantine root required')
    require(0 <= args.seed < 2**128, 'bounded independent seed required')
    args.root.mkdir(mode=0o700)
    candidate = args.root / 'candidate'
    candidate.mkdir(mode=0o700)
    for row in body['files']:
        create(candidate / row['path'], row['text'].encode('utf-8'))
    sentinel = args.root / 'protected-sentinel'
    create(sentinel, os.urandom(32))
    sandbox = worker.Sandbox(candidate)
    conformance = worker.conformance(sandbox, sentinel)
    cases = []
    # This oracle/corpus implementation is separate from the worker's grading.
    for inputs in independent.cases(args.seed):
        code, out, err = sandbox.run('report.py', worker.encoded(inputs))
        expected = independent.oracle(inputs)
        passed = matches(code, out, expected)
        cases.append({'input': inputs, 'expected': expected, 'exit': code, 'passed': passed,
                      'stdout': out.decode(errors='replace'), 'stderr': err.decode(errors='replace')})
    code, out, err = sandbox.run('test_totals.py', b'')
    # Fresh physical checks after code execution; no saved green flag is an oracle.
    observed = {row['path']: worker.digest(read(candidate / row['path'], worker.MAX_BYTES))
                for row in body['files']}
    require(set(os.listdir(candidate)) == set(worker.FILES), 'candidate set changed during checks')
    require(all(observed[row['path']] == worker.digest(row['text'].encode('utf-8')) and
                stat.S_IMODE((candidate / row['path']).lstat().st_mode) == 0o600
                for row in body['files']), 'candidate bytes/modes changed during checks')
    passed = all(row['passed'] for row in cases) and code == 0
    report = {'status': 'DEVELOPMENT_SEMANTICS_CHECKED' if passed else 'REFUSED',
              'authority': 'NONE', 'realm_artifact': None, 'execution_authenticated': False,
              'containment_qualified': False, 'history_complete': False,
              'scope': 'fresh isolated finite checks of pinned export; no guest/publication/host-apply authority',
              'run_id': args.run_id, 'export_sha256': args.export_sha256,
              'verifier_sha256': worker.digest(pathlib.Path(__file__).read_bytes()),
              'interpreter_sha256': worker.digest(sandbox.python.read_bytes()),
              'seed': args.seed, 'cases': cases, 'candidate_tests': {'exit': code,
              'stdout': out.decode(errors='replace'), 'stderr': err.decode(errors='replace'), 'trusted_oracle': False},
              'conformance': conformance, 'files': observed, 'passed': passed}
    create(args.root / 'semantic-report.json', worker.encoded(report))
    print(json.dumps({'status': report['status'], 'authority': 'NONE', 'passed': passed,
                      'independent_passed': sum(r['passed'] for r in cases), 'independent_total': len(cases)}))
    return 0 if passed else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    f = sub.add_parser('freeze')
    f.add_argument('--agent-root', required=True, type=pathlib.Path)
    f.add_argument('--output', required=True, type=pathlib.Path)
    f.add_argument('--interpreter-sha256', required=True)
    v = sub.add_parser('verify')
    v.add_argument('--export', required=True, type=pathlib.Path)
    v.add_argument('--export-sha256', required=True)
    v.add_argument('--root', required=True, type=pathlib.Path)
    v.add_argument('--seed', required=True, type=int)
    for p in (f, v):
        p.add_argument('--run-id', required=True)
        p.add_argument('--worker-sha256', required=True)
        p.add_argument('--journal-head', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'freeze':
            freeze(args)
            return 0
        return verify(args)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
        print(json.dumps({'status': 'REFUSED', 'authority': 'NONE', 'error': str(exc)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
