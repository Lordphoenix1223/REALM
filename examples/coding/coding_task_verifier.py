#!/usr/bin/env python3
"""Independent bounded coding referee; no execution/publication authority.

The producer must pin describe() BEFORE a future execution, and bind the actual
native-owned checker child to that run. A standalone result cannot supply that
missing capability. Hidden planner inputs, full guest history and universal
natural-language/Python correctness are outside these observed properties.
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import secrets
import stat
import sys

import coding_worker as worker
import candidate_channel_guard as channel_guard

EXCLUDED = ['complete-planner-inputs', 'complete-guest-syscall-history',
            'guest-process-count', 'causal-reuse', 'universal-python-correctness']


def describe():
    return {'schema': 'realm.coding-task-referee-scope.v1',
            'original_task_sha256': worker.digest(worker.encoded(worker.contract())),
            'checker_sha256': worker.digest(Path(__file__).read_bytes()),
            'oracle_worker_sha256': worker.digest(Path(worker.__file__).read_bytes()),
            'candidate_channel_guard_sha256': worker.digest(Path(channel_guard.__file__).read_bytes()),
            'linux_candidate_channel_policy': channel_guard.POLICY,
            'paths': list(worker.FILES), 'mode': 0o600, 'max_file_bytes': worker.MAX_BYTES,
            'obligations': ['all-three-original-files-change', 'exact-files-and-metadata',
                            'report-driver-fixed-and-seeded-cases', 'summarize-api-driver-same-cases',
                            'candidate-tests-exit-zero', 'candidate-tests-reject-frozen-totals-baseline',
                            'independent-sandbox-conformance', 'subject-unchanged-after-checks'],
            'excluded_claims': EXCLUDED, 'authority': 'NONE'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def subject(root):
    require(root.is_dir() and not root.is_symlink(), 'regular candidate directory required')
    directory = root.lstat()
    require(directory.st_uid == os.getuid() and stat.S_IMODE(directory.st_mode) == 0o700,
            'private checker subject directory required')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(set(os.listdir(fd)) == set(worker.FILES), 'exact three-file subject required')
        files = {}
        for name in worker.FILES:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                    'candidate regular mode0600 files required')
            data = worker.regular_read(fd, name)
            require(data and data != worker.BASELINE[name].encode(), 'all three baseline files must change')
            files[name] = {'sha256': worker.digest(data), 'bytes': len(data), 'mode': 0o600}
        return files
    finally:
        os.close(fd)


def verify(candidate, output, scope_pin, seed):
    scope = describe()
    require(scope_pin == worker.digest(worker.encoded(scope)), 'independent checker scope pin differs')
    require(type(seed) is int and 0 <= seed < 2**128, 'bounded independent seed required')
    before = subject(candidate)
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    sentinel = output / 'protected-sentinel'
    sentinel.write_bytes(secrets.token_bytes(32)); sentinel.chmod(0o600)
    guard = platform.system() == 'Linux'
    sandbox = worker.Sandbox(candidate, evidence_channel_guard=guard)
    conformance = worker.conformance(sandbox, sentinel)
    report = worker.check(sandbox, seed)
    # Only untrusted candidate code executes in this child. Oracle decisions
    # stay outside it; no candidate PASS flag is trusted. These are bounded
    # process-driver observations, not a theorem about every Python caller.
    cwd = str(sandbox.candidate) if sandbox.backend == 'Darwin' else '/work'
    wrapper = ("import sys,json;sys.path.insert(0," + repr(cwd) + ");from totals import summarize;"
               "x=json.load(sys.stdin)\ntry:\n r=summarize(x); print(json.dumps({'value':r}))\n"
               "except Exception:\n print(json.dumps({'raised':True}))\n")
    api = []
    for case in report['independent_cases']:
        code, out, err = sandbox.execute(wrapper, worker.encoded(case['input']))
        reference = worker.expected(case['input'])
        expected = ({'raised': True} if reference is None else
                    {'value': {r['category']: r['amount'] for r in reference['totals']}})
        try:
            passed = code == 0 and worker.encoded(worker.parse(out)) == worker.encoded(expected)
        except (ValueError, TypeError):
            passed = False
        api.append({'input': case['input'], 'expected': expected, 'passed': passed, 'exit': code,
                    'stdout': out.decode(errors='replace'), 'stderr': err.decode(errors='replace')})
    mutant = output / 'frozen-baseline-mutant'; mutant.mkdir(mode=0o700); mutant.chmod(0o700)
    for name in worker.FILES:
        data = worker.BASELINE[name].encode() if name == 'totals.py' else (candidate / name).read_bytes()
        with (mutant / name).open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600); stream.write(data)
    mutant_code, mutant_out, mutant_err = worker.Sandbox(mutant, evidence_channel_guard=guard).run('test_totals.py', b'')
    after = subject(candidate)
    passed = (report['passed'] and all(row['passed'] for row in api) and
              mutant_code > 0 and before == after)
    result = {'schema': 'realm.coding-task-referee-result.v1', 'authority': 'NONE', 'realm_artifact': None,
              'scope': scope, 'scope_sha256': scope_pin, 'seed': seed, 'subject': before,
              'sandbox': sandbox.profile, 'interpreter_sha256': worker.digest(sandbox.python.read_bytes()),
              'sandbox_conformance': conformance, 'report_checks': report, 'api_driver_checks': api,
              'baseline_discrimination': {'exit': mutant_code, 'stdout': mutant_out.decode(errors='replace'),
                                          'stderr': mutant_err.decode(errors='replace'),
                                          'passed': mutant_code > 0, 'scope': 'bounded mutation predicate; no universal test-quality claim'},
              'subject_unchanged': before == after, 'same_run_native_join': 'NOT_ESTABLISHED',
              'status': 'PASS_BOUNDED_PROPERTIES' if passed else 'REFUSE_BOUNDED_PROPERTIES'}
    with (output / 'result.json').open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(worker.encoded(result)); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['describe', 'check'])
    p.add_argument('--candidate', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--scope-sha256')
    p.add_argument('--seed', type=int)
    args = p.parse_args()
    if args.command == 'describe':
        scope = describe(); print(json.dumps({'scope': scope, 'sha256': worker.digest(worker.encoded(scope))})); return
    require(args.candidate is not None and args.output is not None and args.scope_sha256 is not None,
            'candidate/output/independent scope pin required')
    result = verify(args.candidate, args.output, args.scope_sha256,
                    secrets.randbits(128) if args.seed is None else args.seed)
    print(json.dumps({'status': result['status'], 'authority': 'NONE', 'result': str(args.output / 'result.json')}))
    if result['status'] != 'PASS_BOUNDED_PROPERTIES':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
