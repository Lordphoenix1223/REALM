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
            'functional_oracle_sha256': worker.digest(Path(__file__).with_name('development_task_oracles.py').read_bytes()),
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


def subject(root, required_changed=None):
    if required_changed is None:
        required_changed = set(worker.FILES)
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
            require(data and (name not in required_changed or data != worker.BASELINE[name].encode()), 'required baseline file must change')
            files[name] = {'sha256': worker.digest(data), 'bytes': len(data), 'mode': 0o600}
        return files
    finally:
        os.close(fd)


def decode_packet(raw, expected_binding):
    require(0 < len(raw) <= 128 * 1024, 'bounded native packet required')
    require(type(expected_binding) is dict and set(expected_binding) ==
            {'run_id', 'execution_id', 'challenge_root', 'task_sha256', 'worker_sha256'} and
            all(type(v) is str and len(v) == 64 and all(c in '0123456789abcdef' for c in v)
                for v in expected_binding.values()), 'exact native binding required')
    scope = describe()
    require(expected_binding['task_sha256'] == scope['original_task_sha256'] and
            expected_binding['worker_sha256'] == scope['oracle_worker_sha256'],
            'unsupported original task/worker')
    packet = worker.parse(raw)
    require(type(packet) is dict and set(packet) == {'schema', 'binding', 'transcript_head', 'files'} and
            packet['schema'] == 'realm.coding-submission.v1' and packet['binding'] == expected_binding,
            'packet shape/run differs')
    require(type(packet['transcript_head']) is str and len(packet['transcript_head']) == 64 and
            all(c in '0123456789abcdef' for c in packet['transcript_head']), 'packet head differs')
    require(type(packet['files']) is list and len(packet['files']) == 3, 'three packet files required')
    for file, name in zip(packet['files'], worker.FILES):
        require(type(file) is dict and set(file) == {'path', 'text', 'mode'} and file['path'] == name and
                type(file['text']) is str and type(file['mode']) is int and file['mode'] == 0o600 and
                0 < len(file['text'].encode()) <= worker.MAX_BYTES, 'packet file differs')
    return packet


def candidate_from_packet(raw, expected_binding, root):
    packet = decode_packet(raw, expected_binding)
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    for file in packet['files']:
        with (root / file['path']).open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(file['text'].encode())
    return packet



def owned_request(raw, candidate):
    """Strict native-child input validation, not a native capability issuer.

    The parent materializes and retains the original subject descriptors. This
    check independently compares the actual subject to the submitted packet.
    """
    require(0 < len(raw) <= 1024 * 1024, 'bounded owned request required')
    q = worker.parse(raw)
    require(type(q) is dict and set(q) == {'schema', 'scope', 'binding', 'packet_hex', 'seed'} and
            q['schema'] == 'realm.owned-coding-referee-request.v2', 'owned request shape differs')
    require(type(q['seed']) is int and 0 <= q['seed'] < 2**64, 'u64 seed required')
    text = q['packet_hex']
    require(type(text) is str and 0 < len(text) <= 2 * 128 * 1024 and len(text) % 2 == 0 and
            not set(text) - set('0123456789abcdef'), 'canonical packet hex required')
    scope = q['scope']
    required_scope = {'submission', 'source_commit', 'checker_sha256', 'checker_scope_sha256'}
    require(type(scope) is dict and required_scope <= set(scope) <= required_scope | {'runtime_admission_id', 'native_subtask','task_inputs_blake3'} and
            scope['submission'] == q['binding'], 'prelaunch scope/run differs')
    if 'task_inputs_blake3' in scope:
        value=scope['task_inputs_blake3']
        require(type(value) is str and len(value)==64 and not set(value)-set('0123456789abcdef') and scope.get('native_subtask') is not None,'registered task input commitment required')
    if 'runtime_admission_id' in scope:
        admission = scope['runtime_admission_id']
        require(type(admission) is str and len(admission) == 64 and
                not set(admission) - set('0123456789abcdef'), 'canonical runtime admission identity required')
    # This optional native prelaunch commitment remains in the exact consumed
    # request. Accepting its shape does not authenticate or issue admission.
    source = scope['source_commit']
    require(type(source) is str and len(source) == 40 and
            not set(source) - set('0123456789abcdef'), 'source commit required')
    step = scope.get('native_subtask')
    if step is not None:
        require(type(step) is dict and set(step)=={'workflow','role','attempt','history_prefix_blake3','predecessor'}
                and step['role'] in ('api','cli'), 'registered native subtask shape required')
    actual_scope = native_api_scope() if step and step['role']=='api' else describe()
    require(scope['checker_sha256'] == actual_scope['checker_sha256'] and
            scope['checker_scope_sha256'] == worker.digest(worker.encoded(actual_scope)),
            'prelaunch checker/source scope differs')
    packet = decode_packet(bytes.fromhex(text), q['binding'])
    if step and step['role']=='cli':
        previous=step.get('predecessor')
        require(type(previous) is dict,'native CLI predecessor missing')
        prior=decode_packet(bytes.fromhex(previous['packet_hex']),previous['submission'])
        require(packet['files'][0]==prior['files'][0], 'native CLI changed its original API predecessor')
    expected = {f['path']: {'sha256': worker.digest(f['text'].encode()),
                           'bytes': len(f['text'].encode()), 'mode': f['mode']}
                for f in packet['files']}
    require(subject(candidate, {'totals.py','test_totals.py'} if step and step['role']=='api' else None) == expected,
            'subject differs from original packet')
    return q


def api_checks(sandbox, cases, *, strict_value_error=False):
    cwd = str(sandbox.candidate) if sandbox.backend == 'Darwin' else '/work'
    wrapper = ("import sys,json;sys.path.insert(0," + repr(cwd) + ");from totals import summarize;"
               "x=json.load(sys.stdin)\ntry:\n r=summarize(x); print(json.dumps({'value':r}))\n"
               "except Exception:\n print(json.dumps({'raised':True}))\n")
    if strict_value_error:
        wrapper = wrapper.replace("except Exception:\n print(json.dumps({'raised':True}))",
                                  "except ValueError:\n print(json.dumps({'raised':True}))\nexcept Exception as e:\n print(json.dumps({'wrong_exception':type(e).__name__}))")
    api = []
    for case in cases:
        code, out, err = sandbox.execute(wrapper, worker.encoded(case['input']))
        reference = worker.expected(case['input'])
        expected = ({'raised': True} if reference is None else
                    {'value': reference} if worker.DEVELOPMENT_TASK is not None and 'kind' in worker.DEVELOPMENT_TASK else
                    {'value': {r['category']: r['amount'] for r in reference['totals']}})
        try:
            passed = code == 0 and worker.encoded(worker.parse(out)) == worker.encoded(expected)
        except (ValueError, TypeError):
            passed = False
        api.append({'input': case['input'], 'expected': expected, 'passed': passed, 'exit': code,
                    'stdout': out.decode(errors='replace'), 'stderr': err.decode(errors='replace')})
    return api


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
    api = api_checks(sandbox, report['independent_cases'])
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


def api_scope():
    scope = describe()
    scope['development_subtask'] = 'api-only'
    scope['obligations'] = ['totals-and-tests-change', 'report-baseline-unchanged',
                            'api-fixed-cases-exact-ValueError', 'tests-pass-and-reject-baseline',
                            'sandbox-conformance', 'subject-unchanged']
    return scope


def native_api_scope():
    require(worker.DEVELOPMENT_TASK is None, 'native API supports only the original registered totals task')
    scope = describe()
    scope['native_subtask'] = 'api'
    scope['max_packet_bytes']=16384
    scope['obligations'] = ['totals-and-tests-change', 'report-baseline-unchanged',
                            'api-original-fixed-and-seeded-cases-exact-ValueError',
                            'tests-pass-and-reject-baseline', 'sandbox-conformance', 'subject-unchanged']
    return scope


def verify_native_api(candidate, output, scope_pin, seed, *, packet_bytes=None):
    return _verify_api(candidate,output,scope_pin,seed,native=True,packet_bytes=packet_bytes)


def verify_api(candidate, output, scope_pin, seed):
    return _verify_api(candidate,output,scope_pin,seed,native=False)


def _verify_api(candidate, output, scope_pin, seed, *, native,packet_bytes=None):
    # An API result never establishes complete CLI/task semantics.
    scope = native_api_scope() if native else api_scope()
    require(worker.DEVELOPMENT_TASK is None if native else worker.DEVELOPMENT_TASK is not None and
            worker.DEVELOPMENT_TASK.get('kind') == 'unicode-runs', 'supported API subtask required')
    require(scope_pin == worker.digest(worker.encoded(scope)), 'API scope differs')
    before = subject(candidate, {'totals.py', 'test_totals.py'})
    require((candidate/'report.py').read_text() == worker.BASELINE['report.py'], 'API task changed CLI')
    output.mkdir(mode=0o700)
    sentinel = output/'protected-sentinel'; sentinel.write_bytes(secrets.token_bytes(32)); sentinel.chmod(0o600)
    guard = platform.system() == 'Linux'
    sandbox = worker.Sandbox(candidate, evidence_channel_guard=guard)
    conformance = worker.conformance(sandbox, sentinel)
    api = api_checks(sandbox, [{'input': x} for x in (worker.check_cases(seed) if native else worker.DEVELOPMENT_TASK['acceptance_inputs'])], strict_value_error=True)
    code, out, err = sandbox.run('test_totals.py', b'')
    mutant = output/'frozen-baseline-mutant'; mutant.mkdir(mode=0o700)
    for name in worker.FILES:
        raw = worker.BASELINE[name].encode() if name == 'totals.py' else (candidate/name).read_bytes()
        with (mutant/name).open('xb') as f:
            os.fchmod(f.fileno(), 0o600); f.write(raw)
    mcode, mout, merr = worker.Sandbox(mutant, evidence_channel_guard=guard).run('test_totals.py', b'')
    after = subject(candidate, {'totals.py', 'test_totals.py'})
    passed = all(x['passed'] for x in api) and code == 0 and mcode > 0 and before == after
    if native and packet_bytes is not None:
        passed = passed and type(packet_bytes) is int and 0 < packet_bytes <= 16384
    result = {'schema': 'realm.native-api-subtask-result.v1' if native else 'realm.development-api-subtask-result.v1', 'authority': 'NONE',
              'scope': scope, 'scope_sha256': scope_pin, 'subject': before,
              'api_driver_checks': api, 'sandbox_conformance': conformance,
              'candidate_tests': {'exit': code, 'stdout': out.decode(errors='replace'), 'stderr': err.decode(errors='replace')},
              'baseline_discrimination': {'exit': mcode, 'passed': mcode > 0,
                                           'stdout': mout.decode(errors='replace'), 'stderr': merr.decode(errors='replace')},
              'subject_unchanged': before == after, 'report_checks': 'NOT_RUN_API_ONLY',
              'status': 'PASS_API_SUBTASK' if passed else 'REFUSE_API_SUBTASK'}
    if native:
        result.update(seed=seed, realm_artifact=None, same_run_native_join='NOT_ESTABLISHED')
    with (output/'result.json').open('xb') as f:
        os.fchmod(f.fileno(), 0o600); f.write(worker.encoded(result)); f.flush(); os.fsync(f.fileno())
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['describe', 'check', 'check-api'])
    p.add_argument('--candidate', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--scope-sha256')
    p.add_argument('--seed', type=int)
    p.add_argument('--development-task', type=Path)
    p.add_argument('--development-task-sha256')
    args = p.parse_args()
    if args.development_task is not None:
        worker.configure_development_task(args.development_task, args.development_task_sha256)
    elif args.development_task_sha256 is not None:
        p.error('task definition and pin required together')
    if args.command == 'describe':
        scope = describe(); print(json.dumps({'scope': scope, 'sha256': worker.digest(worker.encoded(scope))})); return
    require(args.candidate is not None and args.output is not None and args.scope_sha256 is not None,
            'candidate/output/independent scope pin required')
    check = verify_api if args.command == 'check-api' else verify
    result = check(args.candidate, args.output, args.scope_sha256,
                    secrets.randbits(128) if args.seed is None else args.seed)
    print(json.dumps({'status': result['status'], 'authority': 'NONE', 'result': str(args.output / 'result.json')}))
    if result['status'] not in ('PASS_BOUNDED_PROPERTIES', 'PASS_API_SUBTASK'):
        raise SystemExit(2)


if __name__ == '__main__':
    main()
