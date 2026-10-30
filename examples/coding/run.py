#!/usr/bin/env python3
"""One local execution-bound development chain. No VM or protected application.

The external task pin is mandatory. Candidate code executes only through the
existing Worker sandbox. The archive is derived from ordered captured writes;
all records remain unauthenticated development evidence and authority NONE.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def snapshot(root):
    result = {}
    for p in [root, *sorted(root.rglob('*'))]:
        s = p.lstat()
        result[str(p.relative_to(root))] = [s.st_dev, s.st_ino, s.st_mode, s.st_nlink,
                                          sha(p.read_bytes()) if p.is_file() else None]
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--task', type=Path, default=Path(__file__).with_name('task.json'))
    ap.add_argument('--task-sha256', help='optional independently supplied task pin; bundled example uses its frozen pin')
    ap.add_argument('--actions', type=Path, default=Path(__file__).with_name('actions.json'))
    ap.add_argument('--checker', type=Path, required=True)
    ap.add_argument('--disposable-replay', action='store_true', help='explicit development-only replay into a new child; grants no protected authority')
    a = ap.parse_args()
    source = Path(__file__).resolve().parents[2]
    if os.geteuid() == 0:
        raise ValueError('run as an ordinary user; no root or privilege escalation')
    if a.task_sha256 is None:
        a.task_sha256 = Path(__file__).with_name('task.sha256').read_text().strip()
    if sha(a.task.read_bytes()) != a.task_sha256:
        raise ValueError('external task pin differs')
    task = json.loads(a.task.read_bytes())
    sys.path.insert(0, str(source / 'examples/coding'))
    import coding_worker as worker
    import coding_task_verifier as verifier
    if (worker.contract() != task['contract'] or worker.digest(worker.encoded(worker.contract())) != task['contract_sha256']
        or sha(Path(worker.__file__).read_bytes()) != task['worker_sha256']
        or sha(Path(verifier.__file__).read_bytes()) != task['checker_sha256']
        or sha(encoded(verifier.describe())) != task['checker_scope_sha256']):
        raise ValueError('external task/source baseline differs')
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--', 'Cargo.toml', 'Cargo.lock', 'crates', 'examples/coding', 'realm'], cwd=source)
    if dirty:
        raise ValueError('commit the selected source and task pins before execution')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    root = a.output.resolve()
    root.mkdir(mode=0o700)
    records = []
    stage = 'build'
    child = None

    def run(label, command, expected=0, data=None, env=None):
        nonlocal stage
        stage = label
        r = subprocess.run([str(x) for x in command], input=data, capture_output=True,
                           cwd=source, timeout=180, env=env)
        write(root / (label + '.stdout'), r.stdout)
        write(root / (label + '.stderr'), r.stderr)
        records.append({'stage': label, 'argv': [str(x) for x in command], 'exit': r.returncode})
        if r.returncode != expected:
            raise ValueError(label + ' unexpected exit ' + str(r.returncode))
        return r.stdout

    try:
        realm = a.checker.resolve(strict=True)
        def b3(raw):
            return subprocess.check_output([realm, 'hash-bytes'], input=raw, timeout=5).decode().strip()
        identities = {str(p): sha(p.read_bytes()) for p in [realm, *sorted((source/'examples/coding').glob('*.py')), a.task, a.actions]}
        write(root / 'task.json', a.task.read_bytes())
        write(root / 'contract.json', encoded(task['contract']))
        scope = {'scope': verifier.describe(), 'sha256': task['checker_scope_sha256']}
        write(root / 'referee-scope.json', encoded(scope))
        freeze = {'authority': 'NONE', 'development_only': True, 'task_sha256': task['contract_sha256'],
                  'run_nonce': os.urandom(32).hex(), 'source_commit': commit, 'external_task_sha256': a.task_sha256, 'actions_sha256': sha(a.actions.read_bytes()), 'identities': identities}
        write(root / 'pre-agent-freeze.json', encoded(freeze))
        protected = root / 'protected-destination'
        protected.mkdir(mode=0o700)
        write(protected / 'canary', b'NO DEVELOPMENT EXECUTION AUTHORITY\n')
        before = snapshot(protected)
        write(root / 'protected-before.json', encoded(before))
        command = [sys.executable, '-B', str(source / 'examples/coding/coding_worker.py'), 'serve', '--root', str(root / 'worker'), '--approve', task['contract_sha256']]
        stage = 'agent-tools'
        worker_err = (root / 'worker.stderr').open('xb')
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_err, cwd=source)
        actions = json.loads(a.actions.read_bytes())
        responses = []
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        for action in actions:
            child.stdin.write(encoded(action) + b'\n'); child.stdin.flush()
            if not selector.select(40):
                raise ValueError('worker response timeout')
            result = json.loads(child.stdout.readline())
            responses.append({'action': action, 'response': result})
            if result.get('status') == 'REFUSED' and action != {'tool': 'read', 'path': '../outside.py'}:
                raise ValueError('unexpected worker refusal')
        child.stdin.close()
        code = child.wait(timeout=5)
        selector.close(); worker_err.close()
        if code or responses[-1]['response'].get('status') != 'DEVELOPMENT_TASK_CHECKED':
            raise ValueError('worker did not finish')
        write(root / 'tool-responses.json', encoded(responses))
        journal = (root / 'worker/events.jsonl').read_bytes()
        rows = [json.loads(line) for line in journal.splitlines()]
        interpreter = next(r['event']['result']['interpreter_sha256'] for r in rows if r['event'].get('request', {}).get('tool') == 'check')
        audit_args = [sys.executable, '-B', source / 'examples/coding/verify_coding_development.py', '--root', root / 'worker', '--contract', root / 'contract.json', '--contract-sha256', task['contract_sha256'], '--worker-sha256', task['worker_sha256'], '--interpreter-sha256', interpreter, '--journal-head', rows[-1]['sha256']]
        audit = run('transcript-audit', audit_args)
        run('independent-referee', [sys.executable, '-B', source / 'examples/coding/coding_task_verifier.py', 'check', '--candidate', root / 'worker/candidate', '--output', root / 'referee', '--scope-sha256', task['checker_scope_sha256'], '--seed', '20261028'])
        captured = {}
        for row in rows:
            req = row['event'].get('request', {})
            if req.get('tool') == 'write' and 'refusal' not in row['event']:
                captured[req['path']] = req['text']
        payload = {'schema': 'realm.coding-development-intake.v1', 'run_label': 'vertical-' + sha(encoded(freeze))[:24],
                   'files': [{'path': n, 'text': captured[n], 'mode': 384} for n in worker.FILES],
                   'evidence': {'journal': journal.decode(), 'task_contract': (root/'contract.json').read_text(), 'referee_scope': (root/'referee-scope.json').read_text(), 'pre_agent_freeze': (root/'pre-agent-freeze.json').read_text(), 'referee_result': (root/'referee/result.json').read_text(), 'transcript_audit': audit.decode()}}
        expectations = {'schema': 'realm.coding-development-expectations.v1', 'run_label': payload['run_label'], **{k: task[k] for k in ['worker_sha256', 'checker_sha256', 'checker_scope_sha256']}, 'task_sha256': task['contract_sha256']}
        write(root/'payload.json', encoded(payload)); write(root/'expectations.json', encoded(expectations))
        pp, ep = b3(encoded(payload)), b3(encoded(expectations))
        artifact = root/'capture.realm'
        packed = json.loads(run('pack-capture', [realm, 'pack-development-coding', root/'payload.json', root/'expectations.json', pp, ep, artifact]))
        pin = packed['artifact_blake3']
        decision = json.loads(run('receiver', [realm, 'inspect-development-realm', artifact, pin, root/'expectations.json', ep], expected=3))
        if decision['status'] != 'INCOMPLETE' or decision['authority'] != 'NONE' or decision['application_dispatched'] or decision['destination_access']:
            raise ValueError('receiver granted unqualified authority')
        extracted = json.loads(run('receiver-extract', [realm, 'extract-development-coding', artifact, pin, root/'expectations.json', ep]))
        # Separate auditor consumes bytes extracted from the actual archive, not
        # the producer's original working directory or projection.
        receiver_root = root/'receiver-audit'; receiver_root.mkdir(mode=0o700)
        (receiver_root/'candidate').mkdir(mode=0o700)
        write(receiver_root/'events.jsonl', extracted['evidence']['journal'].encode())
        rebuilt = {}
        for line in extracted['evidence']['journal'].splitlines():
            event = json.loads(line)['event']
            req = event.get('request', {})
            if req.get('tool') == 'write' and 'refusal' not in event: rebuilt[req['path']] = req['text']
        for n in worker.FILES: write(receiver_root/'candidate'/n, rebuilt[n].encode())
        receiver_args = list(audit_args); receiver_args[receiver_args.index('--root')+1] = receiver_root
        run('receiver-independent-audit', receiver_args)
        def trailing(p):
            rows = p['evidence']['journal'].splitlines()
            p['evidence']['journal'] += rows[-1] + '\n'
        def forged(p):
            r = json.loads(p['evidence']['transcript_audit']); r['execution_authenticated'] = True
            p['evidence']['transcript_audit'] = encoded(r).decode()
        controls = [
            ('missing-capture', lambda p: p['evidence'].pop('journal')),
            ('forbidden-effect', lambda p: p['files'][0].update(path='../outside.py')),
            ('projection-substitution', lambda p: p['files'][0].update(text='unobserved replacement')),
            ('trailing-event', trailing), ('forged-authentication', forged)]
        for label, mutate in controls:
            body = json.loads(encoded(payload)); mutate(body); path = root/(label+'.json'); raw=encoded(body);write(path,raw)
            run(label,[realm,'pack-development-coding',path,root/'expectations.json',b3(raw),ep,root/(label+'.realm')],expected=1)
            if (root/(label+'.realm')).exists(): raise ValueError('invalid capture generated artifact')
        bad = bytearray(artifact.read_bytes()); bad[len(bad)//2] ^= 1
        write(root/'tampered.realm',bad)
        run('tampered-artifact',[realm,'inspect-development-realm',root/'tampered.realm',b3(bad),root/'expectations.json',ep],expected=1)
        wrong = dict(expectations,run_label='different-run')
        write(root/'cross-run.json',encoded(wrong))
        run('cross-run',[realm,'inspect-development-realm',artifact,pin,root/'cross-run.json',b3(encoded(wrong))],expected=1)
        run('missing-pin',[realm,'inspect-development-realm',artifact,'0'*64,root/'expectations.json',ep],expected=1)
        disposable = {'status': 'NOT_RUN', 'authority': 'NONE'}
        if a.disposable_replay:
            stage = 'disposable-replay'
            destination = root/'disposable-replay'
            destination.mkdir(mode=0o700)
            fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for name in worker.FILES:
                    raw = rebuilt[name].encode()
                    f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                    with os.fdopen(f, 'wb') as stream:
                        stream.write(raw);stream.flush();os.fsync(stream.fileno())
                os.fsync(fd)
            finally:
                os.close(fd)
            # Fresh process checks actual destination; input hashes came from
            # the independently audited archive reconstruction, not the writer.
            expected = {n: sha(rebuilt[n].encode()) for n in worker.FILES}
            check = ("import pathlib,sys,json,hashlib,stat; p=pathlib.Path(sys.argv[1]); e=json.loads(sys.argv[2]); "
                     "assert set(x.name for x in p.iterdir())==set(e); "
                     "assert all(stat.S_ISREG((p/n).lstat().st_mode) and stat.S_IMODE((p/n).lstat().st_mode)==384 and (p/n).lstat().st_nlink==1 and hashlib.sha256((p/n).read_bytes()).hexdigest()==h for n,h in e.items()); "
                     "print(json.dumps({'status':'PASS_DISPOSABLE_FINAL_STATE','authority':'NONE','files':e}))")
            verified = json.loads(run('disposable-final-state', [sys.executable, '-I', '-B', '-c', check, destination, json.dumps(expected)]))
            disposable = {'status': 'DEVELOPMENT_ONLY_HUMAN_AUTHORIZED', 'authority': 'NONE', 'receiver_authorized': False, 'destination': str(destination), 'final_state': verified}
        if snapshot(protected) != before: raise ValueError('protected destination changed')
        for p, h in identities.items():
            if sha(Path(p).read_bytes()) != h: raise ValueError('executed source/binary changed')
        write(root/'protected-after.json',encoded(snapshot(protected)))
        result={'status':'INCOMPLETE','mechanics':'PASS_EXECUTION_BOUND_DEVELOPMENT_CHAIN','authority':'NONE','source_commit':commit,'task_sha256':a.task_sha256,'fresh_tool_execution':True,'planner':'Codex-generated restricted tool proposals; reproduction replays proposals, no model API','artifact':str(artifact),'artifact_sha256':sha(artifact.read_bytes()),'artifact_blake3':pin,'expectations_blake3':ep,'receiver_decision':decision['status'],'protected_destination_unchanged':True,'application_dispatched':False,'disposable_replay':disposable,'production_qualification':'NOT_RUN','canonical_publication':'NOT_RUN','stages':records}
        write(root/'RESULT.json',json.dumps(result,indent=2).encode()+b'\n')
        print('PASS: fresh bounded tool execution, independent task/transcript checks and artifact reconstruction')
        print('Receiver: INCOMPLETE | authority: NONE | production qualification: NOT_RUN')
        print('Eight invalid/incomplete controls: REFUSED | protected canary: unchanged')
        print('Disposable replay:', disposable['status'])
        print('Artifact:', artifact)
        print('Full evidence:', root/'RESULT.json')
    except BaseException as error:
        if child is not None and child.poll() is None:
            child.kill();child.wait()
        write(root/'FAILURE.json',encoded({'stage':stage,'error':repr(error),'authority':'NONE','records':records}))
        raise

if __name__ == '__main__':
    main()
