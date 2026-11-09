#!/usr/bin/env python3
"""Existing execution-bound development controller; no qualified VM or authority.

The external task pin is mandatory. Candidate code executes only through the
existing Worker sandbox. The archive is derived from ordered captured writes;
all records remain unauthenticated development evidence and authority NONE.
"""
import argparse
import hashlib
import json
import os
import platform
import resource
import time
from types import SimpleNamespace
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
    ap.add_argument('--task', type=Path)
    ap.add_argument('--task-sha256')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--actions', type=Path)
    mode.add_argument('--live-agent', action='store_true', help='accept freshly generated JSON tool actions on stdin and emit actual responses')
    mode.add_argument('--codex-agent', action='store_true', help='fresh supported Codex CLI generation after freeze; existing ChatGPT login only')
    ap.add_argument('--request')
    ap.add_argument('--approve-disposable', action='store_true')
    ap.add_argument('--successful-procedure', type=Path)
    ap.add_argument('--successful-procedure-pin')
    ap.add_argument('--development-executor', action='store_true')
    ap.add_argument('--planner-timeout', type=int, default=180)
    ap.add_argument('--development-task', type=Path)
    ap.add_argument('--development-task-sha256')
    ap.add_argument('--target', type=Path, required=True)
    ap.add_argument('--session-api', action='store_true', help='use the explicitly unqualified Stage2/3 local session; no VM fallback')
    ap.add_argument('--disposable-replay', action='store_true', help='explicit development-only replay into a new child; grants no protected authority')
    ap.add_argument('--verify-integrated-interfaces', action='store_true', help='exercise actual native-driver/CLI refusal and installed-policy CLI; never launches a guest')
    a = ap.parse_args()
    if not 1 <= a.planner_timeout <= 180:
        ap.error('planner timeout must be 1..180 seconds')
    if a.request is not None:
        if not a.approve_disposable or a.task or a.actions or a.codex_agent or a.live_agent:
            ap.error('project request requires --approve-disposable and no manual task/actions')
        from development_project import run_project
        project_result = run_project(a)
        print(json.dumps(project_result, indent=2))
        if not project_result["development_completed"]:
            raise SystemExit(2)
        return
    if a.task is None or a.task_sha256 is None or not (a.actions or a.live_agent or a.codex_agent):
        ap.error('explicit task/pin and an action source required')
    start = time.monotonic()
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    generated = a.live_agent or a.codex_agent
    source = Path(__file__).resolve().parents[2]
    if sha(a.task.read_bytes()) != a.task_sha256:
        raise ValueError('external task pin differs')
    task = json.loads(a.task.read_bytes())
    sys.path.insert(0, str(source / 'scripts/v7'))
    import coding_worker as worker
    import coding_task_verifier as verifier
    if a.development_task is not None:
        worker.configure_development_task(a.development_task, a.development_task_sha256)
    elif a.development_task_sha256 is not None:
        ap.error("task definition and pin required together")
    if (worker.contract() != task['contract'] or worker.digest(worker.encoded(worker.contract())) != task['contract_sha256']
        or sha(Path(worker.__file__).read_bytes()) != task['worker_sha256']
        or sha(Path(verifier.__file__).read_bytes()) != task['checker_sha256']
        or sha(encoded(verifier.describe())) != task['checker_scope_sha256']):
        raise ValueError('external task/source baseline differs')
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--', 'Cargo.toml', 'Cargo.lock', 'crates', 'scripts'], cwd=source)
    if dirty:
        raise ValueError('freeze source before execution')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    root = a.output.resolve()
    root.mkdir(mode=0o700)
    records = []
    stage = 'build'
    child = None
    session = None
    worker_root = root / ('session/worker' if a.session_api else 'worker')

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
        env = dict(os.environ, CARGO_TARGET_DIR=str(a.target.resolve()), CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0')
        run('build', ['cargo', 'build', '--offline', '--locked', '-p', 'realm-cli'] + (['--features', 'development-executor'] if a.development_executor else []), env=env)
        realm = a.target.resolve() / 'debug/realm'
        libs = list((a.target.resolve() / 'debug/deps').glob('libblake3-*.rlib'))
        if len(libs) != 1:
            raise ValueError('ambiguous hash helper dependency')
        hasher = root / 'hash-helper'
        run('build-hasher', ['rustc', '--edition=2024', source / 'scripts/v6/runtime_recovery_blake3.rs', '--extern', 'blake3=' + str(libs[0]), '-L', 'dependency=' + str(libs[0].parent), '-o', hasher])
        def b3(raw):
            return subprocess.check_output([hasher], input=raw, timeout=5).decode().strip()
        identities = {str(p): sha(p.read_bytes()) for p in [realm, hasher, Path(__file__), source / 'scripts/v7/verify_coding_development.py', source / 'scripts/v7/development_task_oracles.py', source / 'scripts/v7/live_codex_planner.py', Path(worker.__file__), Path(verifier.__file__)]}
        if a.development_task is not None:
            identities[str(a.development_task.resolve())] = a.development_task_sha256
        write(root / 'task.json', a.task.read_bytes())
        write(root / 'contract.json', encoded(task['contract']))
        scope = {'scope': verifier.describe(), 'sha256': task['checker_scope_sha256']}
        write(root / 'referee-scope.json', encoded(scope))
        freeze = {'authority': 'NONE', 'development_only': True, 'task_sha256': task['contract_sha256'],
                  'run_nonce': os.urandom(32).hex(), 'source_commit': commit, 'external_task_sha256': a.task_sha256, 'planner_mode': 'FRESH_CODEX_CLI' if a.codex_agent else 'LIVE_EXTERNAL_CODEX' if a.live_agent else 'RECORDED_PROPOSALS', 'actions_sha256': None if generated else sha(a.actions.read_bytes()), 'identities': identities}
        if a.successful_procedure is not None:
            proc = a.successful_procedure.read_bytes()
            if b3(proc) != a.successful_procedure_pin:
                raise ValueError('external successful procedure pin differs')
            freeze['successful_procedure'] = proc.decode()
            freeze['planner_mode'] = 'CURRENT_RUN_SUCCESSFUL_PROCEDURE_EXECUTION'
        elif a.successful_procedure_pin is not None:
            raise ValueError('procedure and pin required together')
        if a.session_api:
            freeze['session_profile'] = 'development-kernel-child'
            freeze['session_source_sha256'] = {name: sha((source/'scripts/v7'/name).read_bytes())
                for name in ('vm_session.py', 'vm_session_host.py')}
        write(root / 'pre-agent-freeze.json', encoded(freeze))
        protected = root / 'protected-destination'
        protected.mkdir(mode=0o700)
        write(protected / 'canary', b'NO DEVELOPMENT EXECUTION AUTHORITY\n')
        before = snapshot(protected)
        write(root / 'protected-before.json', encoded(before))
        command = [sys.executable, '-B', str(source / 'scripts/v7/coding_worker.py'), 'serve', '--root', str(worker_root), '--approve', task['contract_sha256']]
        if a.development_task is not None:
            command += ['--development-task', str(a.development_task.resolve()), '--development-task-sha256', a.development_task_sha256]
            write(root/'task-definition.json', a.development_task.read_bytes())
        stage = 'agent-tools'
        if a.session_api:
            import vm_session
            session = vm_session.Session.start(vm_session.SessionRequest(
                'development-kernel-child', task['contract_sha256'], 180,
                development_task=a.development_task, development_task_sha256=a.development_task_sha256), root/'session')
        else:
            worker_err = (root / 'worker.stderr').open('xb')
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_err, cwd=source)
        actions = json.loads(a.actions.read_bytes()) if not generated else None
        pending = [{"tool": "read", "path": "../outside.py"}] if a.codex_agent else []
        generation = 0
        responses = []
        selector = selectors.DefaultSelector()
        if not a.session_api:
            selector.register(child.stdout, selectors.EVENT_READ)
        if a.live_agent:
            print(json.dumps({'status': 'REALM_READY_FOR_LIVE_AGENT', 'freeze': freeze,
                              'task': task['contract']}), flush=True)
        for index in range(worker.MAX_REQUESTS):
            if a.codex_agent:
                if not pending:
                    from live_codex_planner import generate
                    generation += 1
                    pending = generate(worker, root, responses, generation, a.planner_timeout)
                action = pending.pop(0)
                write(root / ('live-action-%03d.json' % index), encoded(action))
            elif a.live_agent:
                raw = sys.stdin.buffer.readline(worker.MAX_BYTES * 3 + 1)
                if not raw or not raw.endswith(b'\n') or len(raw) > worker.MAX_BYTES * 3:
                    raise ValueError('live agent EOF or framing limit before finish')
                action = worker.parse(raw)
                # Retain every proposal before tool execution, including failures.
                write(root / ('live-action-%03d.json' % index), encoded(action))
            else:
                if index >= len(actions):
                    break
                action = actions[index]
            if a.session_api:
                result = session.execute(action)
            else:
                child.stdin.write(encoded(action) + b'\n'); child.stdin.flush()
                if not selector.select(40):
                    raise ValueError('worker response timeout')
                result = json.loads(child.stdout.readline())
            responses.append({'action': action, 'response': result})
            if a.live_agent:
                print(json.dumps(responses[-1]), flush=True)
            if result.get('status', '').startswith('REFUSED') and action != {'tool': 'read', 'path': '../outside.py'}:
                if a.codex_agent and generation < 2:
                    pending.clear()
                    continue
                raise ValueError('unexpected worker refusal')
            if a.codex_agent and action.get('tool') == 'check' and not result.get('passed'):
                pending.clear()
            if generated and result.get('status') == 'DEVELOPMENT_TASK_CHECKED':
                break
        if a.session_api:
            terminal = session.close()
            if (not terminal['task_finished'] or terminal['terminal']['status'] != 'PASS'
                    or terminal['actual_vm'] != 'NOT_RUN' or terminal['authority'] != 'NONE'):
                raise ValueError('development session did not finish and close cleanly')
            code = 0
        else:
            child.stdin.close()
            code = child.wait(timeout=5)
            worker_err.close()
        selector.close()
        if code or responses[-1]['response'].get('status') != 'DEVELOPMENT_TASK_CHECKED':
            raise ValueError('worker did not finish')
        write(root / 'tool-responses.json', encoded(responses))
        journal = (worker_root / 'events.jsonl').read_bytes()
        rows = [json.loads(line) for line in journal.splitlines()]
        interpreter = next(r['event']['result']['interpreter_sha256'] for r in rows if r['event'].get('request', {}).get('tool') == 'check')
        audit_args = [sys.executable, '-B', source / 'scripts/v7/verify_coding_development.py', '--root', worker_root, '--contract', root / 'contract.json', '--contract-sha256', task['contract_sha256'], '--worker-sha256', task['worker_sha256'], '--interpreter-sha256', interpreter, '--journal-head', rows[-1]['sha256']]
        audit = run('transcript-audit', audit_args)
        referee_args = [sys.executable, '-B', source / 'scripts/v7/coding_task_verifier.py', 'check', '--candidate', worker_root / 'candidate', '--output', root / 'referee', '--scope-sha256', task['checker_scope_sha256'], '--seed', '20261028']
        if a.development_task is not None:
            referee_args += ['--development-task', str(a.development_task.resolve()), '--development-task-sha256', a.development_task_sha256]
        run('independent-referee', referee_args)
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
        packed = json.loads(run('pack-capture', [realm, 'artifact', 'pack-development-coding', root/'payload.json', root/'expectations.json', pp, ep, artifact]))
        pin = packed['artifact_blake3']
        decision = json.loads(run('receiver', [realm, 'artifact', 'inspect-development-realm', artifact, pin, root/'expectations.json', ep], expected=1))
        if decision['status'] != 'INCOMPLETE' or decision['authority'] != 'NONE' or decision['application_dispatched'] or decision['destination_access']:
            raise ValueError('receiver granted unqualified authority')
        extracted = json.loads(run('receiver-extract', [realm, 'artifact', 'extract-development-coding', artifact, pin, root/'expectations.json', ep]))
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
        integrated_interfaces = {'status': 'NOT_RUN', 'native_execution': 'NOT_RUN', 'authority': 'NONE'}
        if a.verify_integrated_interfaces:
            # This control intentionally exercises the real OS fence, not a
            # mock native phase or simulated successful qualification. Refuse
            # to use this local harness on a host able to launch the native VM.
            if platform.system() != 'Darwin':
                raise ValueError('local native-refusal control requires Darwin; no Linux guest launch allowed')
            import coding_native_run as native_driver
            driver = Path(native_driver.__file__)
            identities[str(driver)] = sha(driver.read_bytes())
            native_state = root/'native-NOT_RUN-state'
            publication = root/('f'*64)
            native_args = SimpleNamespace(native_binary=realm, custodian=root/'NOT_PROVISIONED-custodian',
                native_relay=True, owned_referee_python=Path(sys.executable),
                publication_world=root/'NOT_PROVISIONED-native-world', publication_evidence=publication,
                publication_trust=root/'NOT_PROVISIONED-native-trust.json', publication_trust_sha256='0'*64)
            # The missing configuration is deliberate negative input. No native
            # identity, BINDING frame, trust statement or evidence is fabricated.
            argv = native_driver.native_launch(native_args,native_state,-1)
            stage = 'actual-native-driver-refusal'
            with (root/'actual-native-driver.stderr').open('xb') as err:
                original = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,cwd=source)
                try:
                    original.stdin.close()
                    lines = native_driver.NativeLines(original,root)
                    try:
                        lines.next(time.monotonic()+8)
                    except ValueError as refusal:
                        native_refusal = str(refusal)
                    else:
                        raise ValueError('unqualified local host returned a native binding')
                    code = original.wait(timeout=8)
                    write(root/'actual-native-driver.stdout',bytes(lines.pending))
                finally:
                    if original.poll() is None: original.kill();original.wait()
                    original.stdout.close()
            if code == 0 or native_state.exists() or publication.exists():
                raise ValueError('native OS refusal generated state or publication')
            if b'qualified Linux/x86_64' not in (root/'actual-native-driver.stderr').read_bytes():
                raise ValueError('native refusal did not reach actual platform gate')
            records.append({'stage':stage,'argv':argv,'exit':code,'driver_refusal':native_refusal})
            raw = run('installed-policy-refusal',[realm,'artifact','provision-coding-policy','a'*64],expected=1)
            if raw or b'INCOMPLETE' not in (root/'installed-policy-refusal.stderr').read_bytes():
                raise ValueError('unqualified policy provisioner returned authority data')
            automatic = json.loads(run('automatic-handoff-refusal',
                [realm,'transfer','receive-installed','a'*64,artifact,pin,payload['run_label']],expected=1))
            if (automatic['artifact_integrity'] != 'VALID' or automatic['status'] != 'INCOMPLETE'
                or automatic['execution_qualification'] != 'INCOMPLETE'
                or automatic['application_authorization'] != 'NONE' or automatic['application_dispatched']):
                raise ValueError('automatic handoff confused artifact integrity with authority')
            integrated_interfaces = {'status':'PASS_REAL_INTERFACE_REFUSALS','driver_sha256':identities[str(driver)],
                'actual_native_cli_exit':code,'native_execution':'NOT_RUN','native_binding':'NONE',
                'production_policy_issued':False,'native_state_created':False,'automatic_handoff':automatic,'authority':'NONE'}
            write(root/'integrated-interfaces.json',encoded(integrated_interfaces))
        for label, mutate in [('missing-capture', lambda p: p['evidence'].pop('journal')), ('forbidden-effect', lambda p: p['files'][0].update(path='../outside.py'))]:
            body = json.loads(encoded(payload)); mutate(body); path = root/(label+'.json'); raw=encoded(body);write(path,raw)
            run(label,[realm,'artifact','pack-development-coding',path,root/'expectations.json',b3(raw),ep,root/(label+'.realm')],expected=1)
            if (root/(label+'.realm')).exists(): raise ValueError('invalid capture generated artifact')
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
        result={'status':'INCOMPLETE','mechanics':'PASS_EXECUTION_BOUND_DEVELOPMENT_CHAIN','authority':'NONE','source_commit':commit,'task_sha256':a.task_sha256,'fresh_tool_execution':True,'planner':('Fresh ephemeral Codex CLI; requirements/current files only, no inherited chat' if a.codex_agent else 'Live Codex tool loop; actions generated after freeze in this chat, no model API' if a.live_agent else 'Codex-generated restricted tool proposals; reproduction replays proposals, no model API'),'artifact':str(artifact),'artifact_sha256':sha(artifact.read_bytes()),'artifact_blake3':pin,'receiver_decision':decision['status'],'protected_destination_unchanged':True,'application_dispatched':False,'disposable_replay':disposable,'integrated_interfaces':integrated_interfaces,'production_qualification':'NOT_RUN','canonical_publication':'NOT_RUN','stages':records}
        cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        result['cost'] = {'elapsed_seconds': time.monotonic()-start, 'child_cpu_seconds': (cpu_after.ru_utime+cpu_after.ru_stime)-(cpu_before.ru_utime+cpu_before.ru_stime), 'planner_generations': generation, 'monetary_cost': 'NOT_REPORTED', 'paid_api_fallback': False}
        write(root/'RESULT.json',json.dumps(result,indent=2).encode()+b'\n')
        print(json.dumps(result,indent=2))
    except BaseException as error:
        if child is not None and child.poll() is None:
            child.kill();child.wait()
        write(root/'FAILURE.json',encoded({'stage':stage,'error':repr(error),'authority':'NONE','records':records, 'elapsed_seconds':time.monotonic()-start, 'protected_destination_unchanged':snapshot(protected)==before if 'before' in locals() else 'NOT_ESTABLISHED'}))
        raise
    finally:
        if session is not None:
            session.close()

if __name__ == '__main__':
    main()
