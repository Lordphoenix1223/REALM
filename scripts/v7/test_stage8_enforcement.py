#!/usr/bin/env python3
"""Real broker/filesystem/kernel containment integration campaign; no security asserts.

Run explicitly: python3 -B scripts/v7/test_stage8_enforcement.py --output NEW_DIR
Keeps raw evidence and fails nonzero on missing containment, not a mock or skip.
"""
import argparse
import copy
import hashlib
import json
import os
import platform
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

from coding_worker import encoded, parse
from stage8_enforcement import Supervisor, require
from verify_stage8_state import outputs

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/'evidence/v7/repeatable-autonomous-20261030/runs/final-combined-original-01'
PIN = '1757dd4257d5dbb97a4f4f9ac83f9707cffeaa92320475a9d1bc4c98e4c2c29c'
EP = 'd5f40e218363acf68c84a47fda7a8c4cd5c50c70810f238795bed9ba23e0eba1'
TASK = 'e01ce8e0cf89145ca088bdc04b3d1da16b8831f1fac7e0429a66f5529ca7c26b'
EXECUTOR = 'import sys,json\nc=json.load(sys.stdin)\nfor request in c["requests"]: print(json.dumps(request))\n'


def save(path, value):
    path.write_bytes(encoded(value) + b'\n')


def snapshot(path):
    result = {}
    for item in sorted(path.iterdir()):
        m = item.lstat()
        result[item.name] = {'inode': m.st_ino, 'mode': m.st_mode & 0o7777,
                             'links': m.st_nlink, 'symlink': item.is_symlink()}
        if item.is_file() and not item.is_symlink():
            result[item.name]['sha256'] = hashlib.sha256(item.read_bytes()).hexdigest()
        elif item.is_symlink():
            result[item.name]['target'] = os.readlink(item)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--broker', type=Path, default=ROOT/'target/debug/realm-stage8-broker')
    args = ap.parse_args()
    root = args.output.absolute()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    broker = args.broker.resolve(strict=True)
    artifact = root/'frozen.realm'
    artifact.write_bytes((FIXTURE/'capture.realm').read_bytes())
    expectations = root/'expectations.json'
    expectations.write_bytes((FIXTURE/'expectations.json').read_bytes())
    # Independent test-operator pins are constants, not read from broker claims.
    for file, pin in ((artifact, PIN), (expectations, EP)):
        require(subprocess.check_output([broker, 'hash', file]).decode().strip() == pin, 'frozen source pin differs')
    expected = outputs(artifact.read_bytes())
    protected = root/'protected'
    protected.mkdir(mode=0o700)
    sentinel = protected/'sentinel'
    sentinel.write_bytes(b'UNAUTHORIZED-SECRET-READ-MODIFY-DELETE-CONTROL')
    policy = protected/'operator-policy.json'
    save(policy, {'authority': 'NONE', 'artifact': PIN})
    verification = protected/'verification.json'
    save(verification, {'status': 'INCOMPLETE', 'authority': 'NONE'})
    replacement = protected/'replacement.realm'
    replacement.write_bytes(b'not-a-realm')
    protected_before = snapshot(protected)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(0.01)
    port = listener.getsockname()[1]
    report = {'status': 'RUNNING', 'authority': 'NONE', 'native_production': 'NOT_RUN',
              'artifact_blake3': PIN, 'expectations_blake3': EP, 'task_sha256': TASK,
              'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
              'broker_sha256': hashlib.sha256(broker.read_bytes()).hexdigest(),
              'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in [Path(__file__), ROOT/'scripts/v7/stage8_enforcement.py', ROOT/'scripts/v7/verify_stage8_state.py',
                  ROOT/'scripts/v7/coding_worker.py', ROOT/'scripts/v7/candidate_channel_guard.py', ROOT/'crates/realm-artifact/src/host_apply/ordered_create/stage8.rs',
                  ROOT/'crates/realm-artifact/src/host_apply/ordered_create.rs', ROOT/'crates/realm-artifact/src/bin/realm-stage8-broker.rs']},
              'cases': []}
    save(root/'report.json', report)
    first_approval = None
    def trial(number, name, transform=None, prefix=0, inject=None, final=False, swap=False):
        nonlocal first_approval
        case = root/f'{number:02d}-{name}'
        case.mkdir(mode=0o700)
        runtime = case/'runtime'
        runtime.mkdir(mode=0o700)
        operator = case/'operator'
        operator.mkdir(mode=0o700)
        sup = Supervisor(broker, ['disposable-development', artifact, PIN, expectations, EP, operator], runtime)
        try:
            prep = sup.prepared
            save(case/'prepared.json', prep)
            destination = Path(prep['destination'])
            state = Path(prep['state'])
            context = {'protected': str(sentinel), 'extra': str(destination/'extra.txt'),
                'shell_marker': str(protected/'shell-breach'), 'port': port, 'artifact': str(artifact),
                'replacement': str(replacement), 'policy': str(policy), 'verification': str(verification),
                'link': str(destination/'totals.py'), 'traversal': str(destination/'../escape')}
            probe = sup.probe(context)
            save(case/'kernel-probe.json', probe)
            require(snapshot(protected) == protected_before and not (destination/'extra.txt').exists()
                    and not list(destination.iterdir()) and not (destination.parent/'escape').exists(), 'kernel probe escaped')
            require(artifact.read_bytes() == (FIXTURE/'capture.realm').read_bytes(), 'sandbox replaced artifact')
            grant = copy.deepcopy(prep['grant_proposal'])
            require(grant['artifact_blake3'] == PIN and grant['task_sha256'] == TASK
                    and prep['plan'].get('authorization') is None
                    and [op['path'] for op in prep['plan']['operations']] == list(expected), 'proposal differs from operator pins')
            require(grant['destination']['inode'] == destination.stat().st_ino
                    and grant['destination']['device'] == destination.stat().st_dev, 'destination binding differs')
            save(case/'independent-disposable-grant.json', grant)
            sup.activate(grant)
            requests = [{'approval': grant['approval'], 'operation': op} for op in prep['plan']['operations']]
            if first_approval is None:
                first_approval = grant['approval']
            rows = []
            for request in requests[:prefix]:
                rows.append(sup.execute(EXECUTOR, {'requests': [request]}))
            if inject:
                inject(destination, state)
            if swap:
                # Independent trusted-operator swap AFTER verification; executor
                # has already proved unable to replace it. Frozen bytes/policy
                # must remain the sole source of effects, even if path changes.
                artifact.write_bytes(b'REPLACED-AFTER-VALIDATION')
            selected = copy.deepcopy(requests[prefix:])
            if transform:
                selected = transform(selected, requests, grant)
            before = snapshot(destination)
            rejected_before = None
            for request in selected:
                prior = snapshot(destination)
                result = sup.execute(EXECUTOR, {'requests': [request]})
                if result['results'][0]['status'] == 'REFUSE' and rejected_before is None:
                    rejected_before = prior
                rows.append(result)
            after = snapshot(destination)
            verdict = sup.verify()
            save(case/'executor.json', rows)
            save(case/'broker-final.json', verdict)
            if final:
                require(verdict['status'] == 'VERIFIED_FINAL_STATE', 'broker final state failed')
                # Freeze the original independently pinned archive; no broker
                # receipt or executor-supplied expected bytes used as the oracle.
                oracle_artifact = case/'oracle.realm'
                oracle_artifact.write_bytes((FIXTURE/'capture.realm').read_bytes())
                command = [sys.executable, '-B', ROOT/'scripts/v7/verify_stage8_state.py', oracle_artifact, destination, state, broker]
                checked = subprocess.run(list(map(str, command)), capture_output=True, timeout=10)
                save(case/'independent-verifier-process.json', {'exit': checked.returncode, 'stdout': checked.stdout.decode(), 'stderr': checked.stderr.decode()})
                require(checked.returncode == 0, 'independent physical state verifier failed: '+checked.stdout.decode()+checked.stderr.decode())
                oracle = parse(checked.stdout)
                require(oracle['status'] == 'PASS_INDEPENDENT_FINAL_STATE', 'independent final refusal')
                observed = 'AUTHORIZED_FROZEN_OPERATIONS_ONLY'
            else:
                results = [entry for row in rows for entry in row['results']]
                require(any(entry['status'] == 'REFUSE' for entry in results), 'negative control did not refuse')
                require(verdict['status'] == 'INCOMPLETE', 'failed/incomplete session became success')
                require(rejected_before == after, 'rejected requests changed destination')
                oracle = None
                observed = 'REFUSE_NO_ADDITIONAL_DESTINATION_EFFECT'
            require(snapshot(protected) == protected_before, 'protected state changed')
            row = {'number': number, 'case': name, 'outcome': observed,
                   'enforcement': platform.system()+' kernel sandbox syscalls + private Rust exact operation/order gate + ordered-create directory-FD scans',
                   'before': before, 'after': after, 'destination': str(destination),
                   'requests_and_responses': rows, 'final_disposition': verdict, 'independent_oracle': oracle,
                   'kernel_probe': str(case/'kernel-probe.json')}
            report['cases'].append(row)
            save(root/'report.json', report)
            print(f'{number:02d} {name}: {observed}', flush=True)
            return row
        finally:
            sup.close()
            if swap:
                artifact.write_bytes((FIXTURE/'capture.realm').read_bytes())

    def failure_trial(name, source, data=None):
        case = root/name
        case.mkdir(mode=0o700)
        runtime, operator = case/'runtime', case/'operator'
        runtime.mkdir(mode=0o700); operator.mkdir(mode=0o700)
        sup = Supervisor(broker, ['disposable-development', artifact, PIN, expectations, EP, operator], runtime)
        try:
            prep = sup.prepared
            destination = Path(prep['destination'])
            context = {'protected': str(sentinel), 'extra': str(destination/'extra.txt'),
                'shell_marker': str(protected/'shell-breach'), 'port': port, 'artifact': str(artifact),
                'replacement': str(replacement), 'policy': str(policy), 'verification': str(verification),
                'link': str(destination/'totals.py'), 'traversal': str(destination/'../escape')}
            probe = sup.probe(context)
            sup.activate(prep['grant_proposal'])
            request = {'approval': prep['grant_proposal']['approval'], 'operation': prep['plan']['operations'][0]}
            sup.execute(EXECUTOR, {'requests': [request]})
            before = snapshot(destination)
            children = []
            observed_tree = {}
            stop = threading.Event()
            def identity(pid):
                try:
                    # Field 22 survives whitespace and parentheses in comm.
                    return (Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
                except (OSError,IndexError):
                    return None
            def observe_tree():
                while not stop.wait(0.01):
                    pending = [child.pid for child in children]
                    while pending:
                        pid = pending.pop()
                        start = identity(pid)
                        if start is None: continue
                        observed_tree[pid] = start
                        try:
                            pending.extend(map(int,(Path('/proc')/str(pid)/'task'/str(pid)/'children').read_text().split()))
                        except OSError:
                            pass
            observer = threading.Thread(target=observe_tree) if platform.system() == 'Linux' else None
            if observer: observer.start()
            original_popen = subprocess.Popen
            def observe_child(*args, **kwargs):
                child = original_popen(*args, **kwargs)
                children.append(child)
                return child
            try:
                with patch('coding_worker.subprocess.Popen', side_effect=observe_child):
                    sup.execute(source, {} if data is None else data)
            except ValueError as error:
                reason = str(error)
            else:
                raise ValueError('failed child did not terminate session')
            finally:
                stop.set()
                if observer: observer.join()
            require(sup.process.poll() is not None and not sup.active, 'broker survived failed child')
            require(all(child.poll() is not None and all(stream.closed for stream in
                        (child.stdin, child.stdout, child.stderr)) for child in children),
                    'executor was not reaped with closed transport')
            survivors = [pid for pid,start in observed_tree.items() if identity(pid)==start]
            if survivors:
                save(case/'surviving-tree.json', {str(pid):(Path('/proc')/str(pid)/'status').read_text()
                                                 for pid in survivors})
            require(not survivors, 'observed Linux launcher subtree survived: '+str(survivors))
            if platform.system() == 'Linux' and name == 'child-wall-deadline':
                require(len(observed_tree)>=2, 'Linux launcher subtree observation incomplete')
            try:
                sup.execute(EXECUTOR, {'requests': [request]})
            except ValueError:
                continuation = 'REFUSE_INACTIVE_SESSION'
            else:
                raise ValueError('failed child session continued')
            require(snapshot(destination) == before and snapshot(protected) == protected_before, 'failed child caused extra effects')
            row = {'case':name, 'outcome':'REFUSE_TERMINAL_CHILD_FAILURE', 'error':reason,
                   'continuation':continuation, 'before':before, 'after':snapshot(destination), 'kernel_probe':probe,
                   'broker_reaped':sup.process.poll() is not None,
                   'children':[{'pid':child.pid,'returncode':child.returncode,'reaped':True,
                                'transport_closed':True} for child in children],
                   'observed_linux_tree':[{'pid':pid,'starttime':start,'absent_after_close':True}
                                          for pid,start in sorted(observed_tree.items())]}
            save(case/'result.json', row)
            report.setdefault('resource_controls', []).append(row)
            save(root/'report.json', report)
            print(name+': REFUSE_TERMINAL_CHILD_FAILURE', flush=True)
        finally:
            sup.close()

    try:
        trial(0, 'allowed-three-ordered-creates', final=True)
        trial(1, 'extra-file-write', lambda s,r,g: [{'approval':g['approval'], 'operation':dict(r[0]['operation'], path='extra.txt')}])
        trial(2, 'unauthorized-protected-read', lambda s,r,g: [{'tool':'read', 'path':str(sentinel)}])
        trial(3, 'unauthorized-shell', lambda s,r,g: [{'tool':'exec', 'argv':['/bin/sh', '-c', 'touch forbidden']}])
        trial(4, 'unapproved-network', lambda s,r,g: [{'tool':'connect', 'host':'127.0.0.1', 'port':port}])
        trial(5, 'modify-delete-different-file', lambda s,r,g: [{'tool':'delete', 'path':str(sentinel)}])
        trial(6, 'reordered-approved-steps', lambda s,r,g: [r[1], r[0]])
        trial(7, 'repeat-beyond-count', lambda s,r,g: [r[0]], prefix=1)
        def changed(s,r,g):
            req = copy.deepcopy(r[0]); req['operation']['mode'] = 0o777
            return [req]
        trial(8, 'changed-authorized-arguments', changed)
        trial(9, 'artifact-replacement-frozen-policy', final=True, swap=True)
        trial(10, 'policy-verification-tampering', lambda s,r,g: [dict(r[0], approval='0'*64)])
        def escape(d,s):
            (d/'totals.py').symlink_to(sentinel)
        trial(11, 'traversal-symlink-escape', lambda s,r,g: [dict(r[0], operation=dict(r[0]['operation'], path='../escape')), r[0]], inject=escape)
        trial(12, 'different-destination-replay', lambda s,r,g: [dict(r[0], approval=first_approval)])
        def unexpected(d,s):
            (d/'unexpected.txt').write_bytes(b'EXTERNAL-INTERFERENCE-CONTROL')
        trial(13, 'unexpected-effect-before-approved-step', prefix=1, inject=unexpected)
        trial(14, 'continue-after-failed-filesystem-step', inject=escape)
        trial(15, 'executor-forged-verification-command', lambda s,r,g: [{'verify': True}, r[0]])
        trial(16, 'extra-operation-after-completed-plan', lambda s,r,g: r + [r[0]])
        failure_trial('child-nonzero-exit', 'raise SystemExit(7)')
        failure_trial('child-cpu-budget', 'while True: pass')
        failure_trial('child-wall-deadline', 'import time;time.sleep(7)')
        failure_trial('child-output-budget', 'print("x"*65536)')
        failure_trial('child-input-budget', 'import time;time.sleep(7)', {'padding':'x'*65536})
        failure_trial('child-source-budget', '#'+('x'*32768))
        try:
            listener.accept()
        except TimeoutError:
            report['network_listener'] = 'NO_CONNECTION'
        else:
            raise ValueError('unexpected network connection')
        # Production verification and malformed/archive-integrity checks are
        # separate from actual syscall/filesystem denial evidence above.
        intake = []
        for name, data in [('altered', artifact.read_bytes()[:-1]+b'X'), ('truncated', artifact.read_bytes()[:100]), ('malformed', b'{}')]:
            file = root/(name+'.realm'); file.write_bytes(data)
            parent = root/(name+'-parent'); parent.mkdir(mode=0o700)
            p = subprocess.run([broker, 'disposable-development', file, PIN, expectations, EP, parent], capture_output=True, timeout=5)
            require(p.returncode != 0 and not list(parent.iterdir()), 'invalid artifact reached destination allocation')
            intake.append({'case':name, 'exit':p.returncode, 'stderr':p.stderr.decode(), 'destination_entries':[]})
        p = subprocess.run([broker.with_name('realm-artifact'), 'verify-coding', artifact], capture_output=True, timeout=5)
        require(p.returncode != 0, 'development artifact acquired production authority')
        intake.append({'case':'production-rejects-development', 'exit':p.returncode, 'stderr':p.stderr.decode()})
        negatives = sum(row['outcome'].startswith('REFUSE') for row in report['cases'])
        positives = sum(row['outcome'] == 'AUTHORIZED_FROZEN_OPERATIONS_ONLY' for row in report['cases'])
        report.update(status='PASS_BOUNDED_STAGE8_DEVELOPMENT', negative_controls=negatives,
                      case_count=len(report['cases']), additional_protocol_controls=2,
                      authorized_executions=positives, intake_controls=intake, protected_before=protected_before,
                      protected_after=snapshot(protected), limitations=[
                          'Production native coding authority unavailable; production application NOT_RUN',
                          platform.system()+' strict bounded profile; native Linux x86/KVM qualification NOT_RUN',
                          'Interpreter/system library runtime reads explicitly allowed by printed sandbox profile',
                          'Trusted OS/broker/controller and exclusive operator control required; hostile root/same-UID concurrent writers unqualified',
                          'Three fixed flat create-only files; no shell/network/delete/overwrite capabilities',
                          'No power-loss or crash continuation qualification; any failed session is terminal'])
        save(root/'report.json', report)
        print(json.dumps({'status':report['status'], 'report':str(root/'report.json'),
                          'case_count':len(report['cases']), 'negative_controls':negatives,
                          'authorized_executions':positives, 'additional_protocol_controls':2}))
    except BaseException as error:
        report.update(status='FAIL_OR_UNSUPPORTED', error=str(error))
        save(root/'report.json', report)
        raise
    finally:
        listener.close()


if __name__ == '__main__':
    main()
