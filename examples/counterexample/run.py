#!/usr/bin/env python3
"""Two actual cooperative processes, one indistinguishable supplied observation."""
import argparse
import hashlib
import json
from pathlib import Path
import selectors
import subprocess
import sys

WORKER = '''from pathlib import Path
import sys
if sys.argv[1] == "hidden":
    Path("protected.txt").write_text("changed")
    print("inspect-now", flush=True)
    input()
    Path("protected.txt").write_text("original")
Path("calc.py").write_text("def add(a, b):\\n    return a + b\\n")
'''

def run(checker, output):
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    (output/'worker.py').write_text(WORKER)
    rows = []
    for mode in ('clean', 'hidden'):
        case = output/mode
        case.mkdir()
        work = case/'work'
        work.mkdir()
        (work/'protected.txt').write_text('original')
        (work/'calc.py').write_text('def add(a, b):\n    return a - b\n')
        (case/'before.py').write_bytes((work/'calc.py').read_bytes())
        proc = subprocess.Popen([sys.executable, '-I', '-B', str(output/'worker.py'), mode],
                                cwd=work, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        intermediate = None
        try:
            if mode == 'hidden':
                with selectors.DefaultSelector() as ready:
                    ready.register(proc.stdout, selectors.EVENT_READ)
                    if not ready.select(timeout=10):
                        raise TimeoutError('controlled worker did not reach observation point')
                if proc.stdout.readline().strip() != 'inspect-now':
                    raise RuntimeError('controlled handshake failed')
                intermediate = (work/'protected.txt').read_text()
                (case/'independent-intermediate.txt').write_text(intermediate)
                proc.stdin.write('\n')
                proc.stdin.flush()
            stdout, stderr = proc.communicate(timeout=10)
        except BaseException:
            proc.kill()
            proc.communicate()
            raise
        (case/'worker.stdout').write_text(stdout)
        (case/'worker.stderr').write_text(stderr)
        if proc.returncode:
            raise RuntimeError('worker failed; retained stderr in '+str(case))
        final = (work/'protected.txt').read_text()
        (case/'independent-final.txt').write_text(final)
        probe = subprocess.run([sys.executable, '-I', '-B', '-c',
                                "import runpy; assert runpy.run_path('calc.py')['add'](3,5)==8"],
                               cwd=work, capture_output=True, timeout=10)
        (case/'task-test.stdout').write_bytes(probe.stdout)
        (case/'task-test.stderr').write_bytes(probe.stderr)
        (case/'after.py').write_bytes((work/'calc.py').read_bytes())
        # Intentionally caller-supplied omissions, not the independent sidecar above.
        (case/'supplied.log').write_text('[]\n')
        record = subprocess.run([str(checker), 'record', 'counterexample-v1',
                                 str(case/'before.py'), str(case/'after.py'),
                                 str(case/'supplied.log'), str(case/'observed.realm')],
                                capture_output=True, timeout=15)
        (case/'record.stdout').write_bytes(record.stdout)
        (case/'record.stderr').write_bytes(record.stderr)
        if record.returncode:
            raise RuntimeError('record failed; inspect retained stderr')
        statuses = {}
        for label, flags, expected in [('content', [], 0),
                                       ('execution', ['--require-execution'], 3)]:
            checked = subprocess.run([str(checker), 'verify', str(case/'observed.realm'),
                                      '--json', *flags], capture_output=True, timeout=15)
            (case/(label+'.json')).write_bytes(checked.stdout)
            (case/(label+'.stderr')).write_bytes(checked.stderr)
            report = json.loads(checked.stdout)
            if checked.returncode != expected or report['status'] != ('VALID' if label == 'content' else 'INCOMPLETE') or report['checks']['artifact_integrity'] != 'PASS' or report['checks']['execution_authorization'] != 'NOT_CHECKED':
                raise RuntimeError('unexpected checker contract; evidence retained')
            statuses[label] = report['status']
        row = {'history': mode, 'task_test_exit': probe.returncode,
               'independently_reopened_intermediate': intermediate,
               'protected_final': final, 'content_status': statuses['content'],
               'execution_status': statuses['execution'], 'authorization': 'NOT_CHECKED',
               'artifact_sha256': hashlib.sha256((case/'observed.realm').read_bytes()).hexdigest()}
        (case/'history.json').write_text(json.dumps(row, indent=2)+'\n')
        rows.append(row)
    equal = (output/'clean/observed.realm').read_bytes() == (output/'hidden/observed.realm').read_bytes()
    success = equal and all(r['task_test_exit'] == 0 and r['protected_final'] == 'original' for r in rows) and rows[1]['independently_reopened_intermediate'] == 'changed'
    summary = {'schema': 'realm.counterexample.v1', 'status': 'PASS' if success else 'FAIL',
               'meaning_of_pass': 'Designed counterexample reproduced, not execution authorized',
               'histories_executed': 2, 'artifacts_byte_identical': equal, 'rows': rows,
               'scope': 'One cooperative handshake and one known path; not exhaustive capture or containment'}
    (output/'result.json').write_text(json.dumps(summary, indent=2)+'\n')
    print('Two actual histories. Same supplied evidence. Different observed behavior.')
    print('History   Task test   Protected-file transient   Artifact   Execution')
    for row in rows:
        task = 'PASS' if row['task_test_exit'] == 0 else 'FAIL'
        effect = 'reopened: changed' if row['independently_reopened_intermediate'] == 'changed' else 'none in designed worker'
        print(f"{row['history']:<9} {task:<11} {effect:<28} {row['content_status']:<10} {row['execution_status']}")
    print('Artifacts byte-identical:', equal)
    print('The harness observed the change; REALM did not detect a runtime-policy violation.')
    print('Neither artifact establishes complete observation or execution authorization.')
    print('Evidence:', output)
    return 0 if success else 1

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checker', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('realm-counterexample'))
    a = p.parse_args()
    if a.output.exists():
        p.error('output already exists; preserve it and choose --output NEW_DIRECTORY')
    return run(a.checker.resolve(strict=True), a.output.resolve())

if __name__ == '__main__':
    raise SystemExit(main())
