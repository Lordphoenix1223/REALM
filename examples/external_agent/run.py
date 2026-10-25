#!/usr/bin/env python3
"""Integrate one controlled external worker. It is not a model or trusted runtime."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# The example locates the single-file adapter in this public checkout only.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'integrations/python'))
from realm_client import Checker, Status


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checker', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--wrong-answer', action='store_true', help='negative task-result control')
    a = p.parse_args()
    client = Checker(a.checker)
    output = a.output.resolve(); output.mkdir(exist_ok=False)
    worker = output/'calc.py'; worker.write_text('def add(a, b): return a - b\n')
    (output/'before').write_bytes(worker.read_bytes())
    replacement = 'def add(a, b): return a '+('-' if a.wrong_answer else '+')+' b\n'
    completed = subprocess.run([sys.executable, '-c',
        'from pathlib import Path; import sys; Path("calc.py").write_text(sys.argv[1]); print("worker finished")',
        replacement], cwd=output, capture_output=True, timeout=10, check=True)
    (output/'supplied.log').write_bytes(completed.stdout)
    (output/'after').write_bytes(worker.read_bytes())
    task = subprocess.run([sys.executable, '-c',
        'from calc import add; assert add(2, 3) == 5'], cwd=output, capture_output=True, timeout=10)
    (output/'task.stderr').write_bytes(task.stderr)
    report = client.record_observations('external-worker-example', output/'before',
        output/'after', output/'supplied.log', output/'observations.realm')
    summary = {'task_test_exit':task.returncode, 'artifact':report.to_dict(),
        'observation_source':'caller-supplied snapshots and worker stdout; untrusted',
        'execution_authority':'NOT_ESTABLISHED'}
    (output/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    expected = 1 if a.wrong_answer else 0
    if task.returncode != expected:raise SystemExit('unexpected task-test outcome')
    if report.status != Status.INCOMPLETE or report.checks.referenced_content != 'COMPLETE':
        raise SystemExit('unexpected native import/execution-request result')

if __name__ == '__main__':main()
