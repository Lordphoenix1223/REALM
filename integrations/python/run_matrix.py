#!/usr/bin/env python3
"""Finite integration regression matrix, not a new detection benchmark or qualifier."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from realm_client import Checker, CheckerError

ROOT = Path(__file__).resolve().parents[2]
CASES = [
    ('supported-content','intact','VALID',False),
    ('tampering','payload-0','INVALID',False),
    ('missing-content','thin-missing-blob','INCOMPLETE',False),
    ('misleading-consistent-log','consistent-false-effect','VALID',False),
    ('caller-claims-accept','self-reported-accept','VALID',False),
    ('omitted-observations','omitted-unknowns','VALID',False),
    ('unqualified-environment','intact','INCOMPLETE',True),
    ('unsupported-format','future-format','UNSUPPORTED',False),
]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checker',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();client=Checker(a.checker)
    output=a.output.resolve();output.mkdir(exist_ok=False)
    rows=[]
    for name,fixture,expected,execution in CASES:
        source=ROOT/'benchmarks/fixtures/a'/(fixture+'.realm')
        target=output/(name+'.realm');shutil.copyfile(source,target)
        row={'case':name,'fixture':str(source.relative_to(ROOT)),
             'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
             'expected_artifact_status':expected,'require_execution':execution,
             'observation_source':'frozen supplied evidence; not trusted execution capture'}
        try:
            report=client.verify(target,require_execution=execution)
            row.update(report=report.to_dict(),matches_expected=report.status.value==expected)
        except CheckerError as error:row.update(error=str(error),matches_expected=False)
        rows.append(row)
    # Reuse existing worker mechanisms; do not create a second execution engine.
    for name,script,extra in [('correct-task','examples/external_agent/run.py',[]),
                              ('wrong-task','examples/external_agent/run.py',['--wrong-answer']),
                              ('transient-forbidden-write','examples/counterexample/run.py',[])]:
        process=subprocess.run([sys.executable,str(ROOT/script),'--checker',str(client.executable),
            '--output',str(output/name),*extra],capture_output=True,timeout=60)
        (output/(name+'.stdout')).write_bytes(process.stdout)
        (output/(name+'.stderr')).write_bytes(process.stderr)
        rows.append({'case':name,'oracle':'separate task test / cooperative outside harness',
                     'exit_code':process.returncode,'matches_expected':process.returncode==0,
                     'evidence_directory':name,'execution_authority':'NOT_ESTABLISHED'})
    result={'schema':'realm.python-integration-matrix.v1','rows':rows,
            'status':'PASS' if all(r['matches_expected'] for r in rows) else 'FAIL',
            'scope':'finite supplied-content and adapter controls; no runtime-policy detection or qualification',
            'qualification':'NOT_RUN'}
    (output/'matrix.json').write_text(json.dumps(result,indent=2)+'\n')
    print(result['status'],len(rows),'finite controls; evidence:',output)
    raise SystemExit(0 if result['status']=='PASS' else 1)

if __name__=='__main__':main()
