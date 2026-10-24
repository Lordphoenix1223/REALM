#!/usr/bin/env python3
"""Freeze real native-checker reports for the static replay; never build a verifier in JS."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def checked(checker, artifact, flags, status, code):
    result = subprocess.run([str(checker), 'verify', str(artifact), '--json', *flags], capture_output=True, check=False, timeout=20)
    report = json.loads(result.stdout)
    assert result.returncode == code and report['status'] == status, (result.returncode, report)
    assert report['schema'] == 'realm.artifact-check.v1'
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checker', required=True, type=Path)
    args = parser.parse_args()
    checker = args.checker.resolve()
    target = ROOT / 'site/evidence'
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='realm-public-replay-') as folder:
        work = Path(folder)
        subprocess.run([str(checker), 'demo', '--output', str(work/'samples')], check=True, capture_output=True)
        subprocess.run(['python3', '-B', str(ROOT/'examples/counterexample/run.py'), '--checker', str(checker), '--output', str(work/'pair')], check=True, capture_output=True)
        pair = json.loads((work/'pair/result.json').read_text())
        assert pair['status'] == 'PASS' and pair['artifacts_byte_identical']
        assert (work/'pair/clean/observed.realm').read_bytes() == (work/'pair/hidden/observed.realm').read_bytes()
        reports = {}
        for name, file, expected, code in [('intact','valid.realm','VALID',0),('tampered','tampered.realm','INVALID',1),('missing','incomplete.realm','INCOMPLETE',3)]:
            artifact = work/'samples'/file
            shutil.copyfile(artifact, target/(name+'.realm'))
            reports[name] = checked(checker, artifact, [], expected, code)
            (target/(name+'.json')).write_text(json.dumps(reports[name], indent=2)+'\n')
        reports['intact-execution'] = checked(checker, work/'samples/valid.realm', ['--require-execution'], 'INCOMPLETE', 3)
        (target/'intact-execution.json').write_text(json.dumps(reports['intact-execution'],indent=2)+'\n')
        for mode in ['clean','hidden']:
            for kind in ['content','execution']:
                report = json.loads((work/f'pair/{mode}/{kind}.json').read_text())
                assert report['checks']['execution_authorization'] == 'NOT_CHECKED'
                reports[mode+'-'+kind] = report
                (target/(mode+'-'+kind+'.json')).write_text(json.dumps(report,indent=2)+'\n')
            shutil.copyfile(work/f'pair/{mode}/observed.realm',target/(mode+'.realm'))
        outside = {'hidden_intermediate':(work/'pair/hidden/independent-intermediate.txt').read_text(), 'hidden_final':(work/'pair/hidden/independent-final.txt').read_text(), 'clean_final':(work/'pair/clean/independent-final.txt').read_text(), 'supplied_log':(work/'pair/hidden/supplied.log').read_text(), 'source':'Cooperative independent experimental harness, not the artifact checker', 'scope':pair['scope']}
        assert outside['hidden_intermediate'] == 'changed' and outside['hidden_final'] == 'original'
        (target/'outside-observation.json').write_text(json.dumps(outside,indent=2)+'\n')
        (target/'paired-result.json').write_text(json.dumps(pair,indent=2)+'\n')
    files = {f.name:sha(f) for f in sorted(target.iterdir()) if f.suffix in ['.json','.realm'] and f.name != 'manifest.json'}
    sources = ['examples/counterexample/run.py','crates/realm-artifact/src/inspection.rs','crates/realm-artifact/src/observations.rs','crates/realm-artifact/src/lib.rs','benchmarks/reference/results.json']
    manifest = {'schema':'realm.browser-replay.v1','mode':'PREPARED_NATIVE_RESULTS_NOT_LIVE_VERIFICATION','public_source_base':'716f9c8fd813b361ece4f6b65835877f3aec551a','checker_sha256':sha(checker),'checker_version':reports['intact']['checker_version'],'generation_platform':platform.system()+' '+platform.machine(),'source_sha256':{n:sha(ROOT/n) for n in sources},'files':files,'outside_observation':'Independent sidecar; not part of supplied artifacts; one known cooperative pause, no exhaustive capture','license':'Original generated REALM demonstration evidence, MIT OR Apache-2.0'}
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Frozen real checker reports and paired histories:',len(files),'files; no private inputs, no generated success claims.')

if __name__ == '__main__':
    main()
