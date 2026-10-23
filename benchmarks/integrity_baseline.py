#!/usr/bin/env python3
"""Compare legacy integrity-only validate with full-content verify on frozen inputs."""
import argparse, hashlib, json, subprocess
from pathlib import Path
from run import measured, source_record
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checker',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
provenance=source_record()
if provenance['source_dirty']:p.error('freeze a clean commit first')
folder=ROOT/'benchmarks/fixtures/a'
if not folder.is_dir():folder=ROOT/'benchmarks/results/macos-arm64-20261022/a'
manifest=json.loads((folder/'manifest.json').read_text())
for case in manifest:
    assert hashlib.sha256((folder/(case['id']+'.realm')).read_bytes()).hexdigest()==case['sha256']
output=args.output.resolve();output.mkdir(exist_ok=False,parents=True);rows=[]
for case in manifest:
    file=folder/(case['id']+'.realm')
    for repeat in range(5):
        legacy=measured([args.checker.resolve(),'validate',file],output)
        full=measured([args.checker.resolve(),'verify',file,'--json'],output)
        value=json.loads(full['stdout'])
        expected_legacy=0 if case['expected'] in ('VALID','INCOMPLETE') else 1
        rows.append({'case':case['id'],'repeat':repeat,'expected_full':case['expected'],'legacy_integrity_exit':legacy['exit'],'legacy_expected_exit':expected_legacy,'full_status':value['status'],'legacy_ms':1000*legacy['seconds'],'full_ms':1000*full['seconds'],'authority':value['checks']['execution_authorization']})
report={'schema':'realm.integrity-baseline.v1',**provenance,'binary_sha256':hashlib.sha256(args.checker.read_bytes()).hexdigest(),'fixture_manifest_sha256':hashlib.sha256((folder/'manifest.json').read_bytes()).hexdigest(),'cases':len(manifest),'repeats':5,'measurements':len(rows),'legacy_integrity_accepts':sum(x['legacy_integrity_exit']==0 for x in rows),'full_content_accepts':sum(x['full_status']=='VALID' for x in rows),'missing_content_explicitly_incomplete':sum(x['full_status']=='INCOMPLETE' for x in rows),'legacy_matches_its_contract':sum(x['legacy_integrity_exit']==x['legacy_expected_exit'] for x in rows),'full_matches_its_contract':sum(x['full_status']==x['expected_full'] for x in rows),'interpretation':'Same engine and frozen bytes. Legacy validate checks Integrity, permitting missing thin content. New verify adds ContentComplete and explicit status. The five thin acceptances are not legacy errors against its own integrity-only contract. Neither grants execution authority.','rows':rows}
assert report['legacy_matches_its_contract']==90 and report['full_matches_its_contract']==90
(output/'results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
