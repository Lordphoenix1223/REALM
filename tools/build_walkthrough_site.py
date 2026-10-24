#!/usr/bin/env python3
"""Prepare a static-only Pages snapshot. Does not deploy or alter Git refs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def build(output):
    output = output.resolve()
    assert not output.exists(), 'Use a new output directory; existing evidence is never replaced'
    assert not output.is_relative_to(ROOT), 'Keep deployment output outside the source checkout'
    remote = subprocess.check_output(['git','remote','get-url','origin'],cwd=ROOT,text=True).strip()
    assert remote == 'https://github.com/Lordphoenix1223/REALM.git', 'Build only from the canonical public checkout'
    source = ROOT / 'site'
    pins = json.loads((source/'evidence/manifest.json').read_text())
    for name, digest in pins['files'].items():
        assert hashlib.sha256((source/'evidence'/name).read_bytes()).hexdigest() == digest, name
    files = []
    for file in sorted(source.rglob('*')):
        assert not file.is_symlink(), str(file)
        if file.is_file() and (file.suffix in {'.html','.css','.js','.svg','.json','.realm'} or file.name == '.nojekyll'):
            files.append(file)
    output.mkdir(parents=True)
    for file in files:
        target = output/file.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)
    for name in ['LICENSE-MIT','LICENSE-APACHE','NOTICE']:
        shutil.copyfile(ROOT/name, output/name)
    revision = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
    payload = {'schema':'realm.static-snapshot.v1','source_commit':revision,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)), 'source_url':'https://github.com/Lordphoenix1223/REALM/tree/'+revision+'/site','mode':'Prepared native evidence replay; not a verifier or binary distribution','files':{str(f.relative_to(output)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(output.rglob('*')) if f.is_file()}}
    (output/'DEPLOYMENT.json').write_text(json.dumps(payload,indent=2)+'\n')
    return payload

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT), 'Commit/review the public source first; deploy only a frozen clean snapshot'
    record = build(args.output)
    print('Static snapshot:',args.output,';',len(record['files'])+1,'files; no Git history, backend, uploads or native executable.')

if __name__ == '__main__':
    main()
