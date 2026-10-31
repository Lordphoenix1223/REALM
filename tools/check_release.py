#!/usr/bin/env python3
"""Check selected public bytes/links/notices, including Git-free source archives."""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def require(ok, message):
    # Release checks must remain active under python -O / PYTHONOPTIMIZE.
    if not ok:
        raise ValueError(message)


def inventory():
    if (ROOT/'.git').exists():
        raw = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT)
        names = {x.decode() for x in raw.split(b'\0') if x}
    else:
        # Support the simple rooted and basename patterns used by this project.
        raw_patterns = [p.strip().rstrip('/') for p in (ROOT/'.gitignore').read_text().splitlines()
                        if p.strip() and not p.lstrip().startswith('#')]
        patterns = [p.lstrip('/') for p in raw_patterns]
        require(all('/' not in p and not p.startswith('!') for p in patterns),
                'archive inventory needs updated handling for this .gitignore pattern')
        def ignored(path):
            return any(fnmatch.fnmatchcase(path.parts[0], p[1:]) if p.startswith('/') else
                       any(fnmatch.fnmatchcase(part, p) for part in path.parts) for p in raw_patterns)
        names = set()
        for folder, directories, files in os.walk(ROOT, followlinks=False):
            for name in list(directories):
                path = Path(folder)/name; rel = path.relative_to(ROOT)
                if ignored(rel):
                    directories.remove(name)
                else:
                    require(not path.is_symlink(), 'symlink directory: '+str(rel))
            names.update(str((Path(folder)/n).relative_to(ROOT)) for n in files
                         if not ignored((Path(folder)/n).relative_to(ROOT)))
    result = []
    for name in sorted(names):
        path = ROOT/name
        require(not path.is_symlink(), 'symlink file: '+name)
        require('.git' not in Path(name).parts and not Path(name).is_absolute() and '..' not in Path(name).parts,
                'unsafe selected path: '+name)
        if not path.exists():
            continue  # A deleted tracked file will fail exact-manifest comparison.
        require(stat.S_ISREG(path.lstat().st_mode), 'nonregular selected file: '+name)
        result.append(name)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true', help='Record intentional byte changes; never grants rights or security approval')
    args = parser.parse_args()
    names = inventory()
    require('EXPORT_MANIFEST.json' in names, 'missing export manifest')
    current = {n: hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names if n != 'EXPORT_MANIFEST.json'}
    provenance_path = ROOT/'PUBLIC_V02_PROVENANCE.json'
    provenance = json.loads(provenance_path.read_text()) if provenance_path.exists() else None
    if provenance:
        for item in provenance['files']:
            require(item['public_file'] in current, 'missing promoted source: '+item['public_file'])
            if args.refresh:
                item['public_sha256'] = current[item['public_file']]
                item['transformed'] = item['public_sha256'] != item['source_sha256']
            else:
                require(item['public_sha256'] == current[item['public_file']], 'promoted-source hash differs: '+item['public_file'])
    expected = json.loads((ROOT/'EXPORT_MANIFEST.json').read_text())
    if not args.refresh:
        require(current == expected, 'files differ from manifest; review intentional changes before --refresh')
    for name in names:
        if name.endswith('.md'):
            text = re.sub(r'```.*?```', '', (ROOT/name).read_text(), flags=re.S)
            for ref in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', text):
                ref = unquote(ref.split()[0].strip('<>').split('#')[0])
                require(not ref or re.match(r'[a-z]+:', ref) or (ROOT/name).parent.joinpath(ref).exists(),
                        'broken relative Markdown link: '+name+' -> '+ref)
    for package in json.loads((ROOT/'THIRD_PARTY_INVENTORY.json').read_text())['packages']:
        for name in package['license_texts']:
            require(name in current, 'missing upstream notice: '+name)
    for name in ['LICENSE-MIT', 'LICENSE-APACHE', 'NOTICE', 'RIGHTS.md']:
        require(name in current and (ROOT/name).stat().st_size, 'missing license/rights file: '+name)
    if args.refresh:
        if provenance:
            provenance_path.write_text(json.dumps(provenance, indent=2)+'\n')
            current['PUBLIC_V02_PROVENANCE.json'] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
        (ROOT/'EXPORT_MANIFEST.json').write_text(json.dumps(current, indent=2)+'\n')
    print(f'PASS: {len(names)} files; exact manifest, selected-source hashes, relative Markdown paths and notice paths')
    print('This check does not establish ownership, secret clearance or execution qualification.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit('FAIL: '+str(error))
