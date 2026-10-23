#!/usr/bin/env python3
"""Check/refresh the explicit public file manifest and local documentation links."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true', help='Record intentionally reviewed file changes; does not grant rights')
    args = parser.parse_args()
    raw = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT)
    names = sorted({x.decode() for x in raw.split(b'\0') if x and (ROOT / x.decode()).is_file()})
    assert 'EXPORT_MANIFEST.json' in names
    for name in names:
        assert not (ROOT / name).is_symlink(), f'Symlink is not supported: {name}'
        assert '.git' not in Path(name).parts, name
    current = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in names if n != 'EXPORT_MANIFEST.json'}
    if args.refresh:
        (ROOT / 'EXPORT_MANIFEST.json').write_text(json.dumps(current, indent=2) + '\n')
    expected = json.loads((ROOT / 'EXPORT_MANIFEST.json').read_text())
    assert current == expected, 'Files differ from manifest; review intentional changes before --refresh'
    broken = []
    for name in names:
        if not name.endswith('.md'):
            continue
        # Fenced examples can contain illustrative paths, not actual links.
        text = re.sub(r'```.*?```', '', (ROOT / name).read_text(), flags=re.S)
        for ref in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', text):
            ref = unquote(ref.split()[0].strip('<>').split('#')[0])
            if ref and not re.match(r'[a-z]+:', ref) and not (ROOT / name).parent.joinpath(ref).exists():
                broken.append((name, ref))
    assert not broken, f'Broken local documentation paths: {broken}'
    notices = json.loads((ROOT / 'THIRD_PARTY_INVENTORY.json').read_text())
    for package in notices['packages']:
        for name in package['license_texts']:
            assert name in expected, f'Missing upstream notice: {name}'
    for name in ['LICENSE-MIT', 'LICENSE-APACHE', 'NOTICE', 'RIGHTS.md']:
        assert name in expected and (ROOT / name).stat().st_size, name
    print(f'PASS: {len(names)} files; exact manifest, relative Markdown paths and required notice paths')
    print('This check does not establish ownership, secret clearance or execution qualification.')

if __name__ == '__main__':
    main()
