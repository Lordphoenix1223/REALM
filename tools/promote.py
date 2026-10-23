#!/usr/bin/env python3
"""Copy explicitly reviewed files onto a new branch from current public origin/main."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

PUBLIC = 'https://github.com/Lordphoenix1223/REALM.git'

def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()

def safe_path(root, name):
    path = Path(name)
    assert not path.is_absolute() and path.parts and not any(x in ('.', '..', '.git', '.aws', '.ssh') for x in path.parts), name
    assert not path.name.startswith('.env'), name
    result = root.joinpath(path)
    assert result.resolve().is_relative_to(root), name
    assert not any(x.is_symlink() for x in [result, *result.parents] if x.is_relative_to(root)), name
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--branch', required=True)
    args = parser.parse_args()
    public = Path(__file__).resolve().parents[1]
    source = args.source.resolve()
    assert source.is_dir() and source != public
    assert git(public, 'remote', 'get-url', 'origin') == PUBLIC, 'Use a dedicated canonical PUBLIC clone'
    assert not git(public, 'status', '--porcelain'), 'Public clone must be clean; keep approval plan outside it'
    assert git(public, 'rev-parse', 'HEAD') == git(public, 'rev-parse', 'origin/main'), 'Fetch public main and start there'
    subprocess.run(['git', 'check-ref-format', '--branch', args.branch], check=True, stdout=subprocess.DEVNULL)
    assert args.branch.startswith('codex/'), 'Use a codex/ topic branch'
    plan = json.loads(args.plan.read_text())
    assert plan.get('rights_reviewed') is True and plan.get('purpose'), 'Explicit human rights review and purpose required'
    assert plan.get('files'), 'No approved files'
    copies = []
    targets = set()
    for row in plan['files']:
        assert row.get('rights_basis'), 'Each file needs its reviewed rights basis'
        src = safe_path(source, row['source'])
        dst = safe_path(public, row['target'])
        assert src.is_file() and dst not in targets, row['target']
        assert hashlib.sha256(src.read_bytes()).hexdigest() == row['sha256'], row['source']
        targets.add(dst)
        copies.append((src, dst))
    # All requested paths/hashes are checked before creating a branch or writing.
    subprocess.run(['git', 'switch', '-c', args.branch, 'origin/main'], cwd=public, check=True)
    for src, dst in copies:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        dst.chmod(src.stat().st_mode & 0o777)
    print(f'Prepared {len(copies)} reviewed files. No commits, history, approval plan or remote writes imported.')
    print('Next: inspect diff, rights/dependencies/secrets; refresh manifest; run relevant checks; create a public draft PR.')

if __name__ == '__main__':
    main()
