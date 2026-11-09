#!/usr/bin/env python3
"""Read-only local changes audit; committed-source CI cannot see these files.

Reports hashes and paths, never file contents. No network, publication, cleanup,
checkout, process launch, or execution authority. Explicit roots only; optional
linked-worktree discovery does not claim a whole-machine inventory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

SOURCE_SUFFIXES = ('.rs', '.py', '.c', '.h', '.m', '.sh', '.toml', '.lock', '.json',
                   '.yaml', '.yml', '.proto', '.ipynb', '.md', '.js', '.ts', '.sql')


def git(root, *args):
    p = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-C', str(root), *args],
                       capture_output=True)
    if p.returncode:
        raise ValueError('Git inspection unavailable for ' + str(root))
    return p.stdout


def inspect(root):
    root = Path(root).resolve()
    head = git(root, 'rev-parse', 'HEAD').decode().strip()
    names = {}
    for state, args in [
        ('ignored_source', ['ls-files', '--others', '--ignored', '--exclude-standard', '-z',
                            '--', *['*'+s for s in SOURCE_SUFFIXES], '*.env*']),
        ('untracked', ['ls-files', '--others', '--exclude-standard', '-z']),
        ('modified_or_staged', ['diff', '--no-renames', 'HEAD', '--name-only', '-z']),
    ]:
        for name in git(root, *args).split(b'\0'):
            if name:
                names[name.decode()] = state
    files = []
    for name, state in sorted(names.items()):
        path = root / name
        row = {'path': name, 'state': state}
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            row['state'] = 'deleted'
            files.append(row)
            continue
        if stat.S_ISDIR(metadata.st_mode):
            row['kind'] = 'nested_directory_or_repository'
        elif stat.S_ISLNK(metadata.st_mode):
            row.update(kind='symlink', sha256=hashlib.sha256(os.readlink(path).encode()).hexdigest())
        elif stat.S_ISREG(metadata.st_mode):
            h = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024*1024), b''):
                    h.update(block)
            row.update(kind='regular', size=metadata.st_size, sha256=h.hexdigest())
        else:
            row['kind'] = 'nonregular_not_opened'
        files.append(row)
    return {'root': str(root), 'head': head, 'files': files, 'uncommitted_changes': bool(files)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', action='append', type=Path)
    p.add_argument('--worktrees', action='store_true')
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    roots = {x.resolve() for x in (a.repo or [Path.cwd()])}
    if a.worktrees:
        for root in list(roots):
            for line in git(root, 'worktree', 'list', '--porcelain').decode().splitlines():
                if line.startswith('worktree '):
                    roots.add(Path(line[9:]).resolve())
    records = []
    for root in sorted(roots):
        try:
            records.append(inspect(root))
        except ValueError as error:
            records.append({'root': str(root), 'status': 'UNAVAILABLE', 'error': str(error)})
    result = {'schema': 'realm.local-source-audit/v1', 'scope': 'explicit local roots and selected linked worktrees',
              'committed_source_monitor': False, 'authority': 'NONE', 'repositories': records}
    raw = json.dumps(result, indent=2) + '\n'
    if a.output:
        a.output.write_text(raw)
    print(raw, end='')


if __name__ == '__main__':
    main()
