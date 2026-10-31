#!/usr/bin/env python3
"""Copy explicitly reviewed files onto a new branch from current public origin/main."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import stat
import tempfile
import subprocess

PUBLIC = 'https://github.com/Lordphoenix1223/REALM.git'
MAX_BYTES = 64 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def selected_bytes(path, limit=MAX_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'bounded regular source required')
        parts = []; remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            require(bool(chunk), 'short selected source read')
            parts.append(chunk); remaining -= len(chunk)
        def identity(value):
            return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,
                    value.st_mtime_ns,value.st_ctime_ns)
        require(not os.read(fd, 1) and identity(info) == identity(os.fstat(fd)), 'selected source changed during read')
        return b''.join(parts), stat.S_IMODE(info.st_mode) & 0o777
    finally:
        os.close(fd)


def write_selected(destination, raw, mode):
    # Replace a directory entry; never truncate a symlink/hardlink's target.
    stage = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.realm-promote-', delete=False) as stream:
            stage = Path(stream.name)
            stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
        os.replace(stage, destination)
    finally:
        if stage is not None and stage.exists():
            stage.unlink()  # Only this invocation's newly created staging file.


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()

def safe_path(root, name):
    path = Path(name)
    require(not path.is_absolute() and path.parts and (not any((x.casefold() in ('.', '..', '.git', '.aws', '.ssh') for x in path.parts))), name)
    require(not path.name.casefold().startswith('.env'), name)
    result = root.joinpath(path)
    require(result.resolve().is_relative_to(root), name)
    require(not any((x.is_symlink() for x in [result, *result.parents] if x.is_relative_to(root))), name)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--branch', required=True)
    args = parser.parse_args()
    public = Path(__file__).resolve().parents[1]
    source = args.source.resolve()
    require(source.is_dir() and source != public, 'promotion precondition failed')
    require(git(public, 'remote', 'get-url', 'origin') == PUBLIC, 'Use a dedicated canonical PUBLIC clone')
    require(not git(public, 'status', '--porcelain'), 'Public clone must be clean; keep approval plan outside it')
    require(git(public, 'rev-parse', 'HEAD') == git(public, 'rev-parse', 'origin/main'), 'Fetch public main and start there')
    subprocess.run(['git', 'check-ref-format', '--branch', args.branch], check=True, stdout=subprocess.DEVNULL)
    require(args.branch.startswith('codex/'), 'Use a codex/ topic branch')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate approval-plan field')
            value[key] = item
        return value
    plan = json.loads(selected_bytes(args.plan, 1024 * 1024)[0], object_pairs_hook=unique)
    require(type(plan) is dict, 'approval plan object required')
    require(plan.get('rights_reviewed') is True and plan.get('purpose'), 'Explicit human rights review and purpose required')
    require(type(plan.get('files')) is list and plan['files'], 'No approved file list')
    copies = []
    targets = set()
    total = 0
    for row in plan['files']:
        require(type(row) is dict and all(type(row.get(k)) is str and row[k] for k in ('source','target','sha256','rights_basis')), 'explicit selected-file fields required')
        require(row.get('rights_basis'), 'Each file needs its reviewed rights basis')
        src = safe_path(source, row['source'])
        dst = safe_path(public, row['target'])
        require(src.is_file() and dst not in targets, row['target'])
        raw, mode = selected_bytes(src)
        require(hashlib.sha256(raw).hexdigest() == row['sha256'], row['source'])
        total += len(raw)
        require(total <= MAX_BYTES, 'selected source total exceeds 64 MiB')
        targets.add(dst)
        copies.append((raw, mode, dst))
    # All requested paths/hashes are checked before creating a branch or writing.
    subprocess.run(['git', 'switch', '-c', args.branch, 'origin/main'], cwd=public, check=True)
    for raw, mode, dst in copies:
        safe_path(public, str(dst.relative_to(public)))
        dst.parent.mkdir(parents=True, exist_ok=True)
        safe_path(public, str(dst.relative_to(public)))
        write_selected(dst, raw, mode)
    print(f'Prepared {len(copies)} reviewed files. No commits, history, approval plan or remote writes imported.')
    print('Next: inspect diff, rights/dependencies/secrets; refresh manifest; run relevant checks; create a public draft PR.')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit('REFUSE: ' + str(error))
