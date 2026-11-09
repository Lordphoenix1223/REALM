#!/usr/bin/env python3
"""Promote a reviewed, hash-pinned source snapshot without importing private history.

check exits 1 on drift. prepare writes only approved bytes into a clean public
checkout; it never commits or pushes. publish opens/updates a draft PR using the
caller's separately scoped gh credential. No pull-request code receives secrets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

PUBLIC = 'https://github.com/Lordphoenix1223/REALM.git'
REPO = 'Lordphoenix1223/REALM'
DENIED = {'.git', '.ssh', '.aws', 'evidence', 'diagnostics', 'output', 'research'}


def run(root, *args):
    return subprocess.check_output(list(args), cwd=root).decode().strip()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_path(name):
    p = PurePosixPath(name)
    if (not name or p.is_absolute() or str(p) != name or '..' in p.parts
            or DENIED.intersection(x.lower() for x in p.parts)
            or any(x.lower().startswith('.env') for x in p.parts)):
        raise ValueError('restricted export path: ' + name)
    return p


def blob(root, revision, name):
    validate_path(name)
    entry = run(root, 'git', 'ls-tree', revision, '--', name).split()
    if len(entry) < 4 or entry[0] not in ('100644', '100755') or entry[1] != 'blob':
        raise ValueError('missing/nonregular source: ' + name)
    raw = subprocess.check_output(['git', 'show', revision + ':' + name], cwd=root)
    if len(raw) > 2_000_000 or b'\0' in raw:
        raise ValueError('binary/oversize source requires separate review: ' + name)
    for pattern in [rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----',
                    rb'gh[pousr]_[A-Za-z0-9]{30,}', rb'AKIA[A-Z0-9]{16}',
                    rb'sk-(?:proj-)?[A-Za-z0-9_-]{35,}']:
        if re.search(pattern, raw):
            raise ValueError('credential marker requires review: ' + name)
    return raw, int(entry[0], 8)


def load(root, manifest):
    m = json.loads(manifest.read_text())
    if m['schema'] != 'realm.reviewed-public-export/v1' or not m['review_basis']:
        raise ValueError('missing export review')
    rev = m['source_commit']
    if not re.fullmatch('[0-9a-f]{40}', rev):
        raise ValueError('source must be an immutable full commit')
    for name, pin in m['files'].items():
        if digest(blob(root, rev, name)[0]) != pin:
            raise ValueError('reviewed source hash mismatch: ' + name)
    return m


def report(root, m, revision, public):
    changed, missing, unpublished = [], [], []
    approved = m['files']
    for name, pin in approved.items():
        try:
            actual = digest(blob(root, revision, name)[0])
        except (ValueError, subprocess.CalledProcessError):
            actual = None
        if actual != pin:
            changed.append(name)
        if public is not None:
            path = public / name
            if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != pin:
                unpublished.append(name)
    paths = run(root, 'git', 'ls-tree', '-r', '--name-only', revision).splitlines()
    for name in paths:
        if any(name.startswith(prefix) for prefix in m['shared_prefixes']):
            if name not in approved and name not in m['excluded_files']:
                missing.append(name)
    commits = run(root, 'git', 'log', '--format=%H', m['source_commit'] + '..' + revision,
                  '--', *m['shared_prefixes']).splitlines()
    return {'schema': 'realm.public-sync-report/v1', 'source_commit': m['source_commit'],
            'current_commit': run(root, 'git', 'rev-parse', revision),
            'unreviewed_changed_files': sorted(changed), 'unreviewed_new_files': sorted(missing),
            'unpublished_approved_files': sorted(unpublished), 'source_commits_since_review': commits,
            'authority': 'NONE'}


def public_root(path):
    path = path.resolve()
    if run(path, 'git', 'remote', 'get-url', 'origin') != PUBLIC:
        raise ValueError('public origin mismatch')
    if run(path, 'git', 'status', '--porcelain'):
        raise ValueError('public checkout must be clean')
    return path


def prepare(root, m, public):
    public = public_root(public)
    # Check every approved byte and destination before any write.
    writes = []
    for name in m['files']:
        raw, mode = blob(root, m['source_commit'], name)
        if digest(raw) != m['files'][name]:
            raise ValueError('reviewed source hash mismatch: ' + name)
        dest = public / name
        if any(p.is_symlink() for p in [dest, *dest.parents] if p.is_relative_to(public)):
            raise ValueError('symlink destination: ' + name)
        writes.append((dest, raw, mode))
    old = public / 'SOURCE_MANIFEST.json'
    previous = json.loads(old.read_text())['files'] if old.exists() else {}
    # Never silently delete removed exports: reviewers must account for deletions.
    removed = set(previous) - set(m['files'])
    if removed:
        raise ValueError('explicit public deletion review required: ' + ', '.join(sorted(removed)))
    for dest, raw, mode in writes:
        dest.parent.mkdir(parents=True, exist_ok=True)
        replace_file(dest, raw, mode)
    replace_file(public / 'SOURCE_MANIFEST.json', (json.dumps(m, indent=2) + '\n').encode(), 0o644)


def replace_file(dest, raw, mode):
    # Atomic replacement cannot write through a pre-existing hardlink/symlink.
    fd, name = tempfile.mkstemp(prefix='.realm-sync-', dir=dest.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), mode & 0o777)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, dest)
    finally:
        Path(name).unlink(missing_ok=True)


def publish(root, m, public, branch, base, validation):
    public = public_root(public)
    if not validation or not validation.is_file():
        raise ValueError('supply retained validation report before publishing')
    if not branch.startswith('codex/sync-') or base not in ('main', 'codex/v7-preview'):
        raise ValueError('use a dedicated codex/sync- branch and reviewed public base')
    subprocess.run(['git', 'check-ref-format', '--branch', branch], check=True, capture_output=True)
    run(public, 'git', 'fetch', 'origin', base)
    if run(public, 'git', 'rev-parse', 'HEAD') != run(public, 'git', 'rev-parse', 'origin/' + base):
        raise ValueError('start from fetched public base')
    run(public, 'git', 'switch', '-c', branch)
    prepare(root, m, public)
    run(public, sys.executable, 'tools/check_release.py', '--refresh')
    run(public, sys.executable, 'tools/check_release.py')
    run(public, sys.executable, 'tools/check_source_manifest.py')
    paths = [*m['files'], 'SOURCE_MANIFEST.json', 'EXPORT_MANIFEST.json']
    subprocess.run(['git', 'add', '--', *paths], cwd=public, check=True)
    diff = run(public, 'git', 'diff', '--cached', '--name-status')
    if not diff:
        return
    message = 'feat(sync): promote reviewed canonical source ' + m['source_commit'][:12]
    run(public, 'git', 'diff', '--cached', '--check')
    run(public, 'git', 'commit', '-m', message)
    run(public, 'git', 'push', '-u', 'origin', branch)
    # Raw validation stays private. Publish its hash and approved claims only.
    body = ('Promote reviewed canonical source `' + m['source_commit'] + '`.\n\n'
            'Source manifest lists every promoted path/hash and explicit exclusions. '
            'No private history, evidence, VM assets or credentials are imported.\n\n'
            'Validation report SHA256: `' + digest(validation.read_bytes()) + '`. '
            'Local manifest, exact source correspondence and release checks passed. '
            'Native qualification remains NOT_RUN; authority NONE.\n\n'
            '```text\n' + diff + '\n```\n')
    # Each immutable source revision gets an idempotent PR; never force-push.
    prs = json.loads(run(public, 'gh', 'pr', 'list', '--repo', REPO, '--head', branch,
                         '--state', 'open', '--json', 'number'))
    body_file = public / '.git-sync-body.tmp'
    try:
        body_file.write_text(body)
        if prs:
            run(public, 'gh', 'pr', 'edit', str(prs[0]['number']), '--repo', REPO,
                '--title', message, '--body-file', str(body_file))
        else:
            print(run(public, 'gh', 'pr', 'create', '--repo', REPO, '--draft', '--base', base,
                      '--head', branch, '--title', message, '--body-file', str(body_file)))
    finally:
        body_file.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['check', 'prepare', 'publish'])
    p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--manifest', type=Path)
    p.add_argument('--revision', default='HEAD')
    p.add_argument('--public', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--branch')
    p.add_argument('--base', default='main')
    p.add_argument('--validation', type=Path)
    a = p.parse_args()
    root = a.source.resolve()
    m = load(root, a.manifest or root / 'config/public-export.json')
    r = report(root, m, a.revision, a.public)
    if a.output:
        a.output.write_text(json.dumps(r, indent=2) + '\n')
    print(json.dumps(r, indent=2))
    if r['unreviewed_changed_files'] or r['unreviewed_new_files']:
        raise SystemExit(1)
    if a.mode == 'check':
        raise SystemExit(int(bool(r['unpublished_approved_files'])))
    if not a.public:
        p.error('--public is required for preparation/publication')
    if a.mode == 'prepare':
        prepare(root, m, a.public)
    else:
        if not a.branch:
            p.error('--branch is required')
        publish(root, m, a.public, a.branch, a.base, a.validation)


if __name__ == '__main__':
    main()
