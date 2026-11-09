#!/usr/bin/env python3
"""Materialize pinned DEVELOPMENT raw streams in a fresh private quarantine.

No code execution, .realm publication, host application or execution authority.
Validate the complete bounded archive before creating the destination directory.
"""
import argparse
import gzip
import hashlib
import io
import os
import pathlib
import re
import tarfile

from verify_coding_development import parse, read_regular, require, canonical

LIMIT = 64 * 1024 * 1024
FIXED = {'launch.json', 'agent-report.json', 'guest-failure.txt', 'model-server.log',
         'run/events.jsonl', 'run/protected-sentinel',
         'run/candidate/totals.py', 'run/candidate/report.py', 'run/candidate/test_totals.py'}


def plan(data):
    # Bound decompression too: a tiny compressed archive cannot allocate an
    # unbounded stream or introduce links, devices, duplicate names or paths.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        expanded = stream.read(LIMIT + 1)
    require(len(expanded) <= LIMIT, 'decompressed raw limit')
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for member in archive:
            allowed = member.name in FIXED or re.fullmatch(
                r'(?:prompt|response|model-stream|action-partial)-[0-9]{2}\.(?:json|jsonl|txt)', member.name)
            require(allowed and member.name not in files and member.isreg() and
                    member.mode == 0o600 and not member.linkname and not member.pax_headers,
                    'unsupported raw object/path/mode')
            require(0 <= member.size <= LIMIT, 'raw object limit')
            total += member.size
            require(total <= LIMIT and len(files) < 256, 'raw aggregate limit')
            content = archive.extractfile(member).read(member.size + 1)
            require(len(content) == member.size, 'short raw member')
            files[member.name] = content
    require({'launch.json', 'agent-report.json'} <= files.keys(), 'missing development identity/report')
    launch, report = parse(files['launch.json']), parse(files['agent-report.json'])
    require(launch['authority'] == 'NONE' and report['authority'] == 'NONE' and
            report['realm_artifact'] is None, 'received bytes cannot claim authority')
    return files, launch


def receive(args):
    data = read_regular(args.raw, LIMIT)
    require(hashlib.sha256(data).hexdigest() == args.raw_sha256, 'external raw pin differs')
    files, launch = plan(data)
    require(launch['challenge'] == args.challenge, 'external guest challenge differs')
    require(args.root.is_absolute() and not args.root.exists(), 'fresh absolute quarantine required')
    args.root.mkdir(mode=0o700)
    for name, content in files.items():
        path = args.root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    record = {'status': 'DEVELOPMENT_RAW_QUARANTINED', 'authority': 'NONE', 'realm_artifact': None,
              'execution_authenticated': False, 'raw_sha256': args.raw_sha256,
              'challenge': args.challenge, 'run_id': hashlib.sha256(files['launch.json']).hexdigest(),
              'files': {n: hashlib.sha256(c).hexdigest() for n, c in sorted(files.items())}}
    with (args.root / 'raw-custody.json').open('xb') as stream:
        os.chmod(stream.name, 0o600)
        stream.write(canonical(record))
        stream.flush()
        os.fsync(stream.fileno())
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw', required=True, type=pathlib.Path)
    p.add_argument('--raw-sha256', required=True)
    p.add_argument('--challenge', required=True)
    p.add_argument('--root', required=True, type=pathlib.Path)
    args = p.parse_args()
    try:
        print(canonical(receive(args)).decode())
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, EOFError) as error:
        print(canonical({'status': 'REFUSED', 'authority': 'NONE', 'error': str(error)}).decode())
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
