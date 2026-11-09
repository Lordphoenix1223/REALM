#!/usr/bin/env python3
"""Independent read-only Stage 8 oracle. No executor verdict is an input.

The Rust verifier separately authenticates the artifact, graph and journal. This
process independently decodes the FROZEN raw archive to derive expected bytes,
compares exact directory membership/bytes/modes/link counts, then checks the
physical journal sequence and raw-byte BLAKE3 links using the pinned hash binary.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

from coding_worker import parse


def require(ok, message):
    if not ok:
        raise ValueError(message)


def outputs(raw):
    magic = b'REALM-PORTABLE-3\n'
    require(raw.startswith(magic) and len(raw) <= 2 * 1024 * 1024, 'artifact format/size')
    offset = len(magic)
    def take(n):
        nonlocal offset
        require(0 <= n <= len(raw) - offset, 'truncated archive')
        value = raw[offset:offset+n]
        offset += n
        return value
    def frame():
        return take(struct.unpack('>Q', take(8))[0])
    run, _ = parse(frame())
    blobs = {}
    for _ in range(struct.unpack('>I', take(4))[0]):
        name = frame().decode()
        require(name not in blobs, 'duplicate blob')
        blobs[name] = frame()
    require(offset == len(raw), 'trailing archive bytes')
    require(run['lifecycle'] == 'sealed' and len(run['outputs']) == 3, 'unfinalized plan')
    return {name: blobs[ref['digest']['value']] for name, ref in zip(
        ('totals.py', 'report.py', 'test_totals.py'), run['outputs'])}


def verify(artifact, destination, state, hasher):
    expected = outputs(artifact.read_bytes())
    require(set(os.listdir(destination)) == set(expected), 'unexpected or missing destination object')
    observed = {}
    for name, data in expected.items():
        path = destination / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid() and info.st_nlink == 1, 'permissions/type/links/owner differ')
        require(path.read_bytes() == data, 'actual bytes differ')
        observed[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                          'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink}
    require(set(os.listdir(state)) == {'journal.jsonl', 'receipt.json'}, 'unexpected state entry')
    raw = (state/'journal.jsonl').read_bytes()
    require(raw.endswith(b'\n'), 'torn journal')
    lines = raw.splitlines()
    require(len(lines) == 11, 'incomplete execution history')
    rows = [parse(line) for line in lines]
    expected_phases = ['AUTHORIZED'] + ['STAGED', 'LINKED', 'COMPLETE'] * 3 + ['FINISHED']
    for i, (line, row) in enumerate(zip(lines, rows)):
        require(row['sequence'] == i and row['phase'] == expected_phases[i], 'reordered execution')
        require(row['operation'] == (None if i in (0, 10) else (i-1)//3), 'wrong operation order')
        require(row['plan'] == rows[0]['plan'] and row['approval'] == rows[0]['approval'], 'policy changed')
        if i == 0:
            previous = '0'*64
        else:
            # Read-only hasher consumes stdin; no temporary writes or journal
            # serialization assumptions in this independent process.
            previous = subprocess.check_output([str(hasher), 'hash-stdin'], input=lines[i-1]).decode().strip()
        require(row['previous'] == previous, 'journal hash chain differs')
    return {'status': 'PASS_INDEPENDENT_FINAL_STATE', 'authority': 'NONE', 'files': observed,
            'ordered_operations': 3, 'journal_rows': len(rows), 'unexpected_entries': []}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(*(Path(p) for p in sys.argv[1:]))))
    except (ValueError, OSError, KeyError) as error:
        print(json.dumps({'status': 'REFUSE', 'error': str(error)}))
        raise SystemExit(1)
