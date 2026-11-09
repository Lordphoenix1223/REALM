#!/usr/bin/env python3
"""Verify the public tree against its declared canonical source snapshot."""
import hashlib
import json
from pathlib import Path, PurePosixPath


def check(root):
    m = json.loads((root / 'SOURCE_MANIFEST.json').read_text())
    require(m['schema'] == 'realm.reviewed-public-export/v1', 'unsupported source manifest')
    require(len(m['source_commit']) == 40 and m['review_basis'], 'missing source identity/review')
    for name, pin in m['files'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name, name)
        p = root / name
        require(not any(x.is_symlink() for x in [p, *p.parents] if x.is_relative_to(root)), name)
        require(p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == pin, name)
    print(f"PASS: {len(m['files'])} shared files match canonical {m['source_commit']}; authority NONE")


def require(condition, diagnostic):
    if not condition:
        raise ValueError(diagnostic)


if __name__ == '__main__':
    check(Path(__file__).resolve().parents[1])
