#!/usr/bin/env python3
"""Scan selected public files for concrete secret markers; not security clearance."""
import re
from pathlib import Path
import subprocess

PATTERNS = [rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----',
            rb'gh[pousr]_[A-Za-z0-9]{30,}', rb'github_pat_[A-Za-z0-9_]{40,}',
            rb'AKIA[A-Z0-9]{16}', rb'sk-(?:proj-)?[A-Za-z0-9_-]{35,}',
            rb'/Users/[A-Za-z0-9_.-]+/(?:Documents|\.codex|\.ssh)/']


def findings(name, raw):
    reasons = []
    if name.split('/')[0].lower() in {'evidence','diagnostics','research','output'}:
        reasons.append('private output category')
    if any(part.lower().startswith('.env') for part in Path(name).parts):
        reasons.append('environment file')
    if any(re.search(pattern, raw) for pattern in PATTERNS):
        reasons.append('credential or private machine path marker')
    return reasons


def main():
    root = Path(__file__).resolve().parents[1]
    names = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')[:-1]
    bad = []
    for name in sorted(set(names)):
        p = root/name
        if p.is_file() and not p.is_symlink():
            for reason in findings(name,p.read_bytes()):
                bad.append(name+': '+reason)
    if bad:
        raise SystemExit('FAIL public marker scan (values withheld):\n'+'\n'.join(bad))
    print(f'PASS: {len(set(names))} selected public paths scanned; no listed markers. Not proof of secret absence or legal rights.')


if __name__ == '__main__':
    main()
