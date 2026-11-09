#!/usr/bin/env python3
"""Classify changed paths for bounded public CI; no execution qualification."""
import argparse
import fnmatch
import json
from pathlib import Path
import subprocess

NATIVE = ('crates/**', 'Cargo.*', 'rust-toolchain.toml', 'realm', 'scripts/v7/**',
          'integrations/**', 'examples/**', 'benchmarks/**', 'schemas/**', 'contracts/**',
          'docs/**/*.json', 'tools/**', '.devcontainer/**', '.github/workflows/**')
V7 = ('scripts/v7/**', 'crates/realm-v6/**', 'crates/realm-artifact/**', 'crates/realm-cli/**',
      'integrations/python/**', 'schemas/**', 'contracts/**', 'docs/**/*.json',
      'tools/dev.py', 'tools/ci_paths.py', 'tools/test_ci_paths.py', '.github/workflows/**')


def classify(paths):
    paths = sorted(set(paths))
    # Unknown/new schemas are conservative even outside established directories.
    native = any(any(fnmatch.fnmatchcase(p, pattern) for pattern in NATIVE)
                 or p.endswith('.schema.json') for p in paths)
    v7 = any(any(fnmatch.fnmatchcase(p, pattern) for pattern in V7)
             or p.endswith('.schema.json') for p in paths)
    return {'native': native, 'v7': v7, 'security_and_manifests': True,
            'paths': paths, 'qualification': 'NOT_RUN', 'authority': 'NONE'}


def changed(root, base, head):
    for revision in (base, head):
        if not revision or revision.startswith('-'):
            raise ValueError('explicit non-option revisions required')
    return subprocess.check_output(['git', 'diff', '--no-renames', '--name-only', '-z',
                                    base, head, '--'], cwd=root).decode().split('\0')[:-1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', required=True)
    p.add_argument('--head', default='HEAD')
    p.add_argument('--github-output', type=Path)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    if set(a.base) == {'0'}:
        paths = subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')[:-1]
    else:
        paths = changed(root, a.base, a.head)
    result = classify(paths)
    if a.github_output:
        with a.github_output.open('a') as out:
            for key in ('native', 'v7'):
                out.write(key+'='+str(result[key]).lower()+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
