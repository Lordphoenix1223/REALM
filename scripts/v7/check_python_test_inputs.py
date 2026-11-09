"""Read-only test prerequisite check; never executes a workload or grants authority.

Select groups explicitly. In particular, historical retained-diagnosis inputs
must only be inspected when their existing custody/access restrictions permit it.
Missing prerequisites fail this command; they never skip or pass the tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.v7 import qualification

GROUPS = {
    'termination': {
        'tests': 'scripts.v7.test_audit_termination',
        'archives': {
            'evidence/v7/host-planned-task-20261012/closed-host-planned-probe-012.tar.gz':
                '88d378a15b6e86be464594ed571b94b3569ef079a2161245eeea8f7e8802aa8a',
            'evidence/v7/host-planned-task-20261012/reproduction-013.tar.gz':
                'daebc4176772afeb49f1f53c93dceddc83f37eb72b72dcefb55bc00be9b2d997',
        },
        'git_object': '8cdca3d2fc4603583dad5ded1b7bbb803573ac89:scripts/v7/coding_guest_probe.py',
    },
    'record-relationships': {'tests': 'scripts.v7.test_evidence_graph', 'archives': {}},
    'retained-diagnosis': {
        'tests': 'scripts.v7.test_qualification.RetainedCodingDiagnosisTests',
        'archives': {
            'evidence/v7/clean-closure-018-20261015/closed-clean-probe-018.tar.gz':
                'c8868997e43698d8c40e9595e76cb24e6229bf071af800995680e8f455a7ddae',
        },
    },
}


def inspect(source, groups):
    rows = []
    try:
        identity = qualification.source_identity(source)
        rows.append({'input': 'real Git checkout and verifier source', 'status': 'AVAILABLE',
                     'commit': identity['commit'], 'dirty': identity['dirty']})
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        rows.append({'input': 'real Git checkout and verifier source', 'status': 'UNAVAILABLE',
                     'reason': str(error)})
    for name in groups:
        group = GROUPS[name]
        for relative, pin in group['archives'].items():
            try:
                # Reuse the existing bounded no-follow stable reader. Never
                # repair modes, extract archives or fetch missing input here.
                raw = qualification.evidence_read(source, relative, 16 * 1024 * 1024)
                digest = hashlib.sha256(raw).hexdigest()
                if digest != pin:
                    raise ValueError('historical archive SHA-256 differs')
                rows.append({'group': name, 'input': relative, 'status': 'AVAILABLE', 'sha256': digest})
            except (OSError, ValueError) as error:
                rows.append({'group': name, 'input': relative, 'status': 'UNAVAILABLE',
                             'expected_sha256': pin, 'reason': str(error)})
        if 'git_object' in group:
            try:
                result = subprocess.run(['git', '-C', str(source), 'cat-file', '-e', group['git_object']],
                                        capture_output=True, timeout=10)
                status = 'AVAILABLE' if result.returncode == 0 else 'UNAVAILABLE'
                reason = result.stderr.decode(errors='replace')
            except (OSError, subprocess.TimeoutExpired) as error:
                status, reason = 'UNAVAILABLE', str(error)
            rows.append({'group': name, 'input': group['git_object'], 'status': status, 'reason': reason})
    ready = all(row['status'] == 'AVAILABLE' for row in rows)
    return {'schema': 'realm.python-test-inputs/v1', 'authority': 'NONE', 'release_ready': False,
            'source': str(source), 'groups': groups, 'tests': [GROUPS[g]['tests'] for g in groups],
            'status': 'INPUTS_AVAILABLE' if ready else 'TEST_INPUTS_UNAVAILABLE',
            'test_execution': 'NOT_RUN', 'inputs': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--group', action='append', choices=GROUPS, required=True)
    args = parser.parse_args()
    report = inspect(args.source.resolve(strict=True), list(dict.fromkeys(args.group)))
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'INPUTS_AVAILABLE' else 2


if __name__ == '__main__':
    raise SystemExit(main())
