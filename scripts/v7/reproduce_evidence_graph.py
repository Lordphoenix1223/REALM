"""Retain real signed UNIT_TEST record controls, without any execution authority."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from scripts.v7 import qualification as q
from scripts.v7.test_evidence_graph import EvidenceGraphTests


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True, help='Fresh absolute directory outside checkout')
    args = p.parse_args()
    source = Path(__file__).resolve().parents[2]
    output = args.output
    if not output.is_absolute() or source in (output.resolve(), *output.resolve().parents):
        p.error('fresh absolute output outside checkout required')
    identity = q.source_identity(source)
    if identity['dirty']:
        p.error('commit the intended source before reproducing a campaign')
    output.mkdir(mode=0o700)
    rows = []
    EvidenceGraphTests.setUpClass()
    case = EvidenceGraphTests('test_valid_authenticated_relationships_accept_but_cannot_qualify_fake_artifact')
    try:
        case.setUp()
        original_statements = copy.deepcopy(case.statements); original_policy = copy.deepcopy(case.policy)
        for label in ('valid-unit-records', 'forged-hardware-label', 'cross-run', 'wrong-role',
                      'incomplete-effects', 'stale-destination', 'corrupt-artifact', 'path-escape', 'interrupted-application'):
            case.statements = copy.deepcopy(original_statements); case.policy = copy.deepcopy(original_policy)
            wrong = None
            if label == 'forged-hardware-label': case.policy['evidence_class'] = 'MEASURED_HARDWARE'
            if label == 'cross-run': case.statements['effects']['predicate']['context']['run_id'] = 'other-run'
            if label == 'wrong-role': wrong = ('approval', 'agent')
            if label == 'incomplete-effects': case.statements['effects']['predicate']['result']['history_complete'] = False
            if label == 'stale-destination': case.statements['approval']['predicate']['result']['before_root'] = '0' * 64
            if label == 'interrupted-application': case.statements['application']['predicate']['result']['status'] = 'INTERRUPTED'
            case.emit(wrong_signer=wrong)
            if label == 'path-escape':
                case.graph['records']['artifact']['name'] = '../trust/policy.json'; case.write_manifest()
            directory = output / label; directory.mkdir()
            shutil.copytree(case.root, directory / 'evidence'); shutil.copytree(case.trust, directory / 'trust')
            if label == 'corrupt-artifact': (directory / 'evidence/candidate.realm').write_bytes(b'CORRUPTED_UNIT_FIXTURE')
            command = [sys.executable, '-B', '-m', 'scripts.v7.qualification', 'relationships',
                       '--root', str(directory / 'evidence'), '--policy-root', str(directory / 'trust'),
                       '--policy-sha256', case.policy_pin]
            started = time.perf_counter_ns()
            process = subprocess.run(command, cwd=source, capture_output=True, timeout=30)
            (directory / 'stdout.json').write_bytes(process.stdout); (directory / 'stderr.txt').write_bytes(process.stderr)
            result = json.loads(process.stdout)
            expected = 3 if label in ('valid-unit-records', 'forged-hardware-label') else 2
            rows.append({'case': label, 'argv': command, 'exit': process.returncode, 'expected_exit': expected,
                         'record_relationships_accepted': result.get('record_relationships_accepted', False),
                         'release_ready': result['release_ready'], 'elapsed_ns': time.perf_counter_ns() - started})
            # Retain outputs before raising on an unexpected result.
            (output / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
            if process.returncode != expected or result['release_ready'] is not False:
                raise RuntimeError('unexpected graph result: ' + label)
        report = {'schema': 'realm.v7.relationship-control-campaign/v1', 'source': identity,
                  'python': sys.version, 'authority': 'NONE', 'release_ready': False,
                  'controls': rows, 'scope': 'UNIT_TEST signed-record relationships; no KVM, native artifact or host application',
                  'private_keys_exported': False, 'all_expected_results': True}
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        hashes = {str(f.relative_to(output)): {'bytes': f.stat().st_size, 'sha256': q.sha(f.read_bytes())}
                  for f in sorted(output.rglob('*')) if f.is_file()}
        (output / 'SHA256SUMS.json').write_text(json.dumps(hashes, indent=2) + '\n')
        print('PASS:', len(rows), 'signed-record CLI controls; full release remains unqualified')
    finally:
        case.doCleanups(); EvidenceGraphTests.doClassCleanups()


if __name__ == '__main__':
    main()
