"""Independent V7 readiness/evidence intake. No execution or release authority.

The current coding profile has no registered full-pipeline verifier. Therefore
well-formed, hash-pinned evidence is always INCOMPLETE, never QUALIFIED. A future
positive gate requires reviewed authoritative adapters, not a flag or PASS row.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import time
import tarfile
import tempfile
from types import SimpleNamespace
import uuid

from scripts.v7 import coding_worker as worker
from scripts.v7 import verify_coding_development as independent

SCHEMA = 'realm.v7.qualification-case/v1'
PROFILE = 'realm.v7.coding-totals/v1'
MAX_MANIFEST = 1024 * 1024
MAX_EVIDENCE = 32 * 1024 * 1024
CLASSIFICATIONS = {'NOT_RUN', 'UNIT_TEST', 'SIMULATED', 'LOCAL_REPLAY',
                   'MEASURED_HARDWARE', 'AUTONOMOUS_AGENT', 'HOST_APPLICATION',
                   'READ_ONLY_AUDIT'}
CONTROLS = ('unauthorized-intermediate-effects', 'malformed-artifact',
            'incomplete-observation', 'stale-destination', 'tampered-evidence',
            'path-escape', 'mismatched-authority', 'application-crash-recovery',
            'misleading-task-success', 'fresh-repeat')
# Matches the repository's established nine-step architecture, not a second flow.
STEPS = (
    ('intake', 'Explicit reviewed task predicate and independent user provenance',
     'scripts/v7/coding_worker.py', 'No authenticated coding intake'),
    ('snapshot-isolation', 'Fresh Linux/KVM measured coding profile and confinement',
     'crates/realm-v6/src/measured_launch.rs', 'C0 measurement is not coding qualification'),
    ('autonomous-agent', 'Autonomous planner with confined measured guest tools and declared uncaptured inputs',
     'scripts/v7/coding_worker.py', 'No authenticated coding execution/provenance join; external planner inputs remain outside capture'),
    ('independent-outcome', 'Trusted effect observation and independent same-run semantics',
     'scripts/v7/verify_coding_development.py', 'Transcript integrity is not authenticated effect history'),
    ('publication-authority', 'Opaque same-run coding verification/publication capability',
     'crates/realm-v6/src/publication.rs', 'No reviewed coding publication join'),
    ('canonical-artifact', 'New coding .realm artifact, receipt and lifecycle evidence',
     'crates/realm-artifact/src/lib.rs', 'No production coding artifact profile'),
    ('client-verification', 'Independent exact-head trust and separate destination approval',
     'crates/realm-artifact/src/host_apply/coding_transfer.rs', 'Canonical coding adapter exists; native coding-scoped same-run proof unavailable'),
    ('restricted-application', 'Approved ordered coding effects with durable reconciliation',
     'crates/realm-artifact/src/host_apply/coding_lifecycle.rs', 'Ordered receiver/public CLI campaign exist; genuine native coding publication unavailable'),
    ('final-verification', 'Independent destination observation joined to the actual coding run',
     'crates/realm-artifact/src/host_apply.rs', 'No qualified coding application to observe'),
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def relative(name):
    need(type(name) is str and name and '\\' not in name and '\x00' not in name,
         'invalid evidence path')
    path = PurePosixPath(name)
    need(bool(path.parts) and not path.is_absolute() and str(path) == name and
         all(part not in ('..', '.') for part in path.parts), 'evidence path escape or alias')
    return path.parts


def evidence_read(root, name, limit):
    """Open every component relative to held no-follow directory descriptors.

    Bounded stable regular-file reads; no atomic whole-tree or hostile-root claim.
    """
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts, 'absolute unaliased evidence root required')
    fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in (*root.parts[1:], *relative(name)[:-1]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        leaf = relative(name)[-1]
        f = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(f)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 before.st_uid == os.getuid() and before.st_size <= limit,
                 'evidence must be an owned single-link bounded regular file')
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(f, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                        info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            need(len(data) == before.st_size and
                 identity(before) == identity(os.fstat(f)) ==
                 identity(os.stat(leaf, dir_fd=fd, follow_symlinks=False)),
                 'evidence changed or exceeded its bound')
            return bytes(data)
        finally:
            os.close(f)
    finally:
        os.close(fd)


def source_identity(source):
    source = Path(source).resolve(strict=True)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args],
                                       stderr=subprocess.PIPE).decode().strip()
    need(Path(git('rev-parse', '--show-toplevel')).resolve() == source, 'source must be the checkout root')
    modules = {'scripts/v7/qualification.py': Path(__file__),
               'scripts/v7/coding_worker.py': Path(worker.__file__),
               'scripts/v7/verify_coding_development.py': Path(independent.__file__)}
    module_hashes = {}
    for name, imported in modules.items():
        module_hashes[name] = sha(evidence_read(source, name, MAX_MANIFEST))
        need(module_hashes[name] == sha(imported.read_bytes()),
             'running verifier/worker differs from the pinned source checkout')
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'dirty': bool(git('status', '--porcelain=v1', '--untracked-files=all')),
            'cargo_lock_sha256': sha(evidence_read(source, 'Cargo.lock', MAX_MANIFEST)),
            'verifier_sha256': sha(Path(__file__).read_bytes()), 'modules': module_hashes}


def doctor(source):
    return {'schema': 'realm.v7.readiness/v1', 'authority': 'NONE',
            'release_ready': False, 'source': source_identity(source),
            'local_environment': {'os': platform.system(), 'architecture': platform.machine(),
                                  'python': platform.python_version(),
                                  'kvm_node_present': Path('/dev/kvm').exists(),
                                  'kvm_execution_tested': False},
            'steps': [{'step': i, 'id': key, 'requirement': req,
                       'component': component, 'status': 'NOT_QUALIFIED', 'blocker': blocker}
                      for i, (key, req, component, blocker) in enumerate(STEPS, 1)],
            'required_controls': list(CONTROLS),
            'blocking_interface': 'No registered production verifier for realm.v7.coding-totals/v1',
            'limits': ['Source/component inspection only; no guest, model or cloud execution',
                       'V6 evidence and authored/local replays cannot qualify this coding profile',
                       'Campaign failure-list completeness and environment declarations are not independently authenticated']}


def prepare(source, output):
    output = Path(output)
    need(output.is_absolute(), 'absolute fresh output required')
    need(Path(source).resolve() not in (output.resolve(), *output.resolve().parents),
         'campaign output must be outside the source checkout')
    identity = source_identity(source)
    need(not identity['dirty'], 'freeze a clean source commit before preparing a campaign')
    output.mkdir(mode=0o700)
    case = {'schema': SCHEMA, 'profile': PROFILE, 'source': identity,
            'campaign_id': str(uuid.uuid4()), 'run_id': None, 'task': worker.contract(),
            'task_sha256': sha(canonical(worker.contract())),
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'environment': {'worker': None, 'destination': None, 'model': None, 'profile_sha256': None},
            'observations': [], 'controls': [], 'failures': []}
    raw = canonical(case) + b'\n'
    with open(output / 'case.json', 'xb') as f:
        os.fchmod(f.fileno(), 0o600); f.write(raw); f.flush(); os.fsync(f.fileno())
    return {'status': 'CAMPAIGN_PREPARED_NOT_EXECUTED', 'authority': 'NONE',
            'release_ready': False, 'case': str(output / 'case.json'),
            'case_sha256': sha(raw), 'campaign_id': case['campaign_id'], 'run_id': None,
            'task_sha256': case['task_sha256'],
            'instruction': 'Retain every attempted run and failure; review the predicate before execution. '
                           'Externally pin the final case digest after collecting evidence.'}


def assess(case_root, case_pin, source):
    started = time.perf_counter_ns()
    need(re.fullmatch('[0-9a-f]{64}', case_pin) is not None, 'invalid external case digest')
    raw = evidence_read(case_root, 'case.json', MAX_MANIFEST)
    need(sha(raw) == case_pin, 'external case digest differs')
    case = independent.parse(raw)
    fields = {'schema', 'profile', 'source', 'campaign_id', 'run_id', 'task', 'task_sha256',
              'created_utc', 'environment', 'observations', 'controls', 'failures'}
    need(type(case) is dict and set(case) == fields and case['schema'] == SCHEMA,
         'unsupported case fields/schema; a release_ready flag is not evidence')
    need(case['profile'] == PROFILE, 'C0 or another task profile cannot stand in for V7 coding')
    current = source_identity(source)
    need(canonical(case['source']) == canonical(current), 'exact source, tree, lock, verifier or cleanliness differs')
    need(not current['dirty'], 'source is dirty')
    need(type(case['campaign_id']) is str and str(uuid.UUID(case['campaign_id'])) == case['campaign_id'],
         'invalid campaign ID')
    need(case['run_id'] is None or (type(case['run_id']) is str and
         re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', case['run_id']) is not None), 'invalid producer run ID')
    need(canonical(case['task']) == canonical(worker.contract()) and
         case['task_sha256'] == sha(canonical(case['task'])), 'task predicate/identity differs')
    need(type(case['failures']) is list and len(case['failures']) <= 1000, 'failure retention differs')
    need(type(case['environment']) is dict and
         set(case['environment']) == {'worker', 'destination', 'model', 'profile_sha256'},
         'environment identities must remain explicit')
    observations = case['observations']
    need(type(observations) is list and len(observations) <= 1000, 'observation bound differs')
    need(not observations or case['run_id'] is not None, 'observations require the actual producer run ID')
    checked = []
    total_bytes = 0
    references = 0
    for row in observations:
        need(type(row) is dict and set(row) == {'step', 'classification', 'status', 'source_commit',
                                              'run_id', 'files'}, 'invalid observation shape')
        need(type(row['step']) is int and 1 <= row['step'] <= 9 and
             row['classification'] in CLASSIFICATIONS and row['status'] in {'PASS', 'FAIL', 'UNKNOWN', 'NOT_RUN'},
             'invalid evidence classification')
        need(row['source_commit'] == current['commit'] and row['run_id'] == case['run_id'],
             'cross-source or cross-run evidence join refused')
        need(type(row['files']) is list and 1 <= len(row['files']) <= 100, 'raw evidence required')
        seen = set()
        for pin in row['files']:
            need(type(pin) is dict and set(pin) == {'path', 'sha256', 'bytes'}, 'invalid evidence pin')
            need(pin['path'] not in seen, 'duplicate evidence reference'); seen.add(pin['path'])
            need(type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_EVIDENCE, 'invalid evidence size')
            references += 1
            total_bytes += pin['bytes']
            need(references <= 128 and total_bytes <= 64 * 1024 * 1024, 'campaign evidence budget exceeded')
            data = evidence_read(case_root, pin['path'], MAX_EVIDENCE)
            need(len(data) == pin['bytes'] and sha(data) == pin['sha256'], 'raw evidence pin differs')
        checked.append(row)
    need(type(case['controls']) is list and all(type(c) is str and c in CONTROLS for c in case['controls'])
         and len(set(case['controls'])) == len(case['controls']), 'invalid or duplicate control declarations')
    need(source_identity(source) == current, 'source changed during assessment')
    need(sha(evidence_read(case_root, 'case.json', MAX_MANIFEST)) == case_pin, 'case changed during assessment')
    report = doctor(source)
    need(canonical(report['source']) == canonical(current), 'source changed before reporting')
    report.update(schema='realm.v7.qualification-report/v1', status='INCOMPLETE',
                  campaign_id=case['campaign_id'], run_id=case['run_id'], profile=PROFILE, case_sha256=case_pin,
                  task_sha256=case['task_sha256'],
                  observations=checked, failures=case['failures'],
                  declared_execution_environment=case['environment'], verified_execution_environment=None,
                  raw_evidence_integrity='CHECKED', execution_authenticated=False,
                  measured_coding_qualified=False, trusted_effect_history_complete=False,
                  observed_control_declarations=case['controls'],
                  verified_controls=[], missing_verified_controls=list(CONTROLS),
                  elapsed_ns=time.perf_counter_ns() - started,
                  evidence_scope='Hash custody and exact-source/run linkage only; supplied PASS and class labels are unverified')
    # There is intentionally no path from caller-authored rows to QUALIFIED.
    return report


def inspect_development(root, pins):
    """Reopen a local transcript with externally supplied pins, without executing candidate code."""
    from integrations.research_feedback import observe_coding
    expected = {'contract', 'contract_sha256', 'worker_sha256', 'interpreter_sha256', 'journal_head'}
    need(type(pins) is dict and set(pins) == expected, 'invalid development trust pin set')
    started = time.perf_counter_ns()
    result = independent.audit(Path(root), pins['contract'], pins['contract_sha256'],
                               pins['worker_sha256'], pins['interpreter_sha256'], pins['journal_head'])
    feedback = observe_coding(Path(root) / 'candidate')
    need(result['files'] == {name: metadata['sha256'] for name, metadata in
                              feedback['observation']['diagnostic']['snapshot']['files'].items()},
         'candidate changed between independent transcript and advisory snapshots')
    return {'schema': 'realm.v7.preview-inspection/v1', 'authority': 'NONE', 'release_ready': False,
            'trust_input_sha256': sha(canonical(pins)),
            'independent_verifier_sha256': sha(Path(independent.__file__).read_bytes()),
            'transcript': result, 'advisory': feedback,
            'elapsed_ns': time.perf_counter_ns() - started,
            'limits': ['Read-only local transcript and current-state check',
                       'No authenticated agent execution, complete effect history or coding artifact authority']}



def diagnose_run(source, archive, archive_pin):
    """Cold diagnostic using existing intake/auditor/closure code, never an issuer.

    An external archive digest authenticates bytes to its holder, not execution
    or signer authority. No candidate code runs and no retained file is edited.
    """
    identity = source_identity(source)
    need(re.fullmatch('[0-9a-f]{64}', archive_pin) is not None, 'invalid archive digest')
    data = evidence_read(archive.parent, archive.name, 8 * 1024 * 1024)
    need(sha(data) == archive_pin, 'external archive digest differs')
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        expanded = stream.read(16 * 1024 * 1024 + 1)
    need(len(expanded) <= 16 * 1024 * 1024, 'retained archive expansion limit')
    files, modes = {}, {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as bundle:
        for member in bundle:
            relative(member.name)
            need(member.isfile() and not member.linkname and member.name not in files and
                 len(files) < 256 and 0 <= member.size <= 16 * 1024 * 1024,
                 'unsupported retained archive object')
            content = bundle.extractfile(member).read(member.size + 1)
            need(len(content) == member.size, 'short retained archive object')
            files[member.name], modes[member.name] = content, member.mode & 0o7777
    profile = independent.parse(files['run/profile.json'])
    result = independent.parse(files['run/probe-result.json'])
    header = independent.parse(files['run/raw-header.json'])
    need(all(type(v) is dict for v in (profile, result, header)), 'retained record shape differs')
    raw = files['run/guest-raw.tar.gz']
    retained_driver = files['executed-source/scripts/v7/coding_guest_probe.py']
    need(sha(retained_driver) == profile['driver_sha256'], 'retained driver pin differs')
    need(header['challenge'] == profile['challenge'] and header['sha256'] == sha(raw) and
         type(header['size']) is int and header['size'] == len(raw), 'raw identity differs')
    # These existing script entry points also support direct execution. Resolve
    # their normal sibling imports from this checked source tree, not evidence.
    sibling = str(Path(__file__).resolve().parent)
    sys.path.insert(0, sibling)
    try:
        import coding_guest_probe as probe
        import receive_coding_raw as intake
        import coding_native_client as native
    finally:
        sys.path.pop(0)
    module_pins = {}
    for module in (probe, intake, native, native.worker, probe.planner):
        path = Path(module.__file__).resolve()
        name = str(path.relative_to(Path(__file__).resolve().parents[2]))
        module_pins[name] = sha(evidence_read(source, name, MAX_MANIFEST))
        need(module_pins[name] == sha(path.read_bytes()), 'diagnostic module source differs')
    raw_files, launch = intake.plan(raw)
    need(launch['challenge'] == profile['challenge'], 'guest launch challenge differs')
    binding = profile['native_submission_binding']
    packet = native.packet(files['run/native/custody/output'], binding)
    worker_pin = profile['planner_source_pins']['worker']
    need(worker_pin == sha(files['executed-source/scripts/v7/coding_worker.py']) ==
         sha(Path(worker.__file__).read_bytes()), 'unsupported retained worker source')
    need(launch['native_submission_binding'] == binding and
         binding['task_sha256'] == sha(worker.encoded(worker.contract())), 'task/run join differs')
    events = [independent.parse(line) for line in raw_files['run/events.jsonl'].splitlines()]
    checks = [row['event']['result'] for row in events
              if row['event'].get('request', {}).get('tool') == 'check']
    need(checks and packet['transcript_head'] == events[-1]['sha256'], 'submission head differs')
    with tempfile.TemporaryDirectory(prefix='realm-coding-intake-') as temporary:
        scratch = Path(temporary).resolve()
        incoming = scratch / 'raw.gz'; incoming.write_bytes(raw); incoming.chmod(0o600)
        quarantine = scratch / 'guest'
        intake.receive(SimpleNamespace(raw=incoming, raw_sha256=sha(raw), root=quarantine,
                                       challenge=profile['challenge']))
        transcript = independent.audit(quarantine / 'run', worker.contract(),
            binding['task_sha256'], worker_pin, checks[-1]['interpreter_sha256'],
            packet['transcript_head'])
        for row in packet['files']:
            need(row['text'].encode() == raw_files['run/candidate/' + row['path']],
                 'native submission differs from final candidate')
    native_paths = ['run/native/binding.json', 'run/native/custody/output',
                    'run/native/custody/custody.jsonl',
                    'run/native/' + binding['run_id'] + '.frontier.jsonl']
    bad_modes = {name: oct(modes[name]) for name in native_paths if modes[name] != 0o600}
    # This reuses the current classifier, not a copied old success boolean.
    # Older records without its required pre-cleanup observations stay REFUSE.
    closure = probe.clean_retirement_observed(result, True)
    report = doctor(source)
    statuses = ['UNKNOWN', 'REFUSE', 'UNKNOWN', 'REFUSE', 'REFUSE',
                'NOT_RUN', 'NOT_RUN', 'NOT_RUN', 'NOT_RUN']
    for row, status in zip(report['steps'], statuses):
        row['status'] = status
    report.update(status='INCOMPLETE', archive_sha256=archive_pin,
        actual_coding_realm_works=False, execution_authenticated=False,
        earliest_unresolved_stage=1, earliest_native_blocking_stage=2,
        run_id=profile['planner_run_id'], native_submission_binding=binding,
        diagnostic_modules=module_pins,
        retained_closure={'status': 'PASS' if closure else 'REFUSE',
            'scope': 'diagnostic process/resource classifier; not native closure authority',
            'record': result, 'retained_driver_sha256': profile['driver_sha256']},
        transcript=transcript, native_record_permissions={
            'status': 'REFUSE' if bad_modes else 'PASS', 'violations': bad_modes,
            'scope': 'original archived mode precondition only; native custody audit not implied'},
        native_custody_audit='REFUSE' if bad_modes else 'NOT_RUN',
        independent_outcome_rerun='NOT_RUN',
        missing_interfaces=[
            'Authenticated task-intake trust policy for this coding run',
            'Distinct measured coding launch and bound native mediation session',
            'Broker-owned live observations/effects joined to frozen native closure',
            'Independent coding semantics joined into CheckedExecutionForPublication',
            'Canonical coding artifact joined to production VerifiedCreateBatch'],
        limits=report['limits'] + ['Archive/process records remain development evidence',
            'Transcript checks do not rerun candidate semantics',
            'Original modes are inspected; historical records are never normalized'])
    need(source_identity(source) == identity, 'source changed during diagnosis')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    source_default = Path(__file__).resolve().parents[2]
    d = commands.add_parser('doctor'); d.add_argument('--source', type=Path, default=source_default)
    r = commands.add_parser('diagnose-run', help='Cold retained-run stage diagnostic; never authority')
    r.add_argument('--source', type=Path, default=source_default)
    r.add_argument('--archive', type=Path, required=True); r.add_argument('--archive-sha256', required=True)
    q = commands.add_parser('prepare'); q.add_argument('--source', type=Path, default=source_default)
    q.add_argument('--output', type=Path, required=True)
    a = commands.add_parser('assess'); a.add_argument('--source', type=Path, default=source_default)
    a.add_argument('--case-root', type=Path, required=True); a.add_argument('--case-sha256', required=True)
    i = commands.add_parser('inspect-development'); i.add_argument('--root', type=Path, required=True)
    i.add_argument('--pins', type=Path, required=True)
    g = commands.add_parser('relationships', help='Verify signed evidence joins; no native authority')
    g.add_argument('--root', type=Path, required=True); g.add_argument('--policy-root', type=Path, required=True)
    g.add_argument('--policy-sha256', required=True); g.add_argument('--crypto', type=Path, default=Path('/usr/bin/openssl'))
    args = p.parse_args()
    try:
        if args.command == 'doctor':
            result = doctor(args.source); code = 3
        elif args.command == 'diagnose-run':
            result = diagnose_run(args.source, args.archive, args.archive_sha256); code = 3
        elif args.command == 'prepare':
            result = prepare(args.source, args.output); code = 0
        elif args.command == 'assess':
            result = assess(args.case_root, args.case_sha256, args.source); code = 3
        elif args.command == 'relationships':
            from scripts.v7.evidence_graph import check
            result = check(args.root, args.policy_root, args.policy_sha256, args.crypto); code = 3
        else:
            pins = independent.parse(evidence_read(args.pins.parent, args.pins.name, MAX_MANIFEST))
            result = inspect_development(args.root, pins); code = 0 if result['transcript']['finished'] else 3
    except (ValueError, OSError, KeyError, TypeError, RecursionError, IndexError, subprocess.SubprocessError, tarfile.TarError, EOFError) as e:
        result = {'schema': 'realm.v7.qualification-report/v1', 'status': 'REFUSED',
                  'authority': 'NONE', 'release_ready': False, 'error': str(e)}
        code = 2
    print(json.dumps(result, indent=2, allow_nan=False))
    return code


if __name__ == '__main__':
    sys.exit(main())
