"""Verify authenticated evidence relationships, never mint execution authority.

Strict REALM profile of in-toto Statement v1 + DSSE. Signatures establish who
asserted a record; native measured/custody/capability verifiers remain required.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from scripts.v7 import qualification as intake
from scripts.v7.verify_coding_development import parse

STATEMENT = 'https://in-toto.io/Statement/v1'
MEDIA = 'application/vnd.in-toto+json'
PREFIX = 'https://github.com/Lordphoenix1223/REALM/attestation/v7/'
ROLES = ('intake', 'launch', 'agent', 'effects', 'semantics', 'publication',
         'artifact', 'approval', 'application', 'final')
FILES = ('totals.py', 'report.py', 'test_totals.py')
CONTEXT = {'run_id', 'challenge', 'source_commit', 'source_tree', 'task_sha256',
           'profile_sha256', 'hardware_sha256', 'model_sha256', 'checker_sha256'}
RESOURCES = {
    'intake': ('task.json',), 'launch': ('launch.json', 'profile.json', 'hardware.json'),
    'agent': ('agent.json', 'model.json'),
    'effects': ('frontier.json', 'custody.json', 'closure.json'),
    'semantics': ('semantic.json', *FILES),
    'publication': ('authority.json', 'generation.json'), 'artifact': ('candidate.realm',),
    'approval': ('plan.json', 'destination-before.json'),
    'application': ('application-journal.json', 'receipt.json'),
    'final': ('destination-after.json', *FILES),
}
RESULTS = {
    'intake': {'task_sha256', 'authorized_paths', 'operation', 'max_file_bytes'},
    'launch': {'launch_id', 'profile_sha256', 'hardware_sha256', 'kvm', 'measured', 'closed'},
    'agent': {'launch_id', 'model_sha256', 'controller_inside_guest', 'completion'},
    'effects': {'launch_id', 'frontier_root', 'custody_root', 'closure_root', 'history_complete',
                'unmediated_effects', 'inflight_effects', 'projection', 'mediation_scope'},
    'semantics': {'frontier_root', 'semantic_commitment', 'task_sha256', 'checker_sha256',
                  'projection', 'decision', 'independent'},
    'publication': {'frontier_root', 'semantic_commitment', 'genesis', 'authority_head', 'capability_kind'},
    'artifact': {'artifact_sha256', 'authority_head', 'genesis', 'semantic_commitment', 'profile'},
    'approval': {'artifact_sha256', 'authority_head', 'semantic_commitment', 'destination_id',
                 'before_root', 'plan_sha256', 'approval_id', 'projection'},
    'application': {'approval_id', 'plan_sha256', 'destination_id', 'before_root', 'after_root',
                    'completed', 'pending', 'status', 'projection'},
    'final': {'approval_id', 'artifact_sha256', 'destination_id', 'after_root', 'projection',
              'journal_complete', 'fresh_observation'},
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def shape(value, fields, name):
    need(type(value) is dict and set(value) == set(fields), f'{name}: fields differ')


def equal(a, b, reason):
    need(intake.canonical(a) == intake.canonical(b), reason)


def digest(value, bits=256):
    need(type(value) is str and re.fullmatch(r'[0-9a-f]{' + str(bits // 4) + r'}', value),
         'invalid digest')


def timestamp(value):
    need(type(value) is str and value.endswith('Z'), 'UTC timestamp required')
    d = datetime.fromisoformat(value[:-1] + '+00:00')
    need(d.tzinfo is not None and d.utcoffset().total_seconds() == 0, 'UTC timestamp required')
    return d


def descriptor(value):
    shape(value, {'name', 'digest', 'bytes'}, 'resource')
    intake.relative(value['name'])
    shape(value['digest'], {'sha256'}, 'resource digest')
    digest(value['digest']['sha256'])
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= intake.MAX_EVIDENCE,
         'resource size differs')


def projection(value):
    need(type(value) is list and len(value) == 3, 'three ordered effects required')
    for name, row in zip(FILES, value):
        shape(row, {'path', 'operation', 'sha256', 'bytes', 'mode'}, 'projection')
        equal(row['path'], name, 'unauthorized path or effect order')
        need(row['operation'] == 'create' and type(row['mode']) is int and row['mode'] == 0o600,
             'unsupported effect or mode')
        digest(row['sha256'])
        need(type(row['bytes']) is int and 0 < row['bytes'] <= 32768, 'coding file bound differs')


def pae(kind, body):
    kind = kind.encode('utf-8')
    return b'DSSEv1 ' + str(len(kind)).encode() + b' ' + kind + b' ' + str(len(body)).encode() + b' ' + body


def decoded(value, limit):
    need(type(value) is str and len(value) <= 4 * ((limit + 2) // 3), 'base64 bound differs')
    raw = base64.b64decode(value, altchars=b'-_', validate=True)
    need(len(raw) <= limit, 'decoded bound differs')
    return raw


def binary_identity(path):
    path = Path(path)
    need(path.is_absolute() and not path.is_symlink(), 'absolute trusted crypto executable required')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_size <= 16 * 1024 * 1024,
         'crypto executable is not bounded regular file')
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    need(identity(before) == identity(after), 'crypto executable changed')
    return intake.sha(raw)


def verify_envelope(raw, key, crypto):
    envelope = parse(raw)
    shape(envelope, {'payloadType', 'payload', 'signatures'}, 'DSSE envelope')
    need(envelope['payloadType'] == MEDIA, 'unsupported signed payload type')
    need(type(envelope['signatures']) is list and len(envelope['signatures']) == 1,
         'this profile requires one role signature')
    signature = envelope['signatures'][0]
    need(type(signature) is dict and set(signature) in ({'sig'}, {'sig', 'keyid'}), 'signature fields differ')
    if 'keyid' in signature:
        need(type(signature['keyid']) is str and len(signature['keyid']) <= 256, 'invalid key hint')
    body = decoded(envelope['payload'], intake.MAX_MANIFEST)
    sig = decoded(signature['sig'], 384)
    need(len(sig) == 384, 'RSA-3072 signature required')
    # keyid is never an authority selector. Only the externally pinned role key is tried.
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'}
    with tempfile.TemporaryDirectory(prefix='realm-attestation-') as temp:
        root = Path(temp)
        (root / 'key.pem').write_bytes(key)
        (root / 'signature').write_bytes(sig)
        modulus = subprocess.run([str(crypto), 'rsa', '-pubin', '-in', str(root / 'key.pem'),
                                  '-modulus', '-noout'], capture_output=True, env=env, timeout=10)
        text = modulus.stdout.strip()
        need(modulus.returncode == 0 and re.fullmatch(rb'Modulus=[89A-Fa-f][0-9A-Fa-f]{767}', text),
             'trusted key is not RSA-3072')
        process = subprocess.run([str(crypto), 'dgst', '-sha256', '-verify', str(root / 'key.pem'),
                                  '-signature', str(root / 'signature')], input=pae(MEDIA, body),
                                 capture_output=True, env=env, timeout=10)
        need(process.returncode == 0, 'unauthorized signer or corrupt signed payload')
        public = subprocess.run([str(crypto), 'pkey', '-pubin', '-in', str(root / 'key.pem'),
                                 '-pubout', '-outform', 'DER'], capture_output=True, env=env, timeout=10)
        need(public.returncode == 0 and 0 < len(public.stdout) <= 8192, 'canonical public key decode failed')
        key_identity = intake.sha(public.stdout)
    # Parse the exact bytes verified, never fetch/reparse another payload.
    return parse(body), intake.sha(body), key_identity


def check(root, policy_root, policy_pin, crypto):
    started = datetime.now(timezone.utc)
    evidence_root = Path(root).resolve(); trust_root = Path(policy_root).resolve()
    need(evidence_root != trust_root and evidence_root not in trust_root.parents and
         trust_root not in evidence_root.parents, 'trust policy must be separate from candidate evidence')
    digest(policy_pin)
    policy_raw = intake.evidence_read(policy_root, 'policy.json', intake.MAX_MANIFEST)
    need(intake.sha(policy_raw) == policy_pin, 'external trust policy pin differs')
    policy = parse(policy_raw)
    shape(policy, {'schema', 'profile', 'context', 'window', 'roles', 'projection', 'artifact_sha256',
                   'destination', 'evidence_class', 'crypto_sha256'}, 'trust policy')
    need(policy['schema'] == 'realm.v7.evidence-policy/v1' and policy['profile'] == intake.PROFILE,
         'unsupported trust policy/profile')
    context = policy['context']; shape(context, CONTEXT, 'execution context')
    need(type(context['run_id']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', context['run_id']), 'run ID differs')
    digest(context['source_commit'], 160); digest(context['source_tree'], 160)
    for name in CONTEXT - {'run_id', 'source_commit', 'source_tree'}:
        digest(context[name])
    shape(policy['window'], {'not_before', 'not_after'}, 'policy window')
    earliest = timestamp(policy['window']['not_before']); latest = timestamp(policy['window']['not_after'])
    need(earliest <= started <= latest, 'trust policy is expired or not yet valid')
    need(policy['evidence_class'] in intake.CLASSIFICATIONS - {'NOT_RUN'}, 'unknown evidence classification')
    projection(policy['projection']); digest(policy['artifact_sha256']); digest(policy['crypto_sha256'])
    shape(policy['destination'], {'id', 'before_root', 'after_root'}, 'destination expectation')
    need(type(policy['destination']['id']) is str and 0 < len(policy['destination']['id']) <= 256,
         'destination identity required')
    digest(policy['destination']['before_root']); digest(policy['destination']['after_root'])
    shape(policy['roles'], ROLES, 'role policy')
    keys = {}
    for role, owner in policy['roles'].items():
        shape(owner, {'builder_id', 'key'}, 'role policy binding')
        need(type(owner['builder_id']) is str and owner['builder_id'].startswith('https://') and
             len(owner['builder_id']) <= 512, 'builder identity differs')
        descriptor(owner['key'])
        key = intake.evidence_read(policy_root, owner['key']['name'], 8192)
        need(len(key) == owner['key']['bytes'] and intake.sha(key) == owner['key']['digest']['sha256'],
             'role key pin differs')
        keys[role] = key
    need(len({intake.sha(key) for key in keys.values()}) == len(ROLES), 'role keys must be distinct')
    crypto = Path(crypto)
    need(binary_identity(crypto) == policy['crypto_sha256'], 'crypto executable pin differs')
    manifest_raw = intake.evidence_read(root, 'graph.json', intake.MAX_MANIFEST)
    graph = parse(manifest_raw)
    shape(graph, {'schema', 'records'}, 'graph')
    need(graph['schema'] == 'realm.v7.evidence-graph/v1', 'graph schema differs')
    shape(graph['records'], ROLES, 'complete evidence roles')
    results = {}; records = []; previous = None; previous_time = earliest; signer_identities = set()
    total = 0; pins = []
    def raw_resource(pin):
        nonlocal total
        descriptor(pin); total += pin['bytes']
        need(total <= 64 * 1024 * 1024, 'graph evidence budget exceeded')
        raw = intake.evidence_read(root, pin['name'], intake.MAX_EVIDENCE)
        need(len(raw) == pin['bytes'] and intake.sha(raw) == pin['digest']['sha256'], 'resource custody differs')
        pins.append(pin)
        return raw
    for role in ROLES:
        reference = graph['records'][role]
        need(type(reference) is dict and type(reference.get('bytes')) is int and
             reference['bytes'] <= intake.MAX_MANIFEST, 'envelope size bound differs')
        envelope = raw_resource(reference)
        statement, payload_hash, signer_identity = verify_envelope(envelope, keys[role], crypto)
        need(signer_identity not in signer_identities, 'decoded role keys must be distinct')
        signer_identities.add(signer_identity)
        shape(statement, {'_type', 'subject', 'predicateType', 'predicate'}, 'in-toto statement')
        need(statement['_type'] == STATEMENT and statement['predicateType'] == PREFIX + role + '/v1', 'predicate type differs')
        need(type(statement['subject']) is list and len(statement['subject']) == 1, 'one primary subject required')
        subject = statement['subject'][0]
        shape(subject, {'name', 'digest'}, 'in-toto subject')
        descriptor({**subject, 'bytes': 0})
        p = statement['predicate']
        shape(p, {'context', 'builder', 'metadata', 'predecessor', 'resources', 'result'}, 'predicate')
        equal(p['context'], context, 'cross-run/source/profile/task/hardware/model/checker/challenge substitution')
        equal(p['builder'], {'id': policy['roles'][role]['builder_id']}, 'unauthorized signer-builder pair')
        shape(p['metadata'], {'invocationId', 'startedOn', 'finishedOn'}, 'invocation metadata')
        need(p['metadata']['invocationId'] == context['run_id'], 'invocation ID differs')
        a = timestamp(p['metadata']['startedOn']); b = timestamp(p['metadata']['finishedOn'])
        need(previous_time <= a <= b <= latest, 'record time/order differs')
        previous_time = b
        equal(p['predecessor'], previous, 'evidence predecessor payload differs')
        need(type(p['resources']) is list, 'resources required')
        equal([r.get('name') for r in p['resources'] if type(r) is dict], list(RESOURCES[role]), 'raw evidence names/order differ')
        resources = {r['name']: r for r in p['resources']}
        for pin in p['resources']: raw_resource(pin)
        equal(subject, {k: p['resources'][0][k] for k in ('name', 'digest')},
              'primary subject differs from stage evidence')
        result = p['result']; shape(result, RESULTS[role], role + ' result')
        results[role] = result
        validate_result(role, result, results, resources, policy)
        records.append({'role': role, 'payload_sha256': payload_hash,
                        'signer_key_sha256': intake.sha(keys[role]), 'signer_spki_sha256': signer_identity,
                        'builder_id': p['builder']['id']})
        previous = payload_hash
    # Reopen after all checks. This is bounded custody checking, not atomic whole-tree observation.
    for pin in pins:
        raw = intake.evidence_read(root, pin['name'], intake.MAX_EVIDENCE)
        need(len(raw) == pin['bytes'] and intake.sha(raw) == pin['digest']['sha256'], 'evidence changed during graph check')
    need(intake.evidence_read(root, 'graph.json', intake.MAX_MANIFEST) == manifest_raw and
         intake.evidence_read(policy_root, 'policy.json', intake.MAX_MANIFEST) == policy_raw,
         'graph or trust policy changed during check')
    need(binary_identity(crypto) == policy['crypto_sha256'], 'crypto executable changed')
    return {'schema': 'realm.v7.evidence-relationships/v1', 'status': 'VALID_RECORD_RELATIONSHIPS',
            'record_relationships_accepted': True, 'authority': 'NONE', 'release_ready': False,
            'trust_policy_sha256': policy_pin, 'graph_sha256': intake.sha(manifest_raw),
            'verifier_sha256': intake.sha(Path(__file__).read_bytes()),
            'auditor_source': intake.source_identity(Path(__file__).resolve().parents[2]),
            'context': context, 'evidence_class': policy['evidence_class'], 'records': records,
            'native_authority_verified': False, 'complete_effect_mediation_verified': False,
            'missing_release_checks': ['qualified coding measured launch and complete mediation',
              'independent same-run native semantic/custody/closure checks',
              'opaque canonical publication capability and cold artifact/genesis verification',
              'native approved ordered application and independent physical destination observation',
              'fresh full-path negative, interruption and repeat campaign'],
            'limits': ['Signatures authenticate assertions, not their physical truth or native capabilities',
                      'Externally reviewed role policy and trusted OS/clock/crypto implementation are prerequisites',
                      'No SLSA level, execution, publication, application or release authority is asserted']}


def validate_result(role, r, all_results, resources, policy):
    c = policy['context']; d = policy['destination']; expected = policy['projection']
    def match(key, value): equal(r[key], value, role + ': binding differs for ' + key)
    def yes(key): need(r[key] is True, role + ': ' + key + ' missing')
    def zero(key): need(type(r[key]) is int and r[key] == 0, role + ': incomplete effects/application')
    for key, value in r.items():
        if key.endswith(('_sha256', '_root', '_commitment', '_head')) or key in {'launch_id', 'genesis', 'approval_id'}:
            digest(value)
    if 'projection' in r:
        projection(r['projection']); match('projection', expected)
    if role == 'intake':
        match('task_sha256', c['task_sha256']); match('authorized_paths', list(FILES))
        match('operation', 'create'); match('max_file_bytes', 32768)
        equal(resources['task.json']['digest']['sha256'], c['task_sha256'], 'task resource differs')
    elif role == 'launch':
        for key in ('profile_sha256', 'hardware_sha256'): match(key, c[key])
        for key in ('kvm', 'measured', 'closed'): yes(key)
        for name, key in (('profile.json', 'profile_sha256'), ('hardware.json', 'hardware_sha256')):
            equal(resources[name]['digest']['sha256'], c[key], 'profile/hardware resource differs')
    elif role == 'agent':
        match('launch_id', all_results['launch']['launch_id']); match('model_sha256', c['model_sha256'])
        yes('controller_inside_guest'); match('completion', 'FINISHED')
        equal(resources['model.json']['digest']['sha256'], c['model_sha256'], 'model identity resource differs')
    elif role == 'effects':
        match('launch_id', all_results['launch']['launch_id']); yes('history_complete')
        zero('unmediated_effects'); zero('inflight_effects')
        match('mediation_scope', 'ALL_AUTHORITY_RELEVANT_EXTERNAL_EFFECTS')
    elif role == 'semantics':
        match('frontier_root', all_results['effects']['frontier_root'])
        for key in ('task_sha256', 'checker_sha256'): match(key, c[key])
        match('decision', 'SATISFIED'); yes('independent')
    elif role == 'publication':
        match('frontier_root', all_results['effects']['frontier_root'])
        match('semantic_commitment', all_results['semantics']['semantic_commitment'])
        match('capability_kind', 'CheckedExecutionForPublication')
    elif role == 'artifact':
        match('artifact_sha256', policy['artifact_sha256']); match('profile', policy['profile'])
        for key in ('authority_head', 'genesis', 'semantic_commitment'): match(key, all_results['publication'][key])
        equal(resources['candidate.realm']['digest']['sha256'], policy['artifact_sha256'], 'artifact custody differs')
    elif role == 'approval':
        match('artifact_sha256', policy['artifact_sha256'])
        for key in ('authority_head', 'semantic_commitment'): match(key, all_results['artifact'][key])
        match('destination_id', d['id']); match('before_root', d['before_root'])
        match('plan_sha256', resources['plan.json']['digest']['sha256'])
    elif role == 'application':
        for key in ('approval_id', 'plan_sha256', 'destination_id', 'before_root'): match(key, all_results['approval'][key])
        match('after_root', d['after_root']); match('completed', 3); zero('pending'); match('status', 'COMPLETE')
    elif role == 'final':
        match('approval_id', all_results['approval']['approval_id']); match('artifact_sha256', policy['artifact_sha256'])
        match('destination_id', d['id']); match('after_root', all_results['application']['after_root'])
        yes('journal_complete'); yes('fresh_observation')
    if role in {'semantics', 'final'}:
        for item in expected:
            pin = resources[item['path']]
            equal((pin['digest']['sha256'], pin['bytes']), (item['sha256'], item['bytes']), 'candidate/final byte identity differs')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--policy-root', type=Path, required=True)
    p.add_argument('--policy-sha256', required=True)
    p.add_argument('--crypto', type=Path, default=Path('/usr/bin/openssl'))
    args = p.parse_args()
    try:
        root = args.root.resolve(); trust = args.policy_root.resolve()
        need(root != trust and root not in trust.parents and trust not in root.parents,
             'trust policy must be separate from candidate evidence')
        report = check(args.root, args.policy_root, args.policy_sha256, args.crypto)
        code = 3  # Valid relationships still do not qualify the physical pipeline.
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as e:
        report = {'schema': 'realm.v7.evidence-relationships/v1', 'status': 'REFUSED',
                  'record_relationships_accepted': False, 'authority': 'NONE', 'release_ready': False, 'error': str(e)}
        code = 2
    print(json.dumps(report, indent=2, allow_nan=False))
    return code


if __name__ == '__main__':
    sys.exit(main())
