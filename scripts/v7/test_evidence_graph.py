"""Cryptographically real tests of a synthetic, explicitly non-authorizing graph.

Private role keys exist only in temporary test directories. No .realm, measured
execution, or host application is manufactured by this fixture.
"""
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.v7 import evidence_graph as g
from scripts.v7 import qualification as q


def pin(name, raw):
    return {'name': name, 'digest': {'sha256': q.sha(raw)}, 'bytes': len(raw)}


class EvidenceGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = Path('/usr/bin/openssl')
        if not cls.crypto.is_file():
            raise RuntimeError('Independent evidence tests require /usr/bin/openssl; do not silently skip')
        cls.keys_temp = tempfile.TemporaryDirectory(prefix='realm-spec-keys-')
        cls.addClassCleanup(cls.keys_temp.cleanup)
        cls.keys = {}
        for role in g.ROLES:
            private = Path(cls.keys_temp.name) / (role + '.pem')
            generated = subprocess.run([str(cls.crypto), 'genrsa', '-out', str(private), '3072'],
                                       capture_output=True, timeout=30)
            if generated.returncode:
                raise RuntimeError(generated.stderr.decode())
            public = subprocess.check_output([str(cls.crypto), 'rsa', '-in', str(private), '-pubout'],
                                             stderr=subprocess.PIPE)
            cls.keys[role] = (private, public)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='realm-spec-case-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'evidence'; self.root.mkdir()
        self.trust = self.base / 'trust'; self.trust.mkdir()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        fmt = lambda d: d.isoformat().replace('+00:00', 'Z')
        self.time = fmt(now)
        self.pins = {}
        for role, names in g.RESOURCES.items():
            for name in names:
                # Explicit fixture bytes, including deliberately noncanonical artifact data.
                raw = (f'UNIT_TEST_ONLY: {role}/{name}; no measured evidence\n').encode()
                if name in g.FILES:
                    raw = (f'# UNIT_TEST_ONLY inert bytes for {name}\n').encode()
                if name not in self.pins:
                    (self.root / name).write_bytes(raw); self.pins[name] = pin(name, raw)
        context = {'run_id': 'run-spec-001', 'challenge': q.sha(b'independently issued fixture nonce'),
                   'source_commit': 'a' * 40, 'source_tree': 'b' * 40,
                   'task_sha256': self.pins['task.json']['digest']['sha256'],
                   'profile_sha256': self.pins['profile.json']['digest']['sha256'],
                   'hardware_sha256': self.pins['hardware.json']['digest']['sha256'],
                   'model_sha256': self.pins['model.json']['digest']['sha256'],
                   'checker_sha256': q.sha(b'independent fixture checker')}
        self.project = [{'path': name, 'operation': 'create', 'mode': 0o600,
                         'bytes': self.pins[name]['bytes'], 'sha256': self.pins[name]['digest']['sha256']}
                        for name in g.FILES]
        self.policy = {'schema': 'realm.v7.evidence-policy/v1', 'profile': q.PROFILE,
                       'context': context, 'window': {'not_before': fmt(now - timedelta(minutes=5)),
                                                    'not_after': fmt(now + timedelta(minutes=15))},
                       'roles': {}, 'projection': self.project,
                       'artifact_sha256': self.pins['candidate.realm']['digest']['sha256'],
                       'destination': {'id': 'fixture-destination-dev-7-inode-123-owner-test',
                                       'before_root': q.sha(b'fixture empty world'),
                                       'after_root': q.sha(b'fixture final world')},
                       'evidence_class': 'UNIT_TEST', 'crypto_sha256': g.binary_identity(self.crypto)}
        for role, (_, public) in self.keys.items():
            name = role + '-public.pem'; (self.trust / name).write_bytes(public)
            self.policy['roles'][role] = {'builder_id': 'https://example.invalid/unit-test/' + role,
                                         'key': pin(name, public)}
        H = lambda label: q.sha(label.encode())
        launch, frontier, semantic, genesis, head, approval = map(H, ('launch', 'frontier', 'semantic', 'genesis', 'head', 'approval'))
        artifact = self.policy['artifact_sha256']; before = self.policy['destination']['before_root']; after = self.policy['destination']['after_root']
        self.results = {
            'intake': {'task_sha256': context['task_sha256'], 'authorized_paths': list(g.FILES), 'operation': 'create', 'max_file_bytes': 32768},
            'launch': {'launch_id': launch, 'profile_sha256': context['profile_sha256'], 'hardware_sha256': context['hardware_sha256'], 'kvm': True, 'measured': True, 'closed': True},
            'agent': {'launch_id': launch, 'model_sha256': context['model_sha256'], 'controller_inside_guest': True, 'completion': 'FINISHED'},
            'effects': {'launch_id': launch, 'frontier_root': frontier, 'custody_root': H('custody'), 'closure_root': H('closure'), 'history_complete': True,
                        'unmediated_effects': 0, 'inflight_effects': 0, 'projection': self.project, 'mediation_scope': 'ALL_AUTHORITY_RELEVANT_EXTERNAL_EFFECTS'},
            'semantics': {'frontier_root': frontier, 'semantic_commitment': semantic, 'task_sha256': context['task_sha256'], 'checker_sha256': context['checker_sha256'], 'projection': self.project, 'decision': 'SATISFIED', 'independent': True},
            'publication': {'frontier_root': frontier, 'semantic_commitment': semantic, 'genesis': genesis, 'authority_head': head, 'capability_kind': 'CheckedExecutionForPublication'},
            'artifact': {'artifact_sha256': artifact, 'authority_head': head, 'genesis': genesis, 'semantic_commitment': semantic, 'profile': q.PROFILE},
            'approval': {'artifact_sha256': artifact, 'authority_head': head, 'semantic_commitment': semantic, 'destination_id': self.policy['destination']['id'], 'before_root': before,
                         'plan_sha256': self.pins['plan.json']['digest']['sha256'], 'approval_id': approval, 'projection': self.project},
            'application': {'approval_id': approval, 'plan_sha256': self.pins['plan.json']['digest']['sha256'], 'destination_id': self.policy['destination']['id'], 'before_root': before,
                            'after_root': after, 'completed': 3, 'pending': 0, 'status': 'COMPLETE', 'projection': self.project},
            'final': {'approval_id': approval, 'artifact_sha256': artifact, 'destination_id': self.policy['destination']['id'], 'after_root': after, 'projection': self.project,
                      'journal_complete': True, 'fresh_observation': True},
        }
        self.statements = {}
        for role in g.ROLES:
            resources = [self.pins[name] for name in g.RESOURCES[role]]
            self.statements[role] = {'_type': g.STATEMENT, 'subject': [{k: resources[0][k] for k in ('name', 'digest')}], 'predicateType': g.PREFIX + role + '/v1',
                'predicate': {'context': copy.deepcopy(context), 'builder': {'id': self.policy['roles'][role]['builder_id']},
                              'metadata': {'invocationId': context['run_id'], 'startedOn': self.time, 'finishedOn': self.time},
                              'predecessor': None, 'resources': resources, 'result': copy.deepcopy(self.results[role])}}
        self.emit()

    def emit(self, wrong_signer=None, hints=None):
        previous = None; self.graph = {'schema': 'realm.v7.evidence-graph/v1', 'records': {}}
        for role in g.ROLES:
            statement = self.statements[role]
            statement['predicate']['predecessor'] = previous
            body = q.canonical(statement)
            signer = wrong_signer[1] if wrong_signer and wrong_signer[0] == role else role
            sig = subprocess.check_output([str(self.crypto), 'dgst', '-sha256', '-sign', str(self.keys[signer][0])], input=g.pae(g.MEDIA, body))
            signature = {'sig': base64.b64encode(sig).decode()}
            if hints: signature['keyid'] = hints
            envelope = q.canonical({'payloadType': g.MEDIA, 'payload': base64.b64encode(body).decode(), 'signatures': [signature]})
            name = role + '.dsse.json'; (self.root / name).write_bytes(envelope)
            self.graph['records'][role] = pin(name, envelope)
            previous = q.sha(body)
        self.write_manifest()
        raw = q.canonical(self.policy); (self.trust / 'policy.json').write_bytes(raw); self.policy_pin = q.sha(raw)

    def write_manifest(self):
        (self.root / 'graph.json').write_bytes(q.canonical(self.graph))

    def check(self):
        return g.check(self.root, self.trust, self.policy_pin, self.crypto)

    def test_valid_authenticated_relationships_accept_but_cannot_qualify_fake_artifact(self):
        report = self.check()
        self.assertTrue(report['record_relationships_accepted'])
        self.assertEqual(len(report['records']), 10)
        self.assertEqual(report['evidence_class'], 'UNIT_TEST')
        self.assertFalse(report['release_ready'])
        self.assertFalse(report['native_authority_verified'])
        self.assertFalse(report['complete_effect_mediation_verified'])

    def test_fully_signed_hardware_labels_do_not_upgrade_native_authority(self):
        self.policy['evidence_class'] = 'MEASURED_HARDWARE'; self.emit()
        report = self.check()
        self.assertTrue(report['record_relationships_accepted'])
        self.assertFalse(report['release_ready'])

    def test_wrong_role_key_and_builder_refuse_even_with_correct_bytes(self):
        self.emit(wrong_signer=('semantics', 'agent'))
        with self.assertRaisesRegex(ValueError, 'unauthorized signer'): self.check()
        self.statements['semantics']['predicate']['builder']['id'] = 'https://example.invalid/rogue'
        self.emit()
        with self.assertRaisesRegex(ValueError, 'signer-builder'): self.check()

    def test_key_hint_does_not_select_an_authority(self):
        self.emit(hints='rogue-key-id-is-only-an-unauthenticated-hint')
        self.assertTrue(self.check()['record_relationships_accepted'])

    def test_cross_run_and_all_context_substitutions_refuse_resigned_records(self):
        original = copy.deepcopy(self.statements['effects'])
        for field in g.CONTEXT:
            with self.subTest(field=field):
                self.statements['effects'] = copy.deepcopy(original)
                self.statements['effects']['predicate']['context'][field] = 'substituted'
                self.emit()
                with self.assertRaisesRegex(ValueError, 'substitution'): self.check()

    def test_incomplete_or_unmediated_effects_refuse_valid_signatures(self):
        original = copy.deepcopy(self.statements['effects'])
        for field, value in [('history_complete', False), ('unmediated_effects', 1), ('inflight_effects', 1), ('unmediated_effects', False), ('mediation_scope', 'C0_ONLY')]:
            with self.subTest(field=field, value=value):
                self.statements['effects'] = copy.deepcopy(original)
                self.statements['effects']['predicate']['result'][field] = value; self.emit()
                with self.assertRaises(ValueError): self.check()

    def test_forged_pass_unknown_flags_and_semantic_frontier_refuse(self):
        original = copy.deepcopy(self.statements['semantics'])
        for field, value in [('decision', 'PASS'), ('independent', False), ('frontier_root', '0' * 64), ('release_ready', True)]:
            with self.subTest(field=field):
                self.statements['semantics'] = copy.deepcopy(original)
                self.statements['semantics']['predicate']['result'][field] = value; self.emit()
                with self.assertRaises(ValueError): self.check()

    def test_stale_destination_and_substituted_approval_refuse(self):
        original = copy.deepcopy(self.statements['approval'])
        for field, value in [('before_root', '0' * 64), ('destination_id', 'another-destination'), ('plan_sha256', '0' * 64), ('artifact_sha256', '0' * 64), ('authority_head', '0' * 64)]:
            with self.subTest(field=field):
                self.statements['approval'] = copy.deepcopy(original)
                self.statements['approval']['predicate']['result'][field] = value; self.emit()
                with self.assertRaises(ValueError): self.check()

    def test_interrupted_application_and_incomplete_final_observation_refuse(self):
        original = copy.deepcopy(self.statements)
        for role, field, value in [('application', 'completed', 2), ('application', 'pending', 1), ('application', 'status', 'INTERRUPTED'), ('application', 'approval_id', '0' * 64), ('final', 'journal_complete', False), ('final', 'fresh_observation', False)]:
            with self.subTest(role=role, field=field):
                self.statements = copy.deepcopy(original)
                self.statements[role]['predicate']['result'][field] = value; self.emit()
                with self.assertRaises(ValueError): self.check()

    def test_corrupt_artifact_and_rehashed_corrupt_envelope_refuse(self):
        (self.root / 'candidate.realm').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'custody differs'): self.check()
        name = 'agent.dsse.json'; data = json.loads((self.root / name).read_bytes())
        body = json.loads(base64.b64decode(data['payload'])); body['predicate']['result']['completion'] = 'FORGED'
        data['payload'] = base64.b64encode(q.canonical(body)).decode(); raw = q.canonical(data)
        (self.root / name).write_bytes(raw); self.graph['records']['agent'] = pin(name, raw); self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'unauthorized signer'): self.check()

    def test_missing_role_wrong_predicate_and_predecessor_refuse(self):
        del self.graph['records']['effects']; self.write_manifest()
        with self.assertRaises(ValueError): self.check()
        self.statements['effects']['predicateType'] = g.PREFIX + 'C0/v1'; self.emit()
        with self.assertRaisesRegex(ValueError, 'predicate type'): self.check()

    def test_path_escape_symlink_fifo_and_effect_order_refuse(self):
        self.graph['records']['intake']['name'] = '../trust/policy.json'; self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'escape'): self.check()
        self.emit(); original = (self.root / 'task.json').read_bytes()
        (self.root / 'task.json').unlink(); (self.root / 'task.json').symlink_to(self.trust / 'policy.json')
        with self.assertRaises(OSError): self.check()
        (self.root / 'task.json').unlink(); os.mkfifo(self.root / 'task.json')
        with self.assertRaises(ValueError): self.check()
        (self.root / 'task.json').unlink(); (self.root / 'task.json').write_bytes(original)
        self.statements['effects']['predicate']['result']['projection'][0]['path'] = '../escape'; self.emit()
        with self.assertRaises(ValueError): self.check()

    def test_policy_pin_crypto_pin_expiry_and_role_separation_refuse(self):
        original = copy.deepcopy(self.policy)
        self.policy_pin = '0' * 64
        with self.assertRaisesRegex(ValueError, 'policy pin'): self.check()
        for change in ('crypto', 'expiry', 'keys', 'profile'):
            self.policy = copy.deepcopy(original)
            if change == 'crypto': self.policy['crypto_sha256'] = '0' * 64
            if change == 'expiry': self.policy['window']['not_after'] = '2000-01-01T00:00:00Z'
            if change == 'keys': self.policy['roles']['approval']['key'] = self.policy['roles']['agent']['key']
            if change == 'profile': self.policy['profile'] = 'C0'
            self.emit()
            with self.subTest(change=change), self.assertRaises(ValueError): self.check()

    def test_candidate_byte_substitution_refuses_even_when_signed(self):
        wrong = copy.deepcopy(self.statements['final']['predicate']['resources'])
        wrong[1] = self.pins['report.py']; self.statements['final']['predicate']['resources'] = wrong
        self.emit()
        with self.assertRaises(ValueError): self.check()

    def test_unauthorized_subject_and_model_scope_refuse(self):
        self.statements['launch']['subject'] = [{k: self.pins['task.json'][k] for k in ('name', 'digest')}]; self.emit()
        with self.assertRaisesRegex(ValueError, 'primary subject'): self.check()
        self.statements['launch']['subject'] = [{k: self.pins['launch.json'][k] for k in ('name', 'digest')}]
        self.statements['agent']['predicate']['result']['controller_inside_guest'] = False; self.emit()
        with self.assertRaises(ValueError): self.check()


    def replace_one_envelope(self, role, body, media=g.MEDIA):
        sig = subprocess.check_output([str(self.crypto), 'dgst', '-sha256', '-sign', str(self.keys[role][0])], input=g.pae(media, body))
        raw = q.canonical({'payloadType': media, 'payload': base64.b64encode(body).decode(), 'signatures': [{'sig': base64.b64encode(sig).decode()}]})
        name = role + '.dsse.json'; (self.root / name).write_bytes(raw)
        self.graph['records'][role] = pin(name, raw); self.write_manifest()

    def test_predecessor_type_duplicate_payload_and_timestamp_refuse(self):
        original = copy.deepcopy(self.statements['effects'])
        changed = copy.deepcopy(original); changed['predicate']['predecessor'] = '0' * 64
        self.replace_one_envelope('effects', q.canonical(changed))
        with self.assertRaisesRegex(ValueError, 'predecessor'): self.check()
        self.replace_one_envelope('effects', q.canonical(original), 'application/json')
        with self.assertRaisesRegex(ValueError, 'payload type'): self.check()
        raw = q.canonical(original)
        raw = raw.replace(b'{"_type":', b'{"_type":"duplicate", "_type":', 1)
        self.replace_one_envelope('effects', raw)
        with self.assertRaises(ValueError): self.check()
        changed = copy.deepcopy(original); changed['predicate']['metadata']['finishedOn'] = '1999-01-01T00:00:00Z'
        self.replace_one_envelope('effects', q.canonical(changed))
        with self.assertRaisesRegex(ValueError, 'time/order'): self.check()

    def test_different_pem_encoding_does_not_create_independent_role_key(self):
        # The PEM custody digests differ, but decoded SPKI identity is the same.
        public = self.keys['intake'][1] + b'\n'
        name = 'launch-public.pem'; (self.trust / name).write_bytes(public)
        self.policy['roles']['launch']['key'] = pin(name, public)
        self.emit(wrong_signer=('launch', 'intake'))
        with self.assertRaisesRegex(ValueError, 'decoded role keys'): self.check()

    def test_dot_resource_path_and_shared_trust_root_refuse(self):
        self.graph['records']['intake']['name'] = '.'; self.write_manifest()
        with self.assertRaises(ValueError): self.check()
        with self.assertRaisesRegex(ValueError, 'separate'):
            g.check(self.root, self.root, self.policy_pin, self.crypto)

    def test_cli_valid_records_exit_incomplete_and_wrong_policy_refuses(self):
        command = [sys.executable, '-B', '-m', 'scripts.v7.qualification', 'relationships', '--root', str(self.root),
                   '--policy-root', str(self.trust), '--policy-sha256', self.policy_pin]
        p = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertTrue(json.loads(p.stdout)['record_relationships_accepted'])
        command[-1] = '0' * 64
        p = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertFalse(json.loads(p.stdout)['release_ready'])


if __name__ == '__main__':
    unittest.main()
