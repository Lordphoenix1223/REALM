"""Independent semantic refusals over an actual captured development retry.

The retained input is real Session/Worker execution with scripted fault inputs,
not qualified execution. Mutations below deliberately recompute outer hashes
to test semantic joins rather than only stale-pin detection. No issuer or
verification implementation is supplied here.
"""
import hashlib
from pathlib import Path
import unittest

import coding_worker as codec
import project_history

INPUT = Path(__file__).resolve().parents[2] / 'evidence/v7/receiver-project-history-20261031/input'
PINS = {
    'capture.realm': '236364a1da95ebc3c0f2867283f8c5335bc5ffdd98decfcf056cda3ce19d6ca3',
    'extracted.json': 'e657b19111c3d3e8e38008a381f115f6d8bac27f4853c3ff82a0ba2208aa8564',
}


def rechained(raw, edit):
    rows = []; previous = '0' * 64
    for line in raw.splitlines():
        row = codec.parse(line); row.pop('sha256'); edit(row)
        row['previous'] = previous
        previous = codec.digest(codec.encoded(row))
        rows.append(codec.encoded({**row, 'sha256': previous}).decode())
    return '\n'.join(rows) + '\n'


class ReceiverProjectHistory(unittest.TestCase):
    def setUp(self):
        for name, pin in PINS.items():
            self.assertEqual(hashlib.sha256((INPUT / name).read_bytes()).hexdigest(), pin)
        extracted = codec.parse((INPUT / 'extracted.json').read_bytes())
        freeze = codec.parse(extracted['evidence']['pre_agent_freeze'])
        self.procedure = codec.parse(freeze['successful_procedure'])
        self.body = self.procedure['metadata']['attempt_history']
        self.pin = self.procedure['metadata']['attempt_history_sha256']

    def check(self, *, repin=True):
        pin = codec.digest(codec.encoded(self.body)) if repin else self.pin
        return project_history.audit_procedure(self.procedure, pin)

    def rewrite_outcomes(self):
        outcomes = iter(r['outcome'] for r in self.body['attempts'])
        def edit(row):
            if row['phase'] == 'END': row['item'] = next(outcomes)
        self.body['ledger'] = rechained(self.body['ledger'], edit)

    def test_actual_retry_history_is_non_authorizing(self):
        result = self.check(repin=False)
        self.assertEqual([r['outcome']['status'] for r in self.body['attempts']], ['FAIL', 'PASS', 'PASS'])
        self.assertEqual(result['attempts'], 3)
        self.assertEqual(result['failed_attempts'], 1)
        self.assertEqual(result['authority'], 'NONE')
        self.assertEqual(result['qualification'], 'NOT_RUN')

    def test_missing_failed_worker_observations_refuse(self):
        self.body['attempts'][0]['worker_journal'] = None
        with self.assertRaises(ValueError): self.check()

    def test_missing_bound_session_and_all_capture_refuse(self):
        self.body['attempts'][0].update(session=None, session_journal=None, worker_journal=None)
        with self.assertRaises(ValueError): self.check()

    def test_cross_attempt_worker_journal_refuses(self):
        self.body['attempts'][0]['worker_journal'] = self.body['attempts'][1]['worker_journal']
        with self.assertRaises(ValueError): self.check()

    def test_cross_run_session_identity_refuses(self):
        self.body['attempts'][0]['outcome']['session']['id'] = 'foreign-session'
        self.rewrite_outcomes()
        with self.assertRaises(ValueError): self.check()

    def test_omitted_failed_attempt_refuses(self):
        self.body['attempts'].pop(0)
        with self.assertRaises(ValueError): self.check()

    def test_omitted_entire_history_cannot_select_successes(self):
        self.body.update(ledger='', attempts=[])
        with self.assertRaises(ValueError): self.check()

    def test_interrupted_intent_refuses(self):
        self.body['ledger'] = self.body['ledger'].splitlines()[0] + '\n'
        with self.assertRaises(ValueError): self.check()

    def test_foreign_task_in_original_session_refuses(self):
        record = self.body['attempts'][0]
        session = codec.parse(record['session']); session['task_sha256'] = 'f' * 64
        record['session'] = codec.encoded(session).decode()
        with self.assertRaises(ValueError): self.check()

    def test_forbidden_recorded_effect_refuses(self):
        record = self.body['attempts'][1]
        def edit(row):
            request = row['event'].get('request', {})
            if request.get('tool') == 'write': request['path'] = '../outside.py'
        record['worker_journal'] = rechained(record['worker_journal'], edit)
        with self.assertRaises(ValueError): self.check()

    def test_original_external_pin_rejects_self_consistent_omission(self):
        self.body.update(ledger='', attempts=[])
        with self.assertRaisesRegex(ValueError, 'pin differs'): self.check(repin=False)

    def test_unknown_failed_closure_cannot_promote_procedure(self):
        record = self.body['attempts'][0]
        session = codec.parse(record['session'])
        terminal = dict(session['terminal'], status='INCOMPLETE', owned_processes_closed=False)
        session.update(terminal=terminal, failure='EXPLICIT ADVERSARIAL UNKNOWN CLOSURE')
        def edit(row):
            if row['phase'] == 'CLOSED': row['data'] = terminal
        record['session_journal'] = rechained(record['session_journal'], edit)
        session['journal_head'] = codec.parse(record['session_journal'].splitlines()[-1])['sha256']
        record['session'] = codec.encoded(session).decode()
        record['outcome']['session'].update(terminal=terminal, journal_head=session['journal_head'])
        self.rewrite_outcomes()
        with self.assertRaises(ValueError): self.check()

    def test_retired_failed_owner_does_not_resolve_missing_write_observation(self):
        record = self.body['attempts'][0]
        session = codec.parse(record['session'])
        terminal = dict(session['terminal'], status='INCOMPLETE', owner_exit=-9,
                        owned_processes_closed=True)
        rows = [codec.parse(line) for line in record['session_journal'].splitlines()]
        closed = rows.pop(); closed['data'] = terminal
        rows.extend([
            dict(closed, phase='DISPATCH_INTENT', data={'action': {
                'tool': 'write', 'path': 'totals.py', 'text': '# ADVERSARIAL UNKNOWN WRITE\n'}}),
            dict(closed, phase='UNKNOWN_AFTER_DISPATCH', data={
                'error': 'EXPLICIT ADVERSARIAL LOST OBSERVATION', 'retry_allowed': False}),
            closed,
        ])
        for index, row in enumerate(rows): row['sequence'] = index
        raw = '\n'.join(codec.encoded(row).decode() for row in rows) + '\n'
        record['session_journal'] = rechained(raw, lambda row: None)
        session.update(terminal=terminal, failure='EXPLICIT ADVERSARIAL LOST OBSERVATION',
                       journal_head=codec.parse(record['session_journal'].splitlines()[-1])['sha256'])
        record['session'] = codec.encoded(session).decode()
        record['outcome']['session'].update(terminal=terminal, journal_head=session['journal_head'])
        self.rewrite_outcomes()
        with self.assertRaises(ValueError): self.check()


if __name__ == '__main__': unittest.main()
