"""Actual OS boundary controls; no mocked isolation or coding acceptance."""
import json
import os
from pathlib import Path
import platform
import tempfile
import unittest

import coding_worker as worker
from controller_boundary import ProposalProcess, dispatch


@unittest.skipUnless(platform.system() == 'Darwin', 'this campaign qualifies only the tested Mac boundary')
class ControllerBoundaryTests(unittest.TestCase):
    def test_hidden_positive_negative_directory_alias_and_inherited_fd(self):
        with tempfile.TemporaryDirectory(prefix='realm-controller-') as name:
            root = Path(name).resolve()
            private = root / 'private'; private.mkdir(mode=0o700)
            secret = private / 'policy'; secret.write_text('private-decision-input')
            alias = root / 'alias'; alias.symlink_to(secret)
            # Deliberately inheritable at the parent; close_fds must remove it.
            fd = os.open(secret, os.O_RDONLY); os.set_inheritable(fd, True)
            try:
                child = ProposalProcess([private, secret, alias])
                program = '''import os,json,socket
out={}
def observe(name, fn):
 try: fn(); out[name]='BYPASS'
 except OSError as e: out[name]=e.errno
observe('positive',lambda:open(SECRET).read())
observe('negative',lambda:os.stat(MISSING))
observe('directory',lambda:os.listdir(PRIVATE))
observe('alias',lambda:open(ALIAS).read())
observe('write',lambda:open(SECRET,'w'))
observe('fd',lambda:os.read(FD,1))
observe('network',lambda:socket.socket().connect(('127.0.0.1',9)))
print(json.dumps(out))
'''
                for key, value in [('SECRET', str(secret)), ('MISSING', str(private / 'absent')),
                                   ('PRIVATE', str(private)), ('ALIAS', str(alias)), ('FD', fd)]:
                    program = program.replace(key, repr(value))
                captures = []
                for decision in ('allow', 'deny'):
                    secret.write_text(decision)
                    if decision == 'deny':
                        (private / 'absent').write_text('now present')
                    result, capture = child.propose(program, {'task': worker.DESCRIPTION})
                    self.assertEqual(capture['exit'], 0, capture)
                    self.assertEqual(set(result), {'positive', 'negative', 'directory', 'alias', 'write', 'fd', 'network'})
                    self.assertTrue(all(type(v) is int and v > 0 for v in result.values()), result)
                    for key in ('positive', 'directory', 'alias', 'write', 'network'):
                        self.assertIn(result[key], (1, 13))
                    self.assertEqual(result['fd'], 9)
                    # Actual counterexample: negative lookup reaches ENOENT,
                    # while the existing object is denied. Keep it visible;
                    # this route must refuse qualification rather than claim
                    # that a sandbox label establishes observation completeness.
                    if decision == 'allow':
                        self.assertEqual(result['negative'], 2)
                    else:
                        self.assertIn(result['negative'], (1, 13))
                    self.assertIn(result['positive'], (1, 13))
                    self.assertEqual(secret.read_text(), decision)
                    self.assertEqual(capture['causal_reuse'], 'REFUSE')
                    self.assertEqual(capture['complete_observation_admission'], 'REFUSE')
                    captures.append(capture)
                    with self.assertRaisesRegex(ValueError, 'no qualified native'):
                        child.require_qualified()
                self.assertNotEqual(captures[0]['stdout_hex'], captures[1]['stdout_hex'])
                retained = os.environ.get('REALM_CONTROLLER_PROBE_OUTPUT')
                if retained:
                    with Path(retained).open('x') as stream:
                        json.dump({'classification': 'REAL_OS_NEGATIVE_LOOKUP_COUNTEREXAMPLE',
                                   'authority': 'NONE', 'captures': captures}, stream, indent=2)
            finally:
                os.close(fd)

    def test_two_histories_same_journal_prefix_but_negative_lookup_changes_decision(self):
        # Actual same controller source and stdin, same protected path and same
        # broker list operation. Only the unrecorded namespace state changes.
        with tempfile.TemporaryDirectory(prefix='realm-negative-histories-') as name:
            root = Path(name).resolve(); private = root / 'private'; private.mkdir(mode=0o700)
            protected = private / 'hidden'
            child = ProposalProcess([private])
            program = ("import os,sys,json\ntry: os.stat(" + repr(str(protected)) + ")\n"
                       "except OSError as e: code=e.errno\n"
                       "else: code=0\n"
                       "print(json.dumps({'tool':'list'}))\n"
                       "print(json.dumps({'errno':code,'decision':'missing' if code==2 else 'protected'}),file=sys.stderr)\n")
            histories = []
            for present in (False, True):
                if present:
                    protected.write_text('hidden'); protected.chmod(0o600)
                broker = worker.Worker(root / ('present' if present else 'missing'),
                                       worker.digest(worker.encoded(worker.contract())))
                try:
                    proposal, capture = child.propose(program, {'task': worker.DESCRIPTION})
                    self.assertEqual(capture['exit'], 0, capture)
                    broker.request(proposal)
                    prefix = (broker.root / 'events.jsonl').read_bytes()
                    decision = worker.parse(bytes.fromhex(capture['stderr_hex']))
                    # The controller's actual branch is carried on a separate
                    # diagnostic channel. The old tool journal omits it.
                    broker.request({'tool':'write','path':'report.py','text':decision['decision']})
                    histories.append((prefix, (broker.root / 'candidate/report.py').read_bytes(), capture, decision))
                    self.assertEqual(capture['complete_observation_admission'], 'REFUSE')
                    with self.assertRaisesRegex(ValueError, 'no qualified native'):
                        child.require_qualified()
                finally:
                    broker.close()
            a, b = histories
            self.assertEqual(a[0], b[0])
            for field in ('controller_sha256', 'stdin_hex', 'stdout_hex', 'interpreter_sha256'):
                self.assertEqual(a[2][field], b[2][field])
            self.assertEqual(a[3]['errno'], 2)
            self.assertIn(b[3]['errno'], (1, 13))
            self.assertNotEqual(a[2]['stderr_hex'], b[2]['stderr_hex'])
            self.assertNotEqual(a[1], b[1])
            retained = os.environ.get('REALM_TWO_HISTORY_CAPTURE')
            if retained:
                with Path(retained).open('x') as stream:
                    json.dump({'authority':'NONE', 'legacy_prefixes_equal':a[0] == b[0],
                               'prefix_sha256':worker.digest(a[0]),
                               'histories':[{'capture':h[2], 'decision':h[3],
                                             'report_hex':h[1].hex()} for h in histories]}, stream, indent=2)

    def test_actual_broker_roundtrip_and_unauthorized_proposal(self):
        with tempfile.TemporaryDirectory(prefix='realm-controller-tools-') as name:
            root = Path(name).resolve()
            broker = worker.Worker(root / 'run', worker.digest(worker.encoded(worker.contract())))
            try:
                child = ProposalProcess([broker.root])
                result, capture = dispatch(child, "print('{\"tool\":\"read\",\"path\":\"totals.py\"}')", {}, broker)
                self.assertEqual(result['text'], worker.BASELINE['totals.py'])
                self.assertEqual(json.loads(bytes.fromhex(capture['tool_result_hex'])), result)
                before = broker.tree(); count = broker.count
                result, capture = dispatch(child, "print('{\"tool\":\"write\",\"path\":\"../escape\",\"text\":\"x\"}')", {}, broker)
                self.assertIsNone(result); self.assertEqual(capture['status'], 'REFUSE')
                self.assertEqual(broker.tree(), before); self.assertEqual(broker.count, count)
                result, capture = dispatch(child, "print('not json')", {}, broker)
                self.assertIsNone(result); self.assertEqual(capture['status'], 'REFUSE')
                self.assertEqual(broker.count, count)
            finally:
                broker.close()

    def test_protected_runtime_overlap_refuses_before_launch(self):
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            ProposalProcess([Path('/System')])


if __name__ == '__main__':
    unittest.main()
