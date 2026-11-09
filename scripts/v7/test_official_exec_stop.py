"""Local adapter controls, not privileged cgroup or official-jailer evidence."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import gzip
import hashlib

import official_exec_stop as probe
import prepare_official_exec_stop as prepare


def controlled_diagnostic_fixture(minor=None):
    """TEST_ONLY contract fixture; never a real native execution claim."""
    boot = '00000000-0000-0000-0000-000000000001'
    parent = {'pid': 111, 'start_time_ticks': 10, 'boot_id': boot}
    def receipt(pid, start, code, status):
        return {'pid': pid, 'start_time_ticks': start, 'boot_id': boot,
                'handle': 'original_pidfd', 'wait': 'waitid(P_PIDFD,__WALL)',
                'si_code': code, 'si_status': status, 'signal': status, 'reaped': True}
    a, b = receipt(111, 10, os.CLD_EXITED, 0), receipt(112, 11, os.CLD_KILLED, 9)
    report = {'phase': 'TEST_ONLY_EXEC_STOP_REAPED', 'authority': 'NONE',
              'vmm_userspace_executed': False, 'pid': 112, 'start': 11,
              'origin': {'root': {'dev': 31, 'ino': 300}, 'entries': {}},
              'original_jailer': parent, 'jailer_reaped': True,
              'jailer_exit_status': a, 'target_terminal': b, 'cgroup_empty': True,
              'live_stop_observations': {'terminal': {'empty': True}},
              'terminal_receipts': {'schema': 'realm.exec-stop-diagnostic-terminal.v1',
                                    'complete': True, 'unresolved_descendant_discovery': False, 'required_original_pids': [111, 112],
                                    'receipts': [a, b]},
              'host_userfaultfd_minor': minor, 'excluded_optional_userfaultfd': None}
    journal = [{'phase': 'ORIGINAL_JAILER_EXEC_PINNED', 'jailer': parent},
               {'phase': 'ORIGINAL_JAILER_TERMINAL_PEEK', 'receipt': {**a, 'reaped': False}},
               {'phase': 'STAGE_FD_CENSUS', 'pid': 112, 'start_time_ticks': 11,
                'descriptors': [{'fd': 0}, {'fd': 1}, {'fd': 2}], 'userfaultfd_inherited': False},
               {'phase': 'DEVICE_EXCLUSION_BEFORE', 'pid': 112, 'stage_start_ticks': 11,
                'expected_userfaultfd_minor': minor, 'census': {'root': {'dev': 31, 'ino': 300}}},
               {'phase': 'OFFICIAL_EXEC_STOP', 'pid': 112, 'start': 11}, report.copy()]
    journal.insert(1, {'phase': 'ORIGINAL_DESCENDANT_DISCOVERED', 'parent': 111, 'pid': 112})
    if minor is not None:
        node = {'device': 31, 'inode': 500, 'mode': 0o20600, 'uid': 65534, 'gid': 65534,
                'rdev': os.makedev(10, minor), 'links': 1}
        directory = {'device': 31, 'inode': 400, 'mode': 0o40700, 'uid': 65534, 'gid': 65534}
        exclusion = {'phase': 'DEVICE_EXCLUSION_COMPLETE', 'authority': 'NONE', 'pid': 112,
                     'path': 'dev/userfaultfd', 'path_absent': True, 'original_inode_unlinked': True,
                     'before': node, 'held_after': {**node, 'links': 0}, 'dev_before': directory,
                     'dev_after': {**directory, 'mode': 0o40755, 'uid': 0, 'gid': 0}}
        report['excluded_optional_userfaultfd'] = exclusion
        journal.insert(-2, exclusion)
        journal[-1] = report.copy()
    return report, journal


def fixture_stdout(report):
    return ('running 1 test\nOFFICIAL_EXEC_STOP_DIAGNOSTIC ' + json.dumps(report) +
            '\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n')


class DeadlineAndInputControls(unittest.TestCase):
    def test_sibling_completion_channel(self):
        read, write = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read)
            os.write(write, b'C')
            os._exit(0)
        os.close(write)
        try:
            self.assertEqual(probe.wait_reason(read, time.monotonic() + 2), 'COMPLETE')
        finally:
            os.close(read)
            os.waitpid(child, 0)

    def test_actual_controller_death_is_not_success(self):
        read, write = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read)
            os._exit(71)  # No completion byte; ordinary descriptor EOF is loss.
        os.close(write)
        try:
            self.assertEqual(probe.wait_reason(read, time.monotonic() + 2), 'CONTROLLER_LOST')
        finally:
            os.close(read)
            os.waitpid(child, 0)

    def test_actual_monotonic_timeout_does_not_need_controller_progress(self):
        read, write = os.pipe()
        start = time.monotonic()
        try:
            self.assertEqual(probe.wait_reason(read, start + 0.05), 'DEADLINE')
            self.assertGreaterEqual(time.monotonic() - start, 0.05)
            self.assertLess(time.monotonic() - start, 2)
        finally:
            os.close(read)
            os.close(write)

    def test_unrecognized_completion_is_loss(self):
        read, write = os.pipe()
        os.write(write, b'X')
        try:
            self.assertEqual(probe.wait_reason(read, time.monotonic() + 2), 'CONTROLLER_LOST')
        finally:
            os.close(read)
            os.close(write)

    def test_jailer_cannot_select_unwatched_subtree(self):
        raw = {'backend': {'production_jailer': {'uid': 1001, 'gid': 1001,
                                                'cgroup_parent': 'elsewhere/jailer'}}}
        with self.assertRaisesRegex(ValueError, 'inside watchdog'):
            probe.validate_inputs(json.dumps(raw), 'case1')
        raw['backend']['production_jailer']['cgroup_parent'] = 'realm-exec-stop-case1/jailer'
        self.assertEqual(probe.validate_inputs(json.dumps(raw), 'case1')[1], 'realm-exec-stop-case1')
        raw['backend']['production_jailer']['uid'] = 0
        with self.assertRaisesRegex(ValueError, 'non-root'):
            probe.validate_inputs(json.dumps(raw), 'case1')

    def test_run_identity_cannot_traverse(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            probe.validate_inputs(b'{}', '../outside')

    def test_terminal_cgroup_contract_requires_both_observations(self):
        # Explicit TEST_ONLY regular files check parser semantics, not cgroup enforcement.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            (p / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
            (p / 'cgroup.procs').write_text('123\n')
            fd = os.open(p, os.O_RDONLY)
            try:
                self.assertFalse(probe.empty(fd))
                (p / 'cgroup.procs').write_text('')
                self.assertTrue(probe.empty(fd))
                (p / 'cgroup.events').write_text('populated 1\n')
                self.assertFalse(probe.empty(fd))
            finally:
                os.close(fd)

    def test_evidence_creation_never_overwrites(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'result.json'
            probe.save(p, {'authority': 'NONE'})
            original = p.read_bytes()
            with self.assertRaises(FileExistsError):
                probe.save(p, {'status': 'PASS'})
            self.assertEqual(p.read_bytes(), original)

    def test_zero_tests_and_stale_report_cannot_pass(self):
        report, journal = controlled_diagnostic_fixture()
        marker = 'OFFICIAL_EXEC_STOP_DIAGNOSTIC ' + json.dumps(report)
        with self.assertRaisesRegex(ValueError, 'exactly once'):
            probe.native_report('running 0 tests\n' + marker, report, journal, (65534, 65534, None))
        stdout = 'running 1 test\ntest original ... ' + marker + '\n' + \
                 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n'
        probe.native_report(stdout, report, journal, (65534, 65534, None))
        with self.assertRaisesRegex(ValueError, 'differs'):
            probe.native_report(stdout.replace(marker, ''), report, journal, (65534, 65534, None))
        with self.assertRaisesRegex(ValueError, 'differs'):
            probe.native_report(stdout + marker, report, journal, (65534, 65534, None))

    def test_stalled_controller_cannot_keep_prerelease_gate_open(self):
        # Actual independent child aborts a real blocked exec gate while this
        # controller makes no progress. No cgroup/official execution is claimed.
        gate_read, gate_write = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(gate_write)
            value = os.read(gate_read, 1)
            os._exit(0 if value == b'A' else 71)
        guardian = os.fork()
        if guardian == 0:
            os.close(gate_read)
            time.sleep(0.05)
            os.write(gate_write, b'A')
            os._exit(0)
        os.close(gate_read)
        time.sleep(0.15)  # Deliberately no controller progress during deadline.
        try:
            self.assertEqual(os.waitpid(child, 0)[1], 0)
            self.assertEqual(os.waitpid(guardian, 0)[1], 0)
        finally:
            os.close(gate_write)

    def test_changed_or_linked_preparation_input_refuses_before_decompression(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'input.gz'
            original = gzip.compress(b'original')
            p.write_bytes(original)
            pin = hashlib.sha256(original).hexdigest()
            self.assertEqual(prepare.bounded_read(p, len(original), pin), original)
            p.write_bytes(gzip.compress(b'changed'))
            with self.assertRaises(ValueError):
                prepare.bounded_read(p, len(original), pin)
            with self.assertRaises(ValueError):
                prepare.bounded_read(p, 1, pin)

    def test_expanded_image_size_is_bounded(self):
        raw = gzip.compress(b'x' * 10000)
        with self.assertRaisesRegex(ValueError, 'expanded'):
            prepare.expanded(raw, 128, hashlib.sha256(b'x' * 128).hexdigest())

    def test_original_inner_receipts_refuse_missing_tampered_and_cross_run(self):
        import copy
        for case in range(10):
            report, journal = copy.deepcopy(controlled_diagnostic_fixture())
            rows = report['terminal_receipts']['receipts']
            if case == 0: del report['terminal_receipts']
            elif case == 1: rows.pop()
            elif case == 2: rows[1]['pid'] = 999
            elif case == 3: rows[1]['start_time_ticks'] += 1
            elif case == 4: rows[1]['boot_id'] = 'another-run'
            elif case == 5: rows[1]['reaped'] = None
            elif case == 6: rows[1]['wait'] = 'unobserved assertion'
            elif case == 7: rows[1]['si_code'] = True
            elif case == 8: journal = []
            else: journal[-1] = {'phase': 'REFUSAL_TERMINAL_RECEIPTS'}
            with self.subTest(case=case), self.assertRaises((ValueError, KeyError)):
                probe.native_report(fixture_stdout(report), report, journal, (65534, 65534, None))

    def test_optional_device_absence_and_fd_census_are_required(self):
        import copy
        for case in range(4):
            report, journal = copy.deepcopy(controlled_diagnostic_fixture())
            if case == 0: next(r for r in journal if r['phase'] == 'STAGE_FD_CENSUS')['userfaultfd_inherited'] = True
            elif case == 1: next(r for r in journal if r['phase'] == 'STAGE_FD_CENSUS')['descriptors'].append({'fd': 7})
            elif case == 2:
                report['host_userfaultfd_minor'] = 257
                next(r for r in journal if r['phase'] == 'DEVICE_EXCLUSION_BEFORE')['expected_userfaultfd_minor'] = 257
            else: journal.append({'phase': 'CHAIN_REFUSED'})
            with self.subTest(case=case), self.assertRaises((ValueError, KeyError)):
                probe.native_report(fixture_stdout(report), report, journal, (65534, 65534, None))

    def test_independent_optional_device_policy_refuses_altered_objects(self):
        import copy
        report, journal = controlled_diagnostic_fixture(257)
        probe.native_report(fixture_stdout(report), report, journal, (65534, 65534, 257))
        for case in range(11):
            report, journal = copy.deepcopy(controlled_diagnostic_fixture(257))
            row = report['excluded_optional_userfaultfd']
            if case == 0: row['before']['mode'] = 0o20666
            elif case == 1: row['before']['rdev'] = os.makedev(10, 258)
            elif case == 2: row['before']['uid'] = 1
            elif case == 3: row['before']['gid'] = 1
            elif case == 4: row['before']['links'] = 2
            elif case == 5: row['held_after']['inode'] = 999
            elif case == 6: row['path_absent'] = False
            elif case == 7: row['dev_after']['mode'] = 0o40777
            elif case == 8: next(r for r in journal if r['phase'] == 'ORIGINAL_JAILER_TERMINAL_PEEK')['receipt']['reaped'] = True
            elif case == 10: row['before']['rdev'] = os.makedev(11, 257)
            else:
                index = next(i for i, r in enumerate(journal) if r['phase'] == 'DEVICE_EXCLUSION_COMPLETE')
                journal.insert(-1, journal.pop(index))
            with self.subTest(case=case), self.assertRaises((ValueError, KeyError)):
                probe.native_report(fixture_stdout(report), report, journal, (65534, 65534, 257))


if __name__ == '__main__':
    unittest.main()
