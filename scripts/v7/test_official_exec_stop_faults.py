"""Independent software fault controls; regular-file cgroups are TEST_ONLY.

Real forks, pipes, signals and the original watchdog execute on local Linux.
These tests do not exercise a kernel cgroup, root setup, jailer or guest and
cannot establish physical closure or production authority.
"""
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import official_exec_stop as probe
import prepare_official_exec_stop as prepare


@unittest.skipUnless(platform.system() == 'Linux', 'local Linux watchdog execution required')
class WatchdogFaultControls(unittest.TestCase):
    def exercise(self, reason, *, populated=False, fault=None):
        with tempfile.TemporaryDirectory(prefix='realm-test-only-watchdog-') as directory:
            root = Path(directory)
            reported_populated = populated and fault != 'cgroup.procs'
            (root/'cgroup.events').write_text('populated '+str(int(reported_populated))+'\nfrozen 0\n')
            (root/'cgroup.procs').write_text('TEST_ONLY_NOT_A_PID\n' if populated else '')
            (root/'cgroup.kill').write_text('')
            group = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            complete_read, complete_write = os.pipe()
            ready_read, ready_write = os.pipe()
            gate_read, gate_write = os.pipe()
            deadline = time.monotonic()+0.25
            original_leaf = probe.leaf
            def inject(group, name, value=None):
                if name == fault:
                    raise OSError(errno.EIO, 'TEST_ONLY injected kernel-leaf read/write failure')
                return original_leaf(group, name, value)
            child = os.fork()
            if child == 0:
                os.close(complete_write); os.close(ready_read); os.close(gate_read)
                try:
                    with patch.object(probe, 'leaf', side_effect=inject):
                        probe.watchdog(group, complete_read, ready_write, gate_write,
                                       deadline, root/'watchdog.json')
                except BaseException:
                    os._exit(121)
            os.close(complete_read); os.close(ready_write); os.close(gate_write)
            status = None
            try:
                self.assertTrue(select.select([ready_read], [], [], 2)[0])
                ready = os.read(ready_read, 1)
                if fault == 'cgroup.events':
                    self.assertEqual(ready, b'')
                else:
                    self.assertEqual(ready, b'R')
                if reason == 'COMPLETE':
                    os.write(complete_write, b'C')
                elif reason == 'CONTROLLER_LOST':
                    os.close(complete_write); complete_write = None
                if populated and fault is None:
                    end = time.monotonic()+2
                    while (root/'cgroup.kill').read_text() != '1' and time.monotonic()<end:
                        time.sleep(0.005)
                    self.assertEqual((root/'cgroup.kill').read_text(), '1')
                    # Explicit TEST_ONLY response, not a kernel observation.
                    (root/'cgroup.events').write_text('populated 0\nfrozen 0\n')
                    (root/'cgroup.procs').write_text('')
                end = time.monotonic()+2
                while time.monotonic()<end:
                    waited, status = os.waitpid(child, os.WNOHANG)
                    if waited: break
                    status = None
                    time.sleep(0.005)
                self.assertIsNotNone(status, 'watchdog did not retire in local test bound')
                result = json.loads((root/'watchdog.json').read_text())
                self.assertEqual(result['authority'], 'NONE')
                self.assertEqual(result['qualification'], 'NOT_RUN')
                if fault:
                    self.assertNotEqual(status, 0)
                    self.assertFalse(result['cgroup_empty'])
                    self.assertIn('error', result)
                    if fault != 'cgroup.kill':
                        self.assertEqual((root/'cgroup.kill').read_text(), '1')
                    else:
                        self.assertIn('kill_error', result)
                else:
                    self.assertEqual(status, 0)
                    self.assertEqual(result['reason'], reason)
                    self.assertEqual(result['forced'], populated)
                    self.assertTrue(result['cgroup_empty'])
                    self.assertTrue(select.select([gate_read], [], [], 1)[0])
                    self.assertEqual(os.read(gate_read, 1), b'A')
                print(json.dumps({'test_only_regular_file_cgroup':True,
                                  'reason':reason,'fault':fault,'watchdog':result},sort_keys=True))
            finally:
                if status is None:
                    try: os.kill(child, signal.SIGKILL)
                    except ProcessLookupError: pass
                    os.waitpid(child, 0)
                for fd in [group, complete_write, ready_read, gate_read]:
                    if fd is not None: os.close(fd)

    def test_actual_watchdog_deadline_without_controller_progress(self):
        self.exercise('DEADLINE')

    def test_actual_watchdog_controller_loss_is_not_complete(self):
        self.exercise('CONTROLLER_LOST')

    def test_actual_watchdog_normal_completion_is_not_qualification(self):
        self.exercise('COMPLETE')

    def test_interrupted_populated_fixture_requests_kill_and_waits_readback(self):
        self.exercise('CONTROLLER_LOST', populated=True)

    def test_startup_read_failure_never_releases_ready(self):
        self.exercise('CONTROLLER_LOST', fault='cgroup.events')

    def test_cleanup_read_failure_still_attempts_kill(self):
        self.exercise('CONTROLLER_LOST', populated=True, fault='cgroup.procs')

    def test_kill_failure_remains_incomplete(self):
        self.exercise('CONTROLLER_LOST', populated=True, fault='cgroup.kill')

    def test_stopped_child_needs_kernel_termination_not_an_abort_byte(self):
        # Actual process fact: queued pipe abort cannot terminate a stopped
        # child. This is why physical admission/reaping must be tested later.
        read, write = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(write)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.read(read, 1)
            os._exit(0)
        os.close(read)
        try:
            waited, status = os.waitpid(child, os.WUNTRACED)
            self.assertEqual(waited, child)
            self.assertTrue(os.WIFSTOPPED(status))
            os.write(write, b'A')
            self.assertEqual(os.waitpid(child, os.WNOHANG), (0, 0))
        finally:
            os.kill(child, signal.SIGKILL)
            waited, status = os.waitpid(child, 0)
            os.close(write)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)

    def test_killed_watchdog_cannot_supply_a_success_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'cgroup.events').write_text('populated 0\n')
            (root/'cgroup.procs').write_text('')
            group=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            done_r,done_w=os.pipe(); ready_r,ready_w=os.pipe(); gate_r,gate_w=os.pipe()
            child=os.fork()
            if child==0:
                os.close(done_w); os.close(ready_r); os.close(gate_r)
                probe.watchdog(group,done_r,ready_w,gate_w,time.monotonic()+10,root/'result.json')
            os.close(done_r); os.close(ready_w); os.close(gate_w)
            try:
                self.assertTrue(select.select([ready_r],[],[],2)[0])
                self.assertEqual(os.read(ready_r,1),b'R')
            finally:
                os.kill(child,signal.SIGKILL)
                _,status=os.waitpid(child,0)
                for fd in [group,done_w,ready_r,gate_r]: os.close(fd)
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
            self.assertFalse((root/'result.json').exists())


@unittest.skipUnless(platform.system() == 'Linux', 'actual Linux pidfd/subreaper required')
class OwnedProcessReapingControls(unittest.TestCase):
    def test_original_pidfds_reap_stopped_setsid_orphan(self):
        original=probe.child_subreaper(); probe.child_subreaper(1)
        read,write=os.pipe(); parent=None; descendant=None; parent_fd=None; descendant_fd=None
        reaped=set()
        try:
            parent=os.fork()
            if parent==0:
                os.close(read)
                descendant=os.fork()
                if descendant==0:
                    os.close(write)
                    os.setsid(); os.kill(os.getpid(),signal.SIGSTOP)
                    time.sleep(30); os._exit(0)
                os.write(write,str(descendant).encode()); os.close(write)
                time.sleep(30); os._exit(0)
            os.close(write); write=None
            self.assertTrue(select.select([read],[],[],2)[0])
            descendant=int(os.read(read,64))
            end=time.monotonic()+2
            while time.monotonic()<end:
                fields=Path(f'/proc/{descendant}/stat').read_text().rsplit(')',1)[1].split()
                if fields[0]=='T': break
                time.sleep(0.002)
            self.assertEqual(fields[0],'T')
            self.assertEqual(int(fields[1]),parent)
            self.assertEqual(int(fields[3]),descendant)
            self.assertEqual(Path(f'/proc/{parent}/task/{parent}/children').read_text().split(),[str(descendant)])
            parent_fd=os.pidfd_open(parent); descendant_fd=os.pidfd_open(descendant)
            # Independent native identity must refuse a wrong cgroup. Real
            # membership is intentionally not rewritten into a qualification.
            with self.assertRaisesRegex(ValueError,'held subtree'):
                probe.observe_control_descendant(parent,'TEST_ONLY_WRONG_GROUP',time.monotonic()+1,0)
            signal.pidfd_send_signal(parent_fd,signal.SIGKILL)
            signal.pidfd_send_signal(descendant_fd,signal.SIGKILL)
            results=[]
            for fd,pid in [(parent_fd,parent),(descendant_fd,descendant)]:
                end=time.monotonic()+2; terminal=None
                while terminal is None and time.monotonic()<end:
                    terminal=os.waitid(os.P_PIDFD,fd,os.WEXITED|os.WNOHANG)
                    if terminal is None: time.sleep(0.002)
                self.assertIsNotNone(terminal)
                reaped.add(terminal.si_pid)
                self.assertEqual((terminal.si_pid,terminal.si_code,terminal.si_status),
                                 (pid,os.CLD_KILLED,signal.SIGKILL))
                results.append({'pid':pid,'si_code':terminal.si_code,'signal':terminal.si_status,'reaped':True})
            print(json.dumps({'actual_local_linux_pidfd_reaping':results,
                              'cgroup_enforcement':'NOT_RUN','authority':'NONE'},sort_keys=True))
        finally:
            for fd in [parent_fd,descendant_fd]:
                if fd is not None:
                    try: signal.pidfd_send_signal(fd,signal.SIGKILL)
                    except ProcessLookupError: pass
                    os.close(fd)
            for pid in [parent,descendant]:
                if pid and pid not in reaped:
                    try:
                        os.kill(pid,signal.SIGKILL); os.waitpid(pid,0)
                    except (ProcessLookupError,ChildProcessError): pass
            os.close(read)
            if write is not None: os.close(write)
            probe.child_subreaper(original)
            self.assertEqual(probe.child_subreaper(),original)


class PreparationFaultControls(unittest.TestCase):
    @unittest.skipUnless(platform.system() == 'Linux' and Path('/usr/sbin/debugfs').is_file(),
                         'real Linux debugfs required for the native dependency interface')
    def test_native_clean_environment_resolves_real_debugfs(self):
        self.assertEqual(shutil.which('debugfs', path=probe.NATIVE_EXEC_PATH), '/usr/sbin/debugfs')
        result = subprocess.run(['debugfs', '-V'],
                                env={'PATH': probe.NATIVE_EXEC_PATH, 'LC_ALL': 'C'},
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'debugfs', result.stderr + result.stdout)

    def test_control_mode_rejects_native_arguments_before_any_setup(self):
        # TEST_ONLY host identity patches exercise rejection only. mkdir and
        # native reads are traps, so this cannot install a privileged fixture.
        args=SimpleNamespace(deadline_control=True,run_id='software-only',
                             elf='/TEST_ONLY_FORBIDDEN',elf_sha256=None,inputs=None,inputs_sha256=None)
        with patch.object(probe.platform,'system',return_value='Linux'), \
                patch.object(probe.platform,'machine',return_value='x86_64'), \
                patch.object(probe.os,'geteuid',return_value=0), \
                patch.object(probe,'held_file',side_effect=AssertionError('native input accessed')), \
                patch.object(probe.Path,'mkdir',side_effect=AssertionError('setup attempted')):
            with self.assertRaisesRegex(ValueError,'must not supply native'):
                probe.run(args)

    def test_control_mode_never_reads_native_inputs_before_protected_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(deadline_control=True,run_id='software-only',elf=None,
                                 elf_sha256=None,inputs=None,inputs_sha256=None,output=str(Path(directory)/'out'))
            # Stop at the first evidence write, before held-file checks or ANY
            # cgroup creation. This is control input routing, not host success.
            with patch.object(probe.platform,'system',return_value='Linux'), \
                    patch.object(probe.platform,'machine',return_value='x86_64'), \
                    patch.object(probe.os,'geteuid',return_value=0), \
                    patch.object(probe,'held_file',side_effect=AssertionError('native input accessed')), \
                    patch.object(probe,'save',side_effect=RuntimeError('TEST_ONLY_STOP_BEFORE_KERNEL_SETUP')):
                with self.assertRaisesRegex(RuntimeError,'STOP_BEFORE_KERNEL_SETUP'):
                    probe.run(args)
            self.assertEqual(list(Path(args.output).iterdir()),[])

    def test_native_cli_missing_pins_refuses_before_host_or_input_access(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'out'
            result=subprocess.run([sys.executable,'-B',probe.__file__,'--run-id','software-only',
                                   '--output',str(out)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,2)
            self.assertIn(b'official execution requires exact executable',result.stderr)
            self.assertFalse(out.exists())

    def test_unqualified_host_refuses_before_input_or_resource_access(self):
        if platform.system()=='Linux' and os.geteuid()==0:
            self.skipTest('this refusal control requires actual non-root or non-Linux')
        with self.assertRaisesRegex(ValueError,'separately approved'):
            probe.run(SimpleNamespace())

    def test_symlink_hardlink_and_nonregular_input_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source=root/'original'; source.write_bytes(b'TEST_ONLY')
            pin=hashlib.sha256(source.read_bytes()).hexdigest()
            alias=root/'alias'; alias.symlink_to(source)
            with self.assertRaises(OSError): prepare.bounded_read(alias, 9, pin)
            alias.unlink(); os.link(source, alias)
            with self.assertRaises(ValueError): prepare.bounded_read(source, 9, pin)
            with self.assertRaises(ValueError): prepare.bounded_read(root, 9, pin)

    def test_changed_gzip_and_expansion_boundaries_refuse(self):
        plain=b'TEST_ONLY_IMAGE'; packed=gzip.compress(plain)
        self.assertEqual(prepare.expanded(packed,len(plain),hashlib.sha256(plain).hexdigest()),plain)
        for size in [len(plain)-1,len(plain)+1]:
            with self.assertRaises(ValueError): prepare.expanded(packed,size,hashlib.sha256(plain).hexdigest())
        with self.assertRaises(ValueError): prepare.expanded(packed,len(plain),'0'*64)
        with self.assertRaises((EOFError,OSError)): prepare.expanded(packed[:-3],len(plain),hashlib.sha256(plain).hexdigest())


if __name__ == '__main__':
    unittest.main()
