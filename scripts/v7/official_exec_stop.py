#!/usr/bin/env python3
"""Bound the existing ignored official-jailer test; never start a guest.

The watchdog is a sibling of the native diagnostic, outside its cgroup. Its
held cgroup survives controller loss. No JSON from this adapter grants authority.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import stat
import time

TEST = 'supervisor::tests::official_jailer_exec_stop_probe_without_vmm_userspace'
RUNTIME_SECONDS = 45
CLEANUP_SECONDS = 5
NATIVE_EXEC_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def save(path, value):
    raw = (json.dumps(value, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        pending = memoryview(raw)
        while pending:
            pending = pending[os.write(fd, pending):]
        os.fsync(fd)
    finally:
        os.close(fd)


def held_file(path, pin):
    require(re.fullmatch('[0-9a-f]{64}', pin), 'exact external SHA256 required')
    path = Path(path)
    require(path.is_absolute(), 'absolute protected input required')
    for parent in [path.parent, *path.parent.parents]:
        m = parent.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022,
                'unprotected input parent: ' + str(parent))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        m = os.fstat(fd)
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1
                and not m.st_mode & 0o022, 'unprotected input object')
        raw = b''
        while part := os.read(fd, 1024 * 1024):
            raw += part
        require(hashlib.sha256(raw).hexdigest() == pin, 'input SHA256 differs')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, raw, (m.st_dev, m.st_ino, m.st_size)
    except BaseException:
        os.close(fd)
        raise


def leaf(group, name, value=None):
    fd = os.open(name, (os.O_RDONLY if value is None else os.O_WRONLY)
                 | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=group)
    try:
        if value is not None:
            os.write(fd, value.encode())
            return None
        return os.read(fd, 65536).decode()
    finally:
        os.close(fd)


def empty(group):
    events = dict(line.split() for line in leaf(group, 'cgroup.events').splitlines())
    return events.get('populated') == '0' and not leaf(group, 'cgroup.procs').strip()


def wait_reason(channel, deadline):
    """EOF is controller loss, never permission to abandon cleanup."""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 'DEADLINE'
        ready, _, _ = select.select([channel], [], [], remaining)
        if ready:
            return 'COMPLETE' if os.read(channel, 1) == b'C' else 'CONTROLLER_LOST'


def watchdog(group, completion, ready, gate, deadline, output):
    os.setsid()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    result = {'reason': 'UNKNOWN', 'forced': False, 'authority': 'NONE',
              'qualification': 'NOT_RUN', 'cgroup_empty': False}
    try:
        identity = os.fstat(group)
        result['held_cgroup_identity'] = [identity.st_dev, identity.st_ino]
        result['watchdog_cgroup'] = Path('/proc/self/cgroup').read_text()
        # Read the held kernel object before authorizing controller admission.
        leaf(group, 'cgroup.events')
        os.write(ready, b'R')
        os.close(ready)
        reason = wait_reason(completion, deadline)
        try: os.write(gate, b'A')
        except BrokenPipeError: pass
        before = empty(group)
        result.update(reason=reason, forced=not before, cgroup_empty_before=before)
        if not before:
            leaf(group, 'cgroup.kill', '1')
        end = time.monotonic() + CLEANUP_SECONDS
        while not empty(group) and time.monotonic() < end:
            time.sleep(0.01)
        result.update(cgroup_empty=empty(group), observed_monotonic=time.monotonic(),
                      deadline_monotonic=deadline)
    except BaseException as error:
        result.update(cgroup_empty=False, error=repr(error))
        # Missing readback must not prevent the emergency kill attempt.
        try: leaf(group, 'cgroup.kill', '1')
        except BaseException as failure: result['kill_error'] = repr(failure)
    save(output, result)
    os._exit(0 if result.get('cgroup_empty') else 1)


def validate_inputs(raw, run_id):
    require(re.fullmatch('[a-z0-9-]{1,48}', run_id), 'invalid fresh run identity')
    inputs = json.loads(raw)
    group = 'realm-exec-stop-' + run_id
    config = inputs['backend']['production_jailer']
    require(config['cgroup_parent'] == group + '/jailer',
            'official jailer cgroup must stay inside watchdog subtree')
    require(config['uid'] != 0 and config['gid'] != 0, 'non-root jailer required')
    # The existing native test independently checks all eight exact resource pins.
    return inputs, group


def native_report(stdout, report, journal, expected_device):
    """Check non-authorizing diagnostic evidence, including original waits.

    This does not create runtime qualification or accept a canonical artifact.
    A matching JSON boolean is insufficient: bind every supplemental receipt
    and the final record to the original same-run kernel-observation journal.
    """
    require('running 1 test' in stdout and re.search(
        r'test result: ok\. 1 passed; 0 failed; 0 ignored;', stdout),
        'exact official diagnostic did not execute exactly once')
    lines = re.findall(r'OFFICIAL_EXEC_STOP_DIAGNOSTIC (\{[^\n]+\})', stdout)
    require(len(lines) == 1 and json.loads(lines[0]) == report,
            'fresh native report differs from actual test observation')
    require(report['vmm_userspace_executed'] is False and report['jailer_reaped'] is True
            and report['target_terminal']['reaped'] is True and report['cgroup_empty'] is True,
            'native original-owner exec-stop closure missing')
    require(report['live_stop_observations']['terminal']['empty'] is True,
            'native held cgroup closure missing')
    original = report.get('original_jailer', {})
    parent, target = original.get('pid'), report.get('pid')
    require(type(parent) is int and type(target) is int and parent > 0 and target > 0 and parent != target,
            'original inner process identities absent')
    boot = original.get('boot_id')
    require(isinstance(boot, str) and re.fullmatch(r'[0-9a-f-]{36}', boot), 'original boot identity absent')
    bundle = report.get('terminal_receipts', {})
    require(bundle.get('schema') == 'realm.exec-stop-diagnostic-terminal.v1'
            and bundle.get('complete') is True and bundle.get('unresolved_descendant_discovery') is False
            and bundle.get('required_original_pids') == sorted([parent, target]),
            'complete original inner custody receipts missing')
    receipts = bundle.get('receipts', [])
    require(len(receipts) == 2 and {r.get('pid') for r in receipts} == {parent, target},
            'original inner receipt set differs')
    for row in receipts:
        expected_start = original.get('start_time_ticks') if row['pid'] == parent else report.get('start')
        require(type(expected_start) is int and expected_start > 0
                and row.get('start_time_ticks') == expected_start and row.get('boot_id') == boot
                and row.get('reaped') is True and row.get('handle') == 'original_pidfd'
                and row.get('wait') == 'waitid(P_PIDFD,__WALL)',
                'inner receipt incarnation/handle/reaping differs')
        code, status = row.get('si_code'), row.get('si_status')
        require(type(code) is int and type(status) is int and
                ((row['pid'] == parent and (code, status) == (os.CLD_EXITED, 0))
                 or (code, status) == (os.CLD_KILLED, signal.SIGKILL)),
                'inner terminal result differs')
        expected = report['jailer_exit_status'] if row['pid'] == parent else report['target_terminal']
        require(row == expected, 'inner receipt substituted across records')
    require(isinstance(journal, list) and journal, 'original native journal absent')
    def one(phase):
        rows = [row for row in journal if row.get('phase') == phase]
        require(len(rows) == 1, 'original journal phase absent/duplicated: ' + phase)
        return rows[0]
    descendants = [r for r in journal if r.get('phase') == 'ORIGINAL_DESCENDANT_DISCOVERED']
    require(len(descendants) == 1 and descendants[0]['parent'] == parent and descendants[0]['pid'] == target,
            'original discovered descendant roster differs')
    require(one('ORIGINAL_JAILER_EXEC_PINNED')['jailer'] == original,
            'original jailer journal binding differs')
    peek = one('ORIGINAL_JAILER_TERMINAL_PEEK')['receipt']
    jailer_receipt = next(row for row in receipts if row['pid'] == parent)
    require(peek.get('reaped') is False and all(peek.get(k) == v for k, v in jailer_receipt.items() if k != 'reaped'),
            'original jailer was not terminal before device exclusion')
    fd_census = one('STAGE_FD_CENSUS')
    require(fd_census['pid'] == target and fd_census['start_time_ticks'] == report['start']
            and fd_census['userfaultfd_inherited'] is False
            and sorted(r['fd'] for r in fd_census['descriptors']) == [0, 1, 2],
            'original stage inherited descriptor census differs')
    stop = one('OFFICIAL_EXEC_STOP')
    require(stop['pid'] == target and stop['start'] == report['start'], 'final original exec stop differs')
    final = one('TEST_ONLY_EXEC_STOP_REAPED')
    require(journal[-1] == final and all(report.get(k) == v for k, v in final.items()),
            'terminal report differs from original journal')
    uid, gid, expected_minor = expected_device
    minor = report.get('host_userfaultfd_minor')
    require(type(uid) is int and type(gid) is int and uid > 0 and gid > 0 and minor == expected_minor,
            'independently observed device registration differs')
    exclusion = report.get('excluded_optional_userfaultfd')
    before = one('DEVICE_EXCLUSION_BEFORE')
    require(before['pid'] == target and before['stage_start_ticks'] == report['start']
            and before['expected_userfaultfd_minor'] == minor, 'device exclusion run differs')
    origin = report.get('origin', {})
    require(isinstance(origin.get('entries'), dict) and 'dev/userfaultfd' not in origin['entries']
            and before['census']['root'] == origin.get('root'),
            'post-exclusion canonical origin missing or foreign')
    if minor is not None:
        require(type(minor) is int and 0 <= minor <= 0xfffff, 'device registration differs')
        require(isinstance(exclusion, dict) and one('DEVICE_EXCLUSION_COMPLETE') == exclusion
                and exclusion['pid'] == target and exclusion['path'] == 'dev/userfaultfd'
                and exclusion['path_absent'] is True and exclusion['original_inode_unlinked'] is True
                and exclusion['held_after']['links'] == 0,
                'original device exclusion/absence evidence missing')
        node, after = exclusion['before'], exclusion['held_after']
        require((node['mode'], node['uid'], node['gid'], node['links'], node['rdev']) ==
                (stat.S_IFCHR | 0o600, uid, gid, 1, os.makedev(10, minor)),
                'vendor device metadata differs from independent policy')
        require(all(after[k] == node[k] for k in ('device', 'inode', 'mode', 'uid', 'gid', 'rdev')),
                'unlinked original device identity differs')
        old_dir, new_dir = exclusion['dev_before'], exclusion['dev_after']
        require((old_dir['mode'], old_dir['uid'], old_dir['gid']) == (stat.S_IFDIR | 0o700, uid, gid)
                and (new_dir['mode'], new_dir['uid'], new_dir['gid']) == (stat.S_IFDIR | 0o755, 0, 0)
                and all(new_dir[k] == old_dir[k] for k in ('device', 'inode')),
                'original protected device directory differs')
    else:
        require(exclusion is None and not any(r.get('phase') == 'DEVICE_EXCLUSION_COMPLETE' for r in journal),
                'unregistered device exclusion evidence substituted')
    phases = [r.get('phase') for r in journal]
    if minor is not None:
        require(phases.index('DEVICE_EXCLUSION_BEFORE') < phases.index('DEVICE_EXCLUSION_COMPLETE') < phases.index('OFFICIAL_EXEC_STOP'),
                'optional device was not excluded before VMM exec')
    require(phases.index('ORIGINAL_JAILER_EXEC_PINNED') < phases.index('ORIGINAL_JAILER_TERMINAL_PEEK') <
            phases.index('STAGE_FD_CENSUS') < phases.index('DEVICE_EXCLUSION_BEFORE') < phases.index('OFFICIAL_EXEC_STOP') < len(phases) - 1,
            'native custody phase ordering differs')
    require(not any(p in ('CHAIN_REFUSED', 'REFUSAL_TERMINAL_RECEIPTS') for p in phases),
            'refused/incomplete native custody cannot pass')


def child_subreaper(value=None):
    """Scoped Linux orphan ownership for the fixed two-process control only."""
    libc = ctypes.CDLL(None, use_errno=True)
    if value is None:
        current = ctypes.c_int()
        rc = libc.prctl(37, ctypes.byref(current), 0, 0, 0)  # PR_GET_CHILD_SUBREAPER
        require(rc == 0, 'cannot read child-subreaper state')
        return current.value
    require(libc.prctl(36, int(value), 0, 0, 0) == 0, 'cannot set child-subreaper state')
    require(child_subreaper() == value, 'child-subreaper state differs')


def observe_control_descendant(parent, group, deadline, held_group):
    """Pin the original stopped child from its kernel parent, before timeout."""
    while time.monotonic() < deadline:
        children = Path(f'/proc/{parent}/task/{parent}/children').read_text().split()
        if children:
            require(len(children) == 1, 'fixed control produced unexpected children')
            pid = int(children[0])
            fd = os.pidfd_open(pid)
            try:
                raw = Path(f'/proc/{pid}/stat').read_text()
                fields = raw.rsplit(')', 1)[1].split()
                membership = Path(f'/proc/{pid}/cgroup').read_text().strip()
                info = dict(line.split(':', 1) for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines() if ':' in line)
                if fields[0] != 'T':
                    os.close(fd)
                    time.sleep(0.002)
                    continue
                require(int(fields[1]) == parent and int(fields[3]) == pid,
                        'control descendant parent/session differs')
                require(membership == '0::/' + group + '/owner'
                        and int(info['Pid']) == pid and not select.select([fd], [], [], 0)[0],
                        'original stopped descendant is not live in held subtree')
                directories = {entry for entry in os.listdir(held_group)
                               if stat.S_ISDIR(os.stat(entry, dir_fd=held_group, follow_symlinks=False).st_mode)}
                require(directories == {'owner', 'jailer'} and not leaf(held_group, 'cgroup.procs').strip(),
                        'unexpected control root members or subgroups')
                members = None
                for subgroup in ('owner', 'jailer'):
                    subfd = os.open(subgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=held_group)
                    try:
                        require(not any(stat.S_ISDIR(os.stat(entry, dir_fd=subfd, follow_symlinks=False).st_mode)
                                        for entry in os.listdir(subfd)), 'unexpected nested control cgroup')
                        observed = {int(item) for item in leaf(subfd, 'cgroup.procs').split()}
                        require(observed == ({parent, pid} if subgroup == 'owner' else set()),
                                'fixed control cgroup process set differs')
                        if subgroup == 'owner': members = sorted(observed)
                    finally: os.close(subfd)
                observed_at = time.monotonic()
                require(observed_at < deadline, 'control identity observed after deadline')
                return fd, {'pid': pid, 'parent': parent, 'session': int(fields[3]),
                            'original_owner_members': members,
                            'start_time_ticks': int(fields[19]), 'state': fields[0],
                            'cgroup': membership, 'observed_monotonic': observed_at}
            except BaseException:
                os.close(fd)
                raise
        time.sleep(0.002)
    raise ValueError('original stopped descendant was not pinned before deadline')


def run(args):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and os.geteuid() == 0, 'requires separately approved root Linux x86 host')
    control = args.deadline_control
    elf = manifest = None
    if control:
        # This fixed control never accesses native executable/VM input authority.
        require(re.fullmatch('[a-z0-9-]{1,48}', args.run_id), 'invalid fresh run identity')
        require(not any((args.elf, args.elf_sha256, args.inputs, args.inputs_sha256)),
                'shutdown-only must not supply native inputs')
        name = 'realm-exec-stop-' + args.run_id + '-control'
    else:
        elf, binary, elf_id = held_file(args.elf, args.elf_sha256)
        manifest, raw, manifest_id = held_file(args.inputs, args.inputs_sha256)
        require(binary[:4] == b'\x7fELF' and binary[18:20] == b'\x3e\x00', 'native x86 ELF required')
        inputs, name = validate_inputs(raw, args.run_id)
        state = Path(inputs['backend']['state_dir'])
        require(not os.path.lexists(state / 'official-exec-stop-probe'), 'stale native diagnostic state')
    out = Path(args.output)
    require(out.is_absolute(), 'absolute fresh evidence directory required')
    out.mkdir(mode=0o700)
    # Refuse symlink/writable ancestors before privileged group creation.
    held_file_check = out / 'pins.json'
    save(held_file_check, {'control_only': True, 'authority': 'NONE',
                          'helper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
         if control else {'elf_sha256': args.elf_sha256, 'elf_identity': elf_id,
                          'inputs_sha256': args.inputs_sha256, 'inputs_identity': manifest_id})
    check, _, _ = held_file(held_file_check, hashlib.sha256(held_file_check.read_bytes()).hexdigest())
    os.close(check)
    cg = Path('/sys/fs/cgroup') / name
    cg.mkdir()  # Exclusive; never reuse or remove another run's cgroup.
    group = os.open(cg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    identity = os.fstat(group)
    require({'cpu', 'memory', 'pids'} <= set(leaf(group, 'cgroup.controllers').split()),
            'existing parent delegation missing; do not change host root controls')
    leaf(group, 'memory.max', '1073741824')
    leaf(group, 'pids.max', '128')
    leaf(group, 'cpu.max', '100000 100000')
    leaf(group, 'cgroup.subtree_control', '+cpu +memory +pids')
    limits = {name: leaf(group, name).strip() for name in ['memory.max', 'pids.max', 'cpu.max']}
    require(limits == {'memory.max': '1073741824', 'pids.max': '128', 'cpu.max': '100000 100000'},
            'watchdog resource limits did not read back exactly')
    (cg / 'owner').mkdir()
    (cg / 'jailer').mkdir()
    jailed = os.open(cg / 'jailer', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    leaf(jailed, 'cgroup.subtree_control', '+cpu +memory +pids')
    os.close(jailed)
    go_read, go_write = os.pipe()
    done_read, done_write = os.pipe()
    ready_read, ready_write = os.pipe()
    deadline = time.monotonic() + (1 if control else RUNTIME_SECONDS)
    origin = Path('/proc/self/cgroup').read_text().strip()
    require(origin.startswith('0::/') and '\n' not in origin, 'unified original cgroup required')
    original_group = os.open('/sys/fs/cgroup' + origin[3:],
                             os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    require(len(list(Path('/proc/self/task').iterdir())) == 1, 'single-thread controller required')
    original_subreaper = child_subreaper() if control else None
    if control: child_subreaper(1)
    guardian = os.fork()
    if guardian == 0:
        os.close(done_write); os.close(go_read); os.close(ready_read)
        watchdog(group, done_read, ready_write, go_write, deadline, out / 'watchdog.json')
    os.close(done_read)
    os.close(ready_write)
    child = None
    pidfd = None
    terminal = None
    descendant_fd = None
    descendant_terminal = None
    guardian_status = None
    result = {'status': 'INCOMPLETE', 'authority': 'NONE', 'qualification': 'NOT_RUN',
              'cgroup': str(cg), 'cgroup_identity': [identity.st_dev, identity.st_ino],
              'diagnostic_pid': child, 'watchdog_pid': guardian}
    try:
        ready, _, _ = select.select([ready_read], [], [], 2)
        require(ready and os.read(ready_read, 1) == b'R', 'independent watchdog not armed')
        os.close(ready_read)
        require(time.monotonic() < deadline, 'watchdog deadline elapsed before spawn')
        pid, code = os.waitpid(guardian, os.WNOHANG)
        if pid:
            guardian_status = code
            raise ValueError('watchdog died before diagnostic spawn')
        # The guardian is already armed outside this tree. Temporarily enter
        # the owner leaf BEFORE fork so the child is kernel-coupled at birth.
        # A stopped controller/child cannot survive outside the deadline tree.
        owner = os.open(cg / 'owner', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        leaf(owner, 'cgroup.procs', str(os.getpid()))
        os.close(owner)
        require(time.monotonic() < deadline, 'deadline elapsed during controller admission')
        pid, code = os.waitpid(guardian, os.WNOHANG)
        if pid:
            guardian_status = code
            raise ValueError('watchdog died during controller admission')
        child = os.fork()
        if child == 0:
            try:
                # No copy of a gate writer may survive in the blocked child.
                for descriptor in os.listdir('/proc/self/fd'):
                    if int(descriptor) > 2 and int(descriptor) not in (go_read, elf):
                        try: os.close(int(descriptor))
                        except OSError: pass
                require(os.read(go_read, 1) == b'G', 'watchdog was not armed')
                os.setsid()
                os.dup2(os.open('/dev/null', os.O_RDONLY), 0)
                for fd, file in [(1, out / 'native.stdout'), (2, out / 'native.stderr')]:
                    os.dup2(os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), fd)
                # Static Rust ELF executes by original held FD, not a replacement jailer.
                for fd in os.listdir('/proc/self/fd'):
                    if int(fd) > 2 and int(fd) != elf:
                        try: os.close(int(fd))
                        except OSError: pass
                if control:
                    # This is a separately reported watchdog challenge, never an
                    # official-jailer substitute. setsid cannot escape the cgroup.
                    os.execve('/usr/bin/python3', ['python3', '-I', '-c',
                        'import os,time,json,signal\n'
                        'if os.fork()==0:\n'
                        ' os.setsid()\n'
                        ' print(json.dumps({"descendant":os.getpid(),"session":os.getsid(0),'
                        '"cgroup":open("/proc/self/cgroup").read()}),flush=True)\n'
                        ' os.kill(os.getpid(),signal.SIGSTOP)\n'
                        'time.sleep(120)\n'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
                os.execve(elf, [str(args.elf), TEST, '--exact', '--ignored', '--nocapture',
                               '--test-threads=1'], {'PATH': NATIVE_EXEC_PATH, 'LC_ALL': 'C',
                               'REALM_EXEC_STOP_INPUTS': str(args.inputs),
                               'REALM_EXEC_STOP_INPUTS_SHA256': args.inputs_sha256})
            except BaseException:
                os._exit(125)
        leaf(original_group, 'cgroup.procs', str(os.getpid()))
        require(Path('/proc/self/cgroup').read_text().strip() == origin,
                'controller did not restore its original cgroup')
        os.close(go_read)
        pidfd = os.pidfd_open(child)
        result['diagnostic_pid'] = child
        membership = Path(f'/proc/{child}/cgroup').read_text()
        require(membership.strip() == '0::/' + name + '/owner',
                'original diagnostic is outside watchdog cgroup')
        save(out / 'armed.json', {**result, 'deadline_monotonic': deadline,
                                 'original_diagnostic_cgroup': membership,
                                 'controller_original_cgroup': origin,
                                 'kernel_cgroup_inherited_at_fork': True,
                                 'observed_watchdog_limits': limits,
                                 'limits': {'memory_bytes': 1073741824, 'pids': 128, 'cpu': '100000 100000'}})
        require(time.monotonic() < deadline, 'deadline elapsed before release')
        os.write(go_write, b'G')
        if control:
            descendant_fd, descendant_observed = observe_control_descendant(child, name, deadline, group)
            save(out / 'control-descendant-before-deadline.json', descendant_observed)
        while time.monotonic() < deadline + CLEANUP_SECONDS + 1:
            if guardian_status is None:
                pid, code = os.waitpid(guardian, os.WNOHANG)
                if pid:
                    guardian_status = code
                    if not control:
                        raise ValueError('watchdog exited before diagnostic retirement')
            terminal = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
            if terminal is not None:
                break
            time.sleep(0.01)
        require(terminal is not None, 'original diagnostic terminal wait UNKNOWN')
        if guardian_status is None:
            try: os.write(done_write, b'C')
            except BrokenPipeError:
                require(control, 'watchdog completion channel lost')
        os.close(done_write)
        # Guardian also has a bounded internal cleanup. Do not block indefinitely.
        end = deadline + CLEANUP_SECONDS + 2
        while guardian_status is None and time.monotonic() < end:
            pid, code = os.waitpid(guardian, os.WNOHANG)
            if pid:
                guardian_status = code; break
            time.sleep(0.01)
        require(guardian_status == 0, 'watchdog retirement UNKNOWN')
        guard = json.loads((out / 'watchdog.json').read_text())
        require(guard['held_cgroup_identity'] == [identity.st_dev, identity.st_ino]
                and guard['watchdog_cgroup'].strip() == origin,
                'watchdog held object or independent cgroup origin differs')
        require(guard['observed_monotonic'] <= guard['deadline_monotonic'] + CLEANUP_SECONDS,
                'watchdog closure exceeded its measured cleanup allowance')
        if control:
            require(guard['reason'] == 'DEADLINE' and guard['forced'] and guard['cgroup_empty'],
                    'independent deadline did not terminate challenge subtree')
            require(terminal.si_code == os.CLD_KILLED and terminal.si_status == signal.SIGKILL,
                    'deadline challenge original pidfd was not SIGKILL-reaped')
            while time.monotonic() < deadline + CLEANUP_SECONDS:
                descendant_terminal = os.waitid(os.P_PIDFD, descendant_fd, os.WEXITED | os.WNOHANG)
                if descendant_terminal is not None: break
                time.sleep(0.002)
            require(descendant_terminal is not None
                    and descendant_terminal.si_pid == descendant_observed['pid']
                    and descendant_terminal.si_code == os.CLD_KILLED
                    and descendant_terminal.si_status == signal.SIGKILL,
                    'original adopted control descendant was not SIGKILL-reaped')
            result['control_tree_reaped_monotonic'] = time.monotonic()
            require(result['control_tree_reaped_monotonic'] <= deadline + CLEANUP_SECONDS,
                    'complete fixed control tree reaping exceeded cleanup allowance')
            result['control_descendant_terminal'] = {
                'pid': descendant_terminal.si_pid, 'code': descendant_terminal.si_code,
                'status': descendant_terminal.si_status, 'reaped': True}
            descendant = json.loads((out / 'native.stdout').read_text())
            require(descendant['descendant'] == descendant_observed['pid'],
                    'stdout descendant differs from independently held kernel child')
            require(descendant['descendant'] == descendant['session']
                    and descendant['descendant'] != child
                    and descendant['cgroup'].strip() == '0::/' + name + '/owner',
                    'setsid descendant challenge was not actually observed')
            save(out / 'deadline-control.json', descendant)
            result['status'] = 'PASS_DEADLINE_CONTROL_ONLY'
            return result
        require(guard['reason'] == 'COMPLETE' and not guard['forced'] and guard['cgroup_empty'],
                'watchdog forced/incomplete cleanup cannot pass native diagnostic')
        named = cg.lstat()
        held = os.fstat(group)
        require(empty(group) and (held.st_dev, held.st_ino) == (identity.st_dev, identity.st_ino)
                and (named.st_dev, named.st_ino) == (identity.st_dev, identity.st_ino),
                'held terminal cgroup differs or remains populated')
        require(terminal.si_code == os.CLD_EXITED and terminal.si_status == 0,
                'original native diagnostic did not normally exit zero')
        # Verify original input bytes again; the Rust observer owns native custody.
        for path, pin, original in [(args.elf, args.elf_sha256, elf_id),
                                    (args.inputs, args.inputs_sha256, manifest_id)]:
            fd, _, current = held_file(path, pin)
            os.close(fd)
            require(current == original, 'original executable/input object replaced')
        report = Path(inputs['backend']['state_dir']) / 'official-exec-stop-probe/official-exec-stop-probe.json'
        report_pin, report_raw, _ = held_file(report, hashlib.sha256(report.read_bytes()).hexdigest())
        os.close(report_pin)
        observed = json.loads(report_raw)
        journal_path = report.parent / 'coding-fence/exec.jsonl'
        journal_pin, journal_raw, _ = held_file(journal_path, hashlib.sha256(journal_path.read_bytes()).hexdigest())
        os.close(journal_pin)
        journal = [json.loads(line) for line in journal_raw.decode().splitlines()]
        registrations = [line.split() for line in Path('/proc/misc').read_text().splitlines()
                         if line.split()[-1:] == ['userfaultfd']]
        require(len(registrations) <= 1 and all(len(row) == 2 for row in registrations),
                'independent host device registration ambiguous')
        minor = int(registrations[0][0]) if registrations else None
        config = inputs['backend']['production_jailer']
        native_report((out / 'native.stdout').read_text(), observed, journal,
                      (config['uid'], config['gid'], minor))
        save(out / 'native-observation.json', observed)
        result['status'] = 'PASS_PRE_VMM_DIAGNOSTIC_ONLY'
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        # Closing this channel makes the independent guardian kill the entire
        # original subtree, including setsid and official jailer descendants.
        try: os.close(done_write)
        except OSError: pass
        try: os.write(go_write, b'A')
        except OSError: pass
        try: os.close(go_write)
        except OSError: pass
        # Also restore on a failed fork. If restoration itself fails, the
        # outside guardian still owns the subtree deadline and cannot pass it.
        try: leaf(original_group, 'cgroup.procs', str(os.getpid()))
        except BaseException as error:
            result['controller_restore_error'] = repr(error)
            result['status'] = 'INCOMPLETE'
        try:
            populated = not empty(group)
        except BaseException as error:
            populated = True
            result['cleanup_read_error'] = repr(error)
        if populated:
            result['parent_forced_cleanup'] = True
            result['status'] = 'INCOMPLETE'
            try: leaf(group, 'cgroup.kill', '1')
            except BaseException as error: result['cleanup_kill_error'] = repr(error)
        # Failure never leaves cleanup as an assertion. Observe the whole held
        # subtree and original pidfd; inability to do so remains INCOMPLETE.
        cleanup_end = time.monotonic() + CLEANUP_SECONDS + 1
        group_empty = False
        while time.monotonic() < cleanup_end:
            if terminal is None and pidfd is not None:
                try: terminal = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
                except ChildProcessError: break
            if terminal is None and child is not None and pidfd is None \
                    and not result.get('owned_child_waitpid_fallback'):
                pid, code = os.waitpid(child, os.WNOHANG)
                if pid:
                    result['owned_child_waitpid_fallback'] = {'pid': pid, 'raw_status': code}
            if descendant_fd is not None and descendant_terminal is None:
                try: descendant_terminal = os.waitid(os.P_PIDFD, descendant_fd, os.WEXITED | os.WNOHANG)
                except ChildProcessError: pass
            if guardian_status is None:
                pid, code = os.waitpid(guardian, os.WNOHANG)
                if pid: guardian_status = code
            try: group_empty = empty(group)
            except BaseException: group_empty = False
            if (terminal is not None or child is None or result.get('owned_child_waitpid_fallback')) \
                    and guardian_status is not None and group_empty \
                    and (not control or descendant_terminal is not None):
                break
            time.sleep(0.01)
        result['cleanup_observed'] = {
            'original_diagnostic_reaped_or_not_spawned': terminal is not None or child is None
                or bool(result.get('owned_child_waitpid_fallback')),
            'watchdog_reaped': guardian_status is not None,
            'held_cgroup_empty': group_empty,
            'known_control_descendant_reaped': not control or descendant_terminal is not None}
        if not all(result['cleanup_observed'].values()):
            result['status'] = 'INCOMPLETE'
        result['terminal'] = None if terminal is None else {
            'pid': terminal.si_pid, 'code': terminal.si_code, 'status': terminal.si_status}
        if original_subreaper is not None:
            try: child_subreaper(original_subreaper)
            except BaseException as error:
                result['subreaper_restore_error'] = repr(error)
                result['status'] = 'INCOMPLETE'
        save(out / 'RESULT.json', result)
        for fd in [pidfd, descendant_fd, manifest, elf, group, original_group]:
            if fd is not None: os.close(fd)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['elf', 'elf-sha256', 'inputs', 'inputs-sha256', 'run-id', 'output']:
        parser.add_argument('--' + name, required=name in ['run-id', 'output'])
    parser.add_argument('--deadline-control', action='store_true',
                        help='only challenge this watchdog; never invoke the official diagnostic')
    args = parser.parse_args()
    if not args.deadline_control and not all((args.elf, args.elf_sha256, args.inputs, args.inputs_sha256)):
        parser.error('official execution requires exact executable and input paths and pins')
    result = run(args)
    require(result['status'] == ('PASS_DEADLINE_CONTROL_ONLY' if args.deadline_control
                                else 'PASS_PRE_VMM_DIAGNOSTIC_ONLY'),
            'terminal cleanup refused; see retained RESULT.json')
