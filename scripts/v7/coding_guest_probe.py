#!/usr/bin/env python3
"""Official-jailer DEVELOPMENT coding guest. Never a REALM producer/issuer.

Requires external input/binary pins and an exact probe approval. Refuses a
direct/root VMM fallback. New private jail/cgroup only; existing C0 is untouched.
Raw observations are not typed measured-launch or complete-effect authority.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import stat
import signal
import select
import socket
import struct
import subprocess
import time
import host_planned_coding as planner


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while data := f.read(1024 * 1024):
            h.update(data)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def save(path, value):
    with path.open('xb') as f:
        os.chmod(path, 0o600)
        f.write(canonical(value))
        f.flush()
        os.fsync(f.fileno())


def remaining_timeout(stream, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('absolute handoff deadline exceeded; outcome UNKNOWN')
    stream.settimeout(remaining)


def exact(stream, count, deadline=None):
    chunks = []
    while count:
        if deadline is not None:
            remaining_timeout(stream, deadline)
        part = stream.recv(min(count, 65536))
        if not part:
            raise ValueError('short transport frame')
        count -= len(part)
        chunks.append(part)
    return b''.join(chunks)


def receive_raw_handoff(connection, root, challenge, acknowledged=True, deadline=None):
    deadline = time.monotonic() + 30 if deadline is None else deadline
    length = struct.unpack('!I', exact(connection, 4, deadline))[0]
    if not 0 < length <= 4096:
        raise ValueError('raw header limit')
    header = planner.worker.parse(exact(connection, length, deadline))
    if (type(header) is not dict or set(header) !=
        {'schema', 'authority', 'realm_artifact', 'challenge', 'size', 'sha256'} or
        header['schema'] != ('realm.coding-guest-development-raw.v2' if acknowledged else 'realm.coding-guest-development-raw.v1')):
        raise ValueError('unsupported raw header')
    if (header['authority'], header['realm_artifact'], header['challenge']) != ('NONE', None, challenge):
        raise ValueError('guest raw identity differs')
    if type(header['size']) is not int or not 0 < header['size'] <= 64 * 1024**2:
        raise ValueError('raw payload limit')
    data = exact(connection, header['size'], deadline)
    if hashlib.sha256(data).hexdigest() != header['sha256']:
        raise ValueError('raw payload hash differs')
    with (root / 'guest-raw.tar.gz').open('xb') as output:
        os.chmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    save(root / 'raw-header.json', header)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    # Persist before replying; a lost reply stays UNKNOWN at the sender.
    if acknowledged:
        remaining_timeout(connection, deadline)
        planner.send(connection, {'schema': 'realm.coding-raw-received.v1', 'authority': 'NONE',
                 'challenge': challenge, 'sha256': header['sha256'], 'size': header['size']})
    return header


def request_clean_retirement(api_path, root, pid, pidfd):
    if pidfd_exited(pidfd):
        raise ValueError('VMM exited before retirement request; no clean protocol witness')
    response = api(api_path, 'PUT', '/actions', {'action_type': 'SendCtrlAltDel'})
    save(root / 'retirement-request.json', {'authority': 'NONE', 'pid': pid,
         'action': 'SendCtrlAltDel', 'response': response, 'monotonic_ns': time.monotonic_ns()})
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    poller.poll(10000)
    if not pidfd_exited(pidfd):
        raise ValueError('VMM did not retire after acknowledged raw handoff; forced cleanup cannot qualify')
    # Actual exit status and cgroup are checked after exact reaping in finally.


def enable_child_subreaper():
    # Same parent-ownership pattern as the V6 supervisor; only this process's
    # descendants are adopted. This does not mint its typed launch capability.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'cannot establish child subreaper')


def pidfd_exited(fd):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    events = poller.poll(0)
    if any(mask & ~(select.POLLIN | select.POLLHUP) for _, mask in events):
        raise ValueError('unexpected pidfd poll state')
    return bool(events)


def process_observation(pid, fd):
    # A cgroup membership read is not proof of process death. This fd retains
    # the exact observed incarnation; textual /proc fields are diagnostics only.
    result = {'pid': pid, 'pidfd_exited': pidfd_exited(fd), 'authority': 'NONE',
              'proc': {}, 'observation_errors': []}
    for name in ('stat', 'status', 'cgroup'):
        try:
            result['proc'][name] = (pathlib.Path('/proc') / str(pid) / name).read_text()
        except OSError as error:
            result['observation_errors'].append(name + ': ' + type(error).__name__)
    return result


def cleanup_owned_process(root, pid, pidfd, cg, child, result):
    # Diagnostic ENOSPC/I/O failures must not suppress exact owned cleanup.
    # Every failure stays visible; this function cannot issue closure authority.
    def attempt(name, operation):
        try:
            return operation()
        except Exception as error:
            result.setdefault('cleanup_errors', []).append(name + ': ' + type(error).__name__ + ': ' + str(error))
            return None
    result['cleanup_begin_monotonic_ns'] = time.monotonic_ns()
    if pidfd is not None:
        attempt('precleanup observation', lambda: save(root / 'precleanup-process.json', process_observation(pid, pidfd)))
        def kill_exact():
            intent = {'authority': 'NONE', 'pid': pid, 'signal': int(signal.SIGKILL),
                      'monotonic_ns': time.monotonic_ns(), 'cause': 'owned controller cleanup'}
            attempt('kill intent custody', lambda: save(root / 'kill-intent.json', intent))
            result['kill_intent'] = intent
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                result['kill_syscall_result'] = 'SENT'
            except ProcessLookupError:
                result['kill_syscall_result'] = 'ALREADY_EXITED'
            result['kill_syscall_return_monotonic_ns'] = time.monotonic_ns()
        already_exited = attempt('owned precleanup exit observation', lambda: pidfd_exited(pidfd))
        if already_exited is not True:
            result['forced_vmm_cleanup'] = True
            attempt('owned pidfd termination', kill_exact)
        else:
            result['forced_vmm_cleanup'] = False
    if cg is not None and cg.exists():
        def observe_group_before_cleanup():
            members = (cg / 'cgroup.procs').read_text().split()
            empty = not members
            attempt('prekill group custody', lambda: save(root / 'precleanup-cgroup.json',
                {'authority': 'NONE', 'members': members, 'empty': empty,
                 'monotonic_ns': time.monotonic_ns()}))
            return empty
        result['precleanup_cgroup_empty'] = attempt('prekill group observation', observe_group_before_cleanup)
        result['forced_cgroup_cleanup'] = result['precleanup_cgroup_empty'] is not True
        if result['forced_cgroup_cleanup']:
            attempt('owned cgroup termination', lambda: (cg / 'cgroup.kill').write_text('1'))
        def wait_group():
            end = time.monotonic() + 10
            while (cg / 'cgroup.procs').read_text().strip() and time.monotonic() < end:
                time.sleep(0.1)
            return not (cg / 'cgroup.procs').read_text().strip()
        result['cgroup_empty'] = attempt('owned cgroup empty observation', wait_group)
    if pidfd is not None:
        def wait_exact():
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)
            poller.poll(10000)
            return pidfd_exited(pidfd)
        result['owned_vmm_exited'] = attempt('owned pidfd exit observation', wait_exact)
        if result['owned_vmm_exited'] is True:
            def reap_exact():
                reaped, status = os.waitpid(pid, os.WNOHANG)
                if reaped != pid:
                    raise ChildProcessError('exact adopted VMM wait unavailable')
                return {'pid': reaped, 'raw_status': status,
                        'exit_code': os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
                        'signal': os.WTERMSIG(status) if os.WIFSIGNALED(status) else None}
            result['owned_vmm_wait'] = attempt('owned child wait', reap_exact) or {'status': 'UNKNOWN'}
        attempt('owned pidfd close', lambda: os.close(pidfd))
    if child is not None:
        def wait_jailer():
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
                result['jailer_forced_cleanup'] = True
            return child.returncode
        result['jailer_exit'] = attempt('owned jailer wait', wait_jailer)
    result['cleanup_end_monotonic_ns'] = time.monotonic_ns()


def vmm_zero_exit_observed(result):
    observed = result.get('owned_vmm_wait', {})
    return (type(observed) is dict and type(observed.get('raw_status')) is int and
            observed['raw_status'] == 0 and type(observed.get('exit_code')) is int and
            observed['exit_code'] == 0 and 'signal' in observed and observed['signal'] is None and
            result.get('owned_vmm_exited') is True)


def clean_retirement_observed(result, native_expected):
    # Diagnostic classification only; this does not issue a native capability.
    if not vmm_zero_exit_observed(result):
        return False
    if any(name in result for name in ('failure', 'cleanup_errors', 'planner_cleanup_failure',
            'native_cleanup_failure', 'resource_observation_errors')):
        return False
    if not all(result.get(name) is True for name in ('raw_ack_sent', 'precleanup_cgroup_empty',
            'cgroup_empty', 'source_rootfs_unchanged', 'protected_rootfs_unchanged')):
        return False
    if not all(result.get(name) is False for name in ('forced_vmm_cleanup', 'forced_cgroup_cleanup')):
        return False
    if type(result.get('jailer_exit')) is not int or result['jailer_exit'] != 0:
        return False
    if 'model_disk_unchanged' in result and result['model_disk_unchanged'] is not True:
        return False
    if native_expected:
        children = result.get('native_owned_processes')
        if type(children) is not list or len(children) != 2 or any(type(row) is not dict for row in children):
            return False
        if (any(type(row.get('role')) is not str for row in children) or
                {row['role'] for row in children} != {'broker', 'custodian'}):
            return False
        if any(type(row.get('exit')) is not int or row['exit'] != 0 or
                row.get('forced_owned_cleanup') is not False for row in children):
            return False
    return True


def resource_observation(cg, phase):
    # Diagnostic snapshots only. A missing/global counter cannot prove a kill
    # cause or mint containment/closure authority.
    result = {'authority': 'NONE', 'phase': phase, 'wall_time': time.time(),
              'monotonic_time': time.monotonic(), 'files': {}}
    paths = ['/proc/sys/kernel/random/boot_id', '/proc/self/cgroup',
             '/proc/pressure/memory', '/proc/pressure/io',
             '/sys/fs/cgroup/memory.events', '/sys/fs/cgroup/memory.current',
             '/sys/fs/cgroup/memory.peak', '/sys/fs/cgroup/memory.max']
    paths += [str(cg / name) for name in
              ('memory.events', 'memory.current', 'memory.peak', 'pids.events')]
    for name in paths:
        try:
            with open(name) as stream:
                data = stream.read(8193)
            if len(data) > 8192:
                raise ValueError('bounded resource observation exceeded')
            result['files'][name] = data
        except (OSError, ValueError) as error:
            result['files'][name] = type(error).__name__
    for name, selected in (('/proc/vmstat', ('oom_kill',)),
                           ('/proc/meminfo', ('MemTotal:', 'MemAvailable:', 'SwapFree:'))):
        try:
            with open(name) as stream:
                result[name] = [row.strip() for row in stream if row.split()[0] in selected]
        except OSError as error:
            result[name] = type(error).__name__
    return result


def api(path, method, route, body=None):
    data = b'' if body is None else canonical(body)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(str(path))
        s.sendall((f'{method} {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'
                   f'Content-Length: {len(data)}\r\n\r\n').encode() + data)
        raw = bytearray()
        while b'\r\n\r\n' not in raw:
            part = s.recv(4096)
            if not part:
                raise ValueError('short API response headers')
            raw.extend(part)
            if len(raw) > 16384:
                raise ValueError('API header limit')
        head, data = bytes(raw).split(b'\r\n\r\n', 1)
        lines = head.split(b'\r\n')
        status = lines[0].split(b' ')[1]
        headers = {}
        for line in lines[1:]:
            key, value = line.split(b':', 1)
            key = key.strip().lower()
            if key in headers:
                raise ValueError('duplicate API header')
            headers[key] = value.strip()
        if b'transfer-encoding' in headers:
            raise ValueError('unsupported API framing')
        if b'content-length' not in headers and status != b'204':
            raise ValueError('API body lacks length')
        length = int(headers.get(b'content-length', b'0'))
        if not 0 <= length <= 1024 * 1024 or len(data) > length:
            raise ValueError('API body limit/framing differs')
        data += exact(s, length - len(data))
        if status not in (b'200', b'204'):
            raise ValueError('Firecracker API refused: ' + data.decode(errors='replace'))
    return json.loads(data) if data else None


def profile(args):
    ephemeral = getattr(args, 'ephemeral_run_root', False)
    prefix = '/tmp' if ephemeral else '/var/lib'
    if not re.fullmatch(prefix + r'/realm-v7-coding-development-[0-9]{3}', str(args.root)):
        raise ValueError('fresh restricted task-owned root required')
    if ephemeral:
        parent = args.root.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or
            not parent.st_mode & stat.S_ISVTX or args.root.parent.is_symlink() or
            args.link_protected_input or args.protected_rootfs):
            raise ValueError('ephemeral root requires root-owned sticky parent and fresh copied input')
    if args.root.exists():
        raise ValueError('probe root already exists')
    # Refuse bad launch paths/credentials before hashing multi-gigabyte inputs.
    for name in ('firecracker', 'jailer', 'kernel'):
        path = getattr(args, name)
        info = path.stat()
        if path.is_symlink() or not path.is_file() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unprotected launch binary/kernel')
        if sha(path) != getattr(args, name + '_sha256'):
            raise ValueError('external launch input pin differs')
    native_pins = {}
    for name in ('native_broker', 'native_custodian'):
        path = getattr(args, name, None)
        if path is not None:
            for parent in [path, *path.parents]:
                info = parent.lstat()
                if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('unprotected native binary/parent')
            if not path.is_file() or sha(path) != getattr(args, name + '_sha256'):
                raise ValueError('external native binary pin differs')
            native_pins[name] = sha(path)
    account = pwd.getpwnam(args.vmm_user)
    if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_shell != '/usr/sbin/nologin':
        raise ValueError('existing dedicated non-login VMM identity required')
    if sha(args.inputs / 'guest-inputs.json') != args.inputs_sha256:
        raise ValueError('external guest inputs pin differs')
    inputs = json.loads((args.inputs / 'guest-inputs.json').read_text())
    if inputs.get('raw_handoff_protocol') not in (None, 'durable-ack-cad-v1'):
        raise ValueError('unsupported raw handoff protocol')
    if (type(inputs['memory_mib']) is not int or inputs['memory_mib'] not in ((512, 768, 1024) if inputs.get('execution_mode') == 'host-planned' else (5120, 5632, 6144))
        or type(inputs['vcpu_count']) is not int
        or (inputs['authority'], inputs['qualification'], inputs['architecture'],
            inputs['vcpu_count'], inputs['network_interfaces']) != ('NONE', 'NOT_QUALIFIED', 'x86_64', 2, [])):
        raise ValueError('unsupported development guest')
    if inputs.get('execution_mode') == 'host-planned' and ('model_disk' in inputs or inputs.get('model_name') is not None):
        raise ValueError('host-planned guest cannot attach model inputs')
    image = args.inputs / 'rootfs.ext4'
    reuse = None
    if args.link_protected_input and args.protected_rootfs:
        raise ValueError('choose one protected input materialization')
    if args.link_protected_input:
        if not re.fullmatch(r'/var/lib/realm-v7-coding-inputs-[0-9]{3}/rootfs.ext4', str(image)):
            raise ValueError('unsupported prepared protected input path')
        for path in [image, *image.parents]:
            info = path.lstat()
            if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('unprotected prepared input/parent')
        info = image.stat()
        if not image.is_file() or info.st_mode & 0o777 != 0o444:
            raise ValueError('prepared protected input must be read-only')
        reuse = {'path': str(image), 'device': info.st_dev, 'inode': info.st_ino,
                 'scope': 'protected prepared input materialization only; no VM snapshot or authority reuse'}
    if args.protected_rootfs:
        image = args.protected_rootfs
        match = re.fullmatch(r'(/var/lib/realm-v7-coding-development-[0-9]{3})/jails/firecracker/probe/root/rootfs.ext4', str(image))
        if not match:
            raise ValueError('unsupported protected development input')
        old = pathlib.Path(match.group(1))
        closed = json.loads((old / 'probe-result.json').read_text())
        if (closed['authority'] != 'NONE' or not closed['cgroup_empty']
            or not closed['protected_rootfs_unchanged']
            or (pathlib.Path('/sys/fs/cgroup') / old.name / 'probe/cgroup.procs').read_text().strip()):
            raise ValueError('protected input predecessor is not closed')
        for path in [image, *image.parents]:
            info = path.lstat()
            if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('unprotected predecessor input/parent')
        info = image.stat()
        if not image.is_file() or info.st_mode & 0o777 != 0o444:
            raise ValueError('protected input is not read-only')
        reuse = {'path': str(image), 'device': info.st_dev, 'inode': info.st_ino,
                 'scope': 'root-protected immutable input alias only; no VM snapshot or authority reuse'}
    if sha(image) != inputs['rootfs_sha256']:
        raise ValueError('built/protected guest image differs')
    model_disk = None
    if 'model_disk' in inputs:
        disk = inputs['model_disk']
        if type(disk) is not dict or set(disk) != {'image_path', 'sha256', 'bytes', 'manifest_sha256', 'model_sha256', 'scope'}:
            raise ValueError('unsupported additional model input fields')
        image_path = pathlib.Path(disk['image_path'])
        if not re.fullmatch(r'/var/lib/realm-v7-coding-inputs-[0-9]{3}/rootfs.ext4', str(image_path)):
            raise ValueError('protected model input path required')
        for path in [image_path, *image_path.parents]:
            info = path.lstat()
            if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('unprotected model input/parent')
        info = image_path.stat()
        if (not image_path.is_file() or info.st_mode & 0o777 != 0o444
            or type(disk['bytes']) is not int or disk['bytes'] != info.st_size
            or sha(image_path.parent / 'guest-inputs.json') != disk['manifest_sha256']
            or sha(image_path) != disk['sha256']):
            raise ValueError('protected model input bytes/mode/manifest differ')
        model_disk = {**disk, 'device': info.st_dev, 'inode': info.st_ino}
    source_names = ['host_planned_coding.py', 'coding_worker.py', 'coding_guest_boot.py']
    native_binding = inputs.get('native_submission_binding')
    if (native_binding is not None) != (set(native_pins) == {'native_broker', 'native_custodian'}):
        raise ValueError('native inputs require both externally pinned native binaries')
    if native_pins and native_binding is None:
        raise ValueError('native binaries require explicit native inputs')
    if native_binding is not None:
        source_names += ['coding_native_client.py', 'candidate_channel_guard.py']
    launch = planner.launch_document(inputs['challenge'],
        {name: inputs['files']['controller/' + name]['sha256'] for name in source_names},
        native_binding) if inputs.get('execution_mode') == 'host-planned' else None
    return {'schema': 'realm.coding-jailer-development-probe.v1', 'authority': 'NONE',
        'realm_artifact': None, 'qualification': 'NOT_QUALIFIED', 'root': str(args.root),
        'ephemeral_run_root': ephemeral,
        'raw_handoff_protocol': inputs.get('raw_handoff_protocol'),
        'inputs_sha256': args.inputs_sha256, 'rootfs_sha256': inputs['rootfs_sha256'],
        'rootfs_bytes': inputs['rootfs_bytes'], 'challenge': inputs['challenge'],
        'boot_args': inputs['boot_args'] + (' devtmpfs.mount=0' if args.init_mounts_devtmpfs else ''),
        'devtmpfs_mount_owner': 'coding-init' if args.init_mounts_devtmpfs else 'kernel-default',
        'memory_mib': inputs['memory_mib'], 'vcpu_count': 2,
        'memory_max_bytes': (inputs['memory_mib'] + 1024) * 1024**2, 'pids_max': 32,
        'network_interfaces': [], 'vmm_uid': account.pw_uid, 'vmm_gid': account.pw_gid,
        'launch_input_bytes': {n: getattr(args, n).stat().st_size for n in ('firecracker', 'jailer', 'kernel')},
        'launch_pins': {n: getattr(args, n + '_sha256') for n in ('firecracker', 'jailer', 'kernel')},
        'timeout_seconds': 1800 if inputs.get('execution_mode') == 'host-planned' else 3600,
        'execution_mode': inputs.get('execution_mode', 'offline-model'),
        'planner_run_id': hashlib.sha256(planner.worker.encoded(launch)).hexdigest() if launch else None,
        'native_submission_binding': native_binding, 'native_binary_pins': native_pins,
        'native_host_adapter_sha256': sha(pathlib.Path(__file__).with_name('coding_native_probe.py')) if native_binding else None,
        'planner_source_pins': {'worker': inputs['files']['controller/coding_worker.py']['sha256'],
            'protocol': inputs['files']['controller/host_planned_coding.py']['sha256']} if inputs.get('execution_mode') == 'host-planned' else None, 'protected_input_alias': reuse, 'model_disk': model_disk,
        'vmm_exit_tracking': 'direct adopted child plus retained pidfd',
        'vmm_log': {'path': '/run/vmm.log', 'level': 'Info', 'max_bytes': 32 * 1024**2},
        'driver_sha256': sha(pathlib.Path(__file__))}


def run(args, spec):
    if os.geteuid() != 0 or os.uname().machine != 'x86_64':
        raise ValueError('root Linux x86_64 required for official jailer; no fallback')
    # Conservative preflight margin, not a filesystem quota or hard output cap.
    copied_inputs = sum(spec['launch_input_bytes'].values())
    if not spec['protected_input_alias']:
        copied_inputs += spec['rootfs_bytes']
    required_free = copied_inputs + 1024**3
    if shutil.disk_usage(args.root.parent).free < required_free:
        raise ValueError('insufficient free space for protected guest copy')
    root = args.root
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    save(root / 'profile.json', spec)
    f = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    try:
        if fcntl.ioctl(f, 0xAE00) != 12:
            raise ValueError('KVM API differs')
    finally:
        os.close(f)
    uid, gid = spec['vmm_uid'], spec['vmm_gid']
    jail_base = root / 'jails'
    jail = jail_base / 'firecracker/probe/root'
    jail.mkdir(parents=True, mode=0o755)
    run_dir = jail / 'run'
    run_dir.mkdir(mode=0o700)
    os.chown(run_dir, uid, gid)
    for name, source in [('rootfs.ext4', args.inputs / 'rootfs.ext4'), ('kernel', args.kernel)]:
        if name == 'rootfs.ext4' and spec['protected_input_alias']:
            alias = spec['protected_input_alias']
            source = pathlib.Path(alias['path'])
            info = source.stat()
            if (info.st_dev, info.st_ino) != (alias['device'], alias['inode']):
                raise ValueError('protected input identity changed')
            os.link(source, jail / name, follow_symlinks=False)
            linked = (jail / name).stat()
            if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('protected input alias differs')
        else:
            shutil.copyfile(source, jail / name)
            (jail / name).chmod(0o444)
    if spec['model_disk']:
        model_disk = spec['model_disk']
        source = pathlib.Path(model_disk['image_path'])
        info = source.stat()
        if (info.st_dev, info.st_ino) != (model_disk['device'], model_disk['inode']):
            raise ValueError('protected model disk identity changed')
        os.link(source, jail / 'model-inputs.ext4', follow_symlinks=False)
        linked = (jail / 'model-inputs.ext4').stat()
        if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('protected model disk alias differs')
    if sha(jail / 'rootfs.ext4') != spec['rootfs_sha256']:
        raise ValueError('protected materialization differs')
    cg_parent = pathlib.Path('/sys/fs/cgroup') / root.name
    if not {'cpu', 'memory', 'pids'} <= set((cg_parent.parent / 'cgroup.subtree_control').read_text().split()):
        raise ValueError('existing host cgroup controllers unavailable; no global changes')
    cg_parent.mkdir()
    (cg_parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    cg = cg_parent / 'probe'
    endpoint = run_dir / 'vsock_9000'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    os.chown(endpoint, uid, gid)
    endpoint.chmod(0o600)
    log_path = run_dir / 'vmm.log'
    log_path.touch(mode=0o600, exist_ok=False)
    os.chown(log_path, uid, gid)
    listener.listen(1)
    listener.settimeout(1)
    proxy = planner.PlannerProxy(root, run_dir, uid, gid) if spec['execution_mode'] == 'host-planned' else None
    native = None
    if spec['native_submission_binding'] is not None:
        from coding_native_probe import NativeProbe
        native = NativeProbe(root, run_dir, spec, {name: getattr(args, name) for name in spec['native_binary_pins']})
    command = [str(args.jailer), '--id', 'probe', '--exec-file', str(args.firecracker),
        '--uid', str(uid), '--gid', str(gid), '--chroot-base-dir', str(jail_base),
        '--cgroup-version', '2', '--parent-cgroup', cg_parent.name,
        '--cgroup', 'memory.max=' + str(spec['memory_max_bytes']),
        '--cgroup', 'cpu.max=200000 100000', '--cgroup', 'pids.max=32', '--new-pid-ns',
        '--', '--api-sock', '/run/api.sock', '--log-path', '/run/vmm.log',
        '--level', 'Info', '--show-level', '--show-log-origin']
    save(root / 'jailer-command.json', command)
    pid = None
    pidfd = None
    result = {'authority': 'NONE', 'realm_artifact': None, 'qualification': 'NOT_QUALIFIED',
              'status': 'NOT_COMPLETE', 'payload_received': False}
    enable_child_subreaper()
    with (root / 'serial.log').open('xb') as serial, (root / 'jailer.stderr').open('xb') as stderr, \
         (root / 'resources.jsonl').open('xb') as resources:
        os.chmod(root / 'resources.jsonl', 0o600)
        def capture_resources(phase):
            try:
                data = canonical(resource_observation(cg, phase)) + b'\n'
                if resources.tell() + len(data) > 4 * 1024**2:
                    raise ValueError('resource timeline limit')
                resources.write(data)
                resources.flush()
                os.fsync(resources.fileno())
            except Exception as error:
                result.setdefault('resource_observation_errors', []).append(phase + ': ' + type(error).__name__)
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=serial, stderr=stderr,
                                 close_fds=True, start_new_session=True)
        try:
            capture_resources('JAILER_STARTED')
            deadline = time.monotonic() + 20
            while True:
                procs = (cg / 'cgroup.procs').read_text().split() if cg.exists() else []
                if len(procs) == 1 and (run_dir / 'api.sock').exists():
                    pid = int(procs[0])
                    break
                if time.monotonic() > deadline:
                    raise ValueError('official jailer readiness timeout')
                time.sleep(0.1)
            proc = pathlib.Path('/proc') / str(pid)
            actual_root, expected_root = (proc / 'root').stat(), jail.stat()
            if ((actual_root.st_dev, actual_root.st_ino) != (expected_root.st_dev, expected_root.st_ino)
                or (proc / 'exe').stat().st_uid != uid or sha(proc / 'exe') != args.firecracker_sha256):
                raise ValueError('VMM jail/incarnation differs')
            status = (proc / 'status').read_text()
            save(root / 'preconfiguration-status.json', {'pid': pid, 'status': status, 'authority': 'NONE'})
            if 'CapEff:\t0000000000000000' not in status:
                raise ValueError('VMM prestart capability observation differs')
            pidfd = os.pidfd_open(pid)
            child.wait(timeout=5)
            fields = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            if int(fields['PPid'].strip()) != os.getpid() or child.returncode != 0:
                raise ValueError('official jailer VMM not directly adopted; refuse exit inference')
            save(root / 'adopted-parent.json', {'pid': pid, 'parent_pid': os.getpid(),
                 'status': (proc / 'status').read_text(), 'authority': 'NONE'})
            os.chown(jail, 0, 0)
            jail.chmod(0o555)
            os.chown(jail / 'firecracker', 0, 0)
            (jail / 'firecracker').chmod(0o555)
            api_path = run_dir / 'api.sock'
            api(api_path, 'PUT', '/boot-source', {'kernel_image_path': '/kernel', 'boot_args': spec['boot_args']})
            api(api_path, 'PUT', '/drives/rootfs', {'drive_id': 'rootfs', 'path_on_host': '/rootfs.ext4',
                'is_root_device': True, 'is_read_only': True, 'io_engine': 'Sync'})
            if spec['model_disk']:
                api(api_path, 'PUT', '/drives/zz_model_inputs', {'drive_id': 'zz_model_inputs',
                    'path_on_host': '/model-inputs.ext4', 'is_root_device': False,
                    'is_read_only': True, 'io_engine': 'Sync'})
            api(api_path, 'PUT', '/machine-config', {'vcpu_count': 2, 'mem_size_mib': spec['memory_mib'], 'smt': False})
            api(api_path, 'PUT', '/vsock', {'vsock_id': 'coding-development', 'guest_cid': 7477, 'uds_path': '/run/vsock'})
            save(root / 'prestart-observations.json', {'pid': pid, 'stat': (proc / 'stat').read_text(),
                'status': status, 'cgroup': (proc / 'cgroup').read_text(),
                'namespaces': {p.name: os.readlink(p) for p in (proc / 'ns').iterdir()},
                'config': api(api_path, 'GET', '/vm/config'), 'version': api(api_path, 'GET', '/version'),
                'vmm_sha256': sha(proc / 'exe'), 'authority': 'NONE'})
            api(api_path, 'PUT', '/actions', {'action_type': 'InstanceStart'})
            # Match the V6 launch order: Firecracker installs the VMM thread
            # filter during InstanceStart. Require it before receiving any raw
            # guest data; never use --no-seccomp or a direct VMM fallback.
            threads = {p.name: (p / 'status').read_text() for p in (proc / 'task').iterdir()}
            save(root / 'running-status.json', {'pid': pid, 'threads': threads, 'authority': 'NONE'})
            for observed in threads.values():
                fields = dict(line.split(':', 1) for line in observed.splitlines() if ':' in line)
                if (fields['Seccomp'].strip() != '2' or int(fields['Seccomp_filters'].strip()) < 1
                    or fields['CapEff'].strip() != '0000000000000000'
                    or int(fields['Uid'].split()[1]) != uid or int(fields['Gid'].split()[1]) != gid):
                    raise ValueError('running VMM thread filter/capability/credentials differ')
            deadline = time.monotonic() + spec['timeout_seconds']
            last_resource = 0
            while True:
                if time.monotonic() - last_resource >= 5:
                    capture_resources('RUNNING')
                    last_resource = time.monotonic()
                if log_path.stat().st_size > spec['vmm_log']['max_bytes']:
                    raise ValueError('VMM log output limit')
                if (root / 'serial.log').stat().st_size > 32 * 1024**2:
                    raise ValueError('serial output limit')
                if pidfd_exited(pidfd):
                    save(root / 'unexpected-process-exit.json', process_observation(pid, pidfd))
                    raise ValueError('owned VMM exited before raw transport')
                members = (cg / 'cgroup.procs').read_text().split()
                if str(pid) not in members:
                    observation = process_observation(pid, pidfd)
                    observation['cgroup_members'] = members
                    save(root / 'unverified-cgroup-membership.json', observation)
                    raise ValueError('owned VMM cgroup membership unverified; process death not inferred')
                if time.monotonic() > deadline:
                    raise ValueError('guest task timeout')
                if proxy:
                    surfaces = [listener, proxy.guest_listener, proxy.local]
                    if native and native.listener:
                        surfaces.append(native.listener)
                    ready, _, _ = select.select(surfaces, [], [], 1)
                    if native and native.listener in ready:
                        native.accept(pid, pidfd)
                    if proxy.guest_listener in ready:
                        proxy.accept_guest(pid, spec, spec['planner_source_pins'])
                    if proxy.local in ready:
                        proxy.serve_local()
                    if listener not in ready:
                        continue
                try:
                    connection, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            with connection:
                connection.settimeout(30)
                peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if peer != (pid, uid, gid):
                    raise ValueError('raw handoff peer differs from owned VMM')
                acknowledged = spec['raw_handoff_protocol'] == 'durable-ack-cad-v1'
                receive_raw_handoff(connection, root, spec['challenge'], acknowledged,
                                    min(deadline, time.monotonic() + 30))
            result.update(payload_received=True, raw_ack_sent=acknowledged)
            if acknowledged:
                request_clean_retirement(api_path, root, pid, pidfd)
            result.update(status='DEVELOPMENT_RAW_RECEIVED', payload_received=True)
        except Exception as exc:
            capture_resources('FAILURE_BEFORE_OWNED_CLEANUP')
            result['failure'] = type(exc).__name__ + ': ' + str(exc)
            raise
        finally:
            if proxy:
                try:
                    proxy.close()
                except BaseException as proxy_error:
                    result['planner_cleanup_failure'] = type(proxy_error).__name__ + ': ' + str(proxy_error)
            listener.close()
            capture_resources('NORMAL_OR_FAILED_BEFORE_OWNED_CLEANUP')
            cleanup_owned_process(root, pid, pidfd, cg, child, result)
            if native:
                try:
                    result['native_owned_processes'] = native.close_after_vmm_cleanup()
                except Exception as error:
                    result['native_cleanup_failure'] = type(error).__name__ + ': ' + str(error)
            capture_resources('AFTER_OWNED_CLEANUP')
            result['vmm_log_sha256'] = sha(log_path)
            result['vmm_log_bytes'] = log_path.stat().st_size
            if cg.exists():
                save(root / 'terminal-cgroup.json', {name: (cg / name).read_text()
                     for name in ('memory.events', 'pids.events', 'cpu.stat', 'cgroup.procs')})
            result['source_rootfs_unchanged'] = sha(args.inputs / 'rootfs.ext4') == spec['rootfs_sha256']
            result['protected_rootfs_unchanged'] = sha(jail / 'rootfs.ext4') == spec['rootfs_sha256']
            if spec['model_disk']:
                result['model_disk_unchanged'] = sha(jail / 'model-inputs.ext4') == spec['model_disk']['sha256']
            result['vmm_zero_exit_observed'] = vmm_zero_exit_observed(result)
            result['clean_retirement_observed'] = clean_retirement_observed(result, native is not None)
            if result['clean_retirement_observed']:
                result['status'] = 'DEVELOPMENT_RAW_RECEIVED_CLEAN_EXIT'
            elif result.get('raw_ack_sent'):
                result['status'] = 'DEVELOPMENT_CLOSURE_REFUSED'
            save(root / 'probe-result.json', result)
    print(json.dumps(result))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['draft', 'run'])
    p.add_argument('--root', required=True, type=pathlib.Path)
    p.add_argument('--inputs', required=True, type=pathlib.Path)
    p.add_argument('--inputs-sha256', required=True)
    for name in ('firecracker', 'jailer', 'kernel'):
        p.add_argument('--' + name, required=True, type=pathlib.Path)
        p.add_argument('--' + name + '-sha256', required=True)
    for name in ('native_broker', 'native_custodian'):
        p.add_argument('--' + name.replace('_', '-'), type=pathlib.Path)
        p.add_argument('--' + name.replace('_', '-') + '-sha256')
    p.add_argument('--init-mounts-devtmpfs', action='store_true',
                   help='disable kernel automount; existing strict guest init must mount devtmpfs itself')
    p.add_argument('--ephemeral-run-root', action='store_true',
                   help='use a fresh owned /tmp run root; persist evidence before host migration/stop')
    p.add_argument('--protected-rootfs', type=pathlib.Path)
    p.add_argument('--link-protected-input', action='store_true',
                   help='materialize the externally pinned prepared root-owned 0444 image by hardlink')
    p.add_argument('--vmm-user', default='realm-fc')
    p.add_argument('--approve')
    args = p.parse_args()
    spec = profile(args)
    approval = hashlib.sha256(canonical(spec)).hexdigest()
    if args.command == 'draft':
        print(json.dumps({'profile': spec, 'approval': approval}, indent=2))
    elif args.approve != approval:
        p.error('exact development probe approval required')
    else:
        run(args, spec)


if __name__ == '__main__':
    main()
