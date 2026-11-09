#!/usr/bin/env python3
"""Bounded adapter for the existing native coding launcher; no host application.

Diagnostic mode never publishes. Explicit publication mode invokes the existing
qualified CLI and installed admission; it cannot convert diagnostic evidence.

The root operator, preparation helper, relay and raw receiver are trusted.
This exercises native containment/retirement plus independently auditable custody;
it cannot qualify complete planner provenance, coding semantics or authority.
"""
import array
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import time

import coding_worker as worker
import coding_task_verifier as referee
import coding_guest_probe as probe
import host_planned_coding as planner
import derive_host_planned_guest as derive


CHILD_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
             'PYTHONDONTWRITEBYTECODE': '1'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def save(path, value):
    probe.save(path, value)


def transfer_auxiliary(channel, transports, *, native_control=False):
    """Transfer actual sockets; drop sender aliases before the done barrier.

    Native code independently checks endpoints, measured VMM peers, EOF and
    revocation. The root relay's earlier reads remain trusted, not proven here.
    """
    try:
        count = 2 if native_control else 4
        need(len(transports) == count and len({s.fileno() for s in transports}) == count,
             'exact unique auxiliary descriptors required')
        rights = array.array('i', [s.fileno() for s in transports])
        need(channel.sendmsg([b'R7RAW1' if native_control else b'R7AUX1'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) == 6,
             'partial auxiliary transfer')
    finally:
        for transport in transports:
            transport.close()
    need(channel.send(b'DONE') == 4, 'partial auxiliary transfer barrier')


class NativeLines:
    def __init__(self, child, root):
        self.child, self.root = child, root
        self.pending, self.rows = bytearray(), []

    def next(self, deadline):
        need(getattr(self,'cancelled',None) is None or not self.cancelled.is_set(),
             'original Session cancelled during native phase')
        while b'\n' not in self.pending:
            need(getattr(self,'cancelled',None) is None or not self.cancelled.is_set(),
                 'original Session cancelled during native phase')
            seconds = deadline - time.monotonic()
            need(seconds > 0, 'native phase deadline exceeded')
            ready, _, _ = select.select([self.child.stdout], [], [], min(seconds, 1))
            if not ready:
                need(self.child.poll() is None, 'native owner exited before phase')
                continue
            part = os.read(self.child.stdout.fileno(), 8192)
            need(bool(part), 'native owner closed phase stream')
            self.pending.extend(part)
            need(len(self.pending) <= 128 * 1024, 'native phase frame bound')
        raw, _, remaining = self.pending.partition(b'\n')
        self.pending = bytearray(remaining)
        row = worker.parse(raw)
        need(type(row) is dict and row.get('authority') == 'NONE', 'native phase shape differs')
        self.rows.append(row)
        save(self.root / ('native-phase-%02d.json' % len(self.rows)), row)
        return row


class NativeAttemptKeeper:
    """Transport to ONE live original Rust owner; never imports Session JSON.

    Opening the audit process grants no admission. Session and run() still
    require the real protected root Linux/x86 runtime. Original opaque owners
    remain solely inside the Rust process; these replies are diagnostic data.
    """
    def __init__(self, binary, binary_sha256, evidence, workflow_sha256, tasks, *, publisher=None):
        self.binary = Path(binary).resolve()
        need(probe.sha(self.binary) == binary_sha256, 'keeper executable pin differs')
        self.binary_sha256 = binary_sha256
        self.root = Path(evidence).absolute(); self.root.mkdir(mode=0o700)
        self.tasks = worker.parse(worker.encoded(tasks))
        self.active = None; self.poisoned = False; self.closed = False
        self.child = None; self.pidfd = None
        self.count = 0
        self.publisher=publisher
        if publisher is not None:
            need(set(publisher)=={'world','evidence','trust'},'existing Stage7 publication inputs required')
            for path in publisher.values(): protected(Path(path))
        self.auxiliary, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.forbidden_objects = {(os.fstat(s.fileno()).st_dev, os.fstat(s.fileno()).st_ino)
                                  for s in (self.auxiliary, receiver)}
        self.stderr = (self.root/'keeper.stderr').open('xb')
        try:
            try:
                prefix=[str(self.binary)]
                if publisher is not None:
                    prefix+=['task','run-coding-native-workflow',str(publisher['world']),str(publisher['evidence']),str(publisher['trust'])]
                self.child = subprocess.Popen(prefix+['--retain-native-attempts', str(self.root),
                    workflow_sha256, worker.encoded(self.tasks).decode(), str(receiver.fileno())],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
                    pass_fds=(receiver.fileno(),), start_new_session=True, env=CHILD_ENV, umask=0o077)
            finally:
                receiver.close()
            self.pidfd = os.pidfd_open(self.child.pid)
            self.lines = NativeLines(self.child, self.root)
            birth = self.lines.next(time.monotonic()+10)
            need(birth.get('phase') == 'HISTORY_OPEN' and birth.get('owner_pid') == self.child.pid
                 and birth.get('workflow') == workflow_sha256, 'original keeper birth differs')
            self.nonce = birth['owner_nonce']; self.verify_live()
        except BaseException:
            # No ATTEMPT was sent during construction. Closing this exact
            # audit-only child cannot interrupt any native execution.
            if self.child is not None:
                if self.child.stdin: self.child.stdin.close()
                try: self.child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.child.kill(); self.child.wait(timeout=10)
                if self.child.stdout: self.child.stdout.close()
            self.auxiliary.close()
            if self.pidfd is not None: os.close(self.pidfd)
            self.stderr.flush(); os.fsync(self.stderr.fileno()); self.stderr.close()
            raise

    def verify_live(self):
        need(not self.closed and self.child.poll() is None and not probe.pidfd_exited(self.pidfd),
             'original native keeper lost; JSON cannot restore it')
        need(probe.sha(Path('/proc')/str(self.child.pid)/'exe') == self.binary_sha256,
             'original native keeper executed identity differs')

    def lend(self, task):
        """Lend original kernel channels to the existing independent host.

        The sealed memfd describes descriptors; it carries NO native owners.
        Those stay in Rust. The host alarm remains independent of the caller.
        """
        self.verify_live()
        need(not self.poisoned and self.active is None and not self.lines.pending,
             'cannot lend a poisoned, active or partially read native keeper')
        need(type(task) is int and 0 <= task < len(self.tasks), 'registered native task required')
        loan_root = self.root/('loan-%02d'%self.count)
        loan_root.mkdir(mode=0o700)
        fds = {'stdin':self.child.stdin.fileno(),'stdout':self.child.stdout.fileno(),
               'pidfd':self.pidfd,'auxiliary':self.auxiliary.fileno()}
        body = {'schema':'realm.native-keeper-descriptors.v1','pid':self.child.pid,
                'binary':str(self.binary),'binary_sha256':self.binary_sha256,
                'nonce':self.nonce,'tasks':self.tasks,'task':task,'count':self.count,
                'root':str(self.root),'forbidden_objects':sorted(self.forbidden_objects),'fds':fds}
        raw = worker.encoded(body); need(len(raw)<=65536,'bounded native descriptor handoff required')
        fd = os.memfd_create('realm-native-keeper-handoff',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            with os.fdopen(os.dup(fd),'wb',buffering=0) as stream:
                stream.write(raw); os.fsync(stream.fileno())
            seals = fcntl.F_SEAL_SEAL|fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,seals)
            os.lseek(fd,0,os.SEEK_SET)
            self.active = ('LOAN',task,self.count)
            return fd, tuple([fd,*fds.values()])
        except BaseException:
            os.close(fd);raise

    def complete_loan(self, binding, deadline):
        self.verify_live()
        need(not self.poisoned and self.active is not None and self.active[0]=='LOAN','no original healthy keeper loan')
        _,task,index = self.active
        self.active = None
        try:
            receipt = self.inspect(deadline)
            attempts = receipt['attempts']
            need(len(attempts)==index+1 and attempts[index]['attempt']==index
                 and attempts[index]['task']==task and attempts[index]['original_owner_retained'] is True
                 and attempts[index]['outcome'] in ('PASS','REFUSED')
                 and attempts[index]['binding']==binding,
                 'original attempt missing/mismatched after Session closure')
            self.count += 1
            return receipt
        except BaseException:
            self.poisoned=True
            # If original live inspection completed, record the mismatch in
            # Rust too. If framing/ownership is uncertain, EOF ends eligibility.
            if self.lines.rows and self.lines.rows[-1].get('schema')=='realm.retained-native-attempts.v1':
                try:self.poison('original attempt missing/mismatched after Session closure')
                except (ValueError,OSError):self.abandon_loan('original keeper revalidation failed')
            else:self.abandon_loan('original keeper inspection incomplete')
            raise

    def abandon_loan(self, reason):
        # Unknown framing/closure cannot be repaired by reading Session JSON.
        # EOF makes the original Rust owner fail closed; do not kill it while
        # its original VMM retirement might still be unresolved.
        self.poisoned=True;self.active=None
        save(self.root/('loan-incomplete-%02d.json'%self.count),
             {'status':'INCOMPLETE','reason':str(reason),'authority':'NONE'})
        if self.child.stdin and not self.child.stdin.closed:self.child.stdin.close()

    def begin(self, task, launch, root):
        self.verify_live()
        need(not self.poisoned and self.active is None, 'keeper poisoned or attempt already active')
        need(type(task) is int and 0 <= task < len(self.tasks), 'registered native task required')
        need(launch[0] == str(self.binary) and launch[1] == '--native-referee-launch',
             'retained attempts require the original referee path; no alternate publisher')
        self.lines.root = Path(root)
        self.active = (task, self.count)
        send(self.child, {'phase':'ATTEMPT','task':task,'args':launch})
        return self.child, self.lines, self.auxiliary.dup()

    def finish(self, binding, deadline):
        self.verify_live()
        need(self.active is not None, 'no original active native attempt')
        row = self.lines.next(deadline)
        task, index = self.active
        need(row.get('phase') == 'ATTEMPT_RETAINED' and row.get('owner_nonce') == self.nonce
             and row.get('attempt') == index and row.get('task') == task
             and row.get('binding') == binding and row.get('outcome') in ('PASS','REFUSED'),
             'original native attempt did not retain matching owners')
        self.active = None; self.count += 1
        receipt = self.inspect(deadline)
        need(receipt['attempts'][index]['outcome'] == row['outcome'], 'retained outcome changed')
        return row, receipt

    def inspect(self, deadline):
        self.verify_live()
        need(self.active is None, 'cannot inspect across an active native control exchange')
        send(self.child, {'phase':'INSPECT'})
        row = self.lines.next(deadline)
        need(row.get('schema') == 'realm.retained-native-attempts.v1'
             and row.get('owner_nonce') == self.nonce and row.get('authority') == 'NONE',
             'original keeper inspection identity differs')
        return row

    def poison(self, reason):
        self.poisoned = True
        self.lines.cancelled = None  # Cleanup must observe original closure.
        self.verify_live()
        if self.active is not None and self.lines.rows:
            last = self.lines.rows[-1]
            observed = last.get('retained', {})
            if (last.get('phase') == 'ATTEMPT_INCOMPLETE'
                    and observed.get('owner_nonce') == self.nonce
                    and any(r.get('attempt') == self.active[1] and r.get('outcome') == 'INCOMPLETE'
                            for r in observed.get('attempts',[]))):
                # Only latch failure. This cannot construct/restore an owner.
                self.active = None
        # The driver kills only its held VMM/cgroup before this call. Never
        # kill a keeper whose active execution closure remains unknown.
        if self.active is not None:
            send(self.child, {'phase':'ABORT','reason':str(reason)[:1024]})
            deadline = time.monotonic()+145
            while self.active is not None:
                row = self.lines.next(deadline)
                if row.get('phase') == 'ATTEMPT_INCOMPLETE':
                    need(row.get('retained',{}).get('owner_nonce') == self.nonce,
                         'foreign incomplete attempt')
                    self.active = None
                elif row.get('phase') == 'ATTEMPT_RETAINED':
                    need(row.get('owner_nonce') == self.nonce and row.get('attempt') == self.active[1],
                         'foreign retained attempt during cleanup')
                    self.active = None; self.count += 1
        send(self.child, {'phase':'ABORT','reason':str(reason)[:1024]})
        row = self.lines.next(time.monotonic()+10)
        need(row.get('owner_nonce') == self.nonce and row.get('ownership_status') == 'INCOMPLETE',
             'original keeper abort did not latch incomplete')

    def publish(self, deadline):
        self.verify_live()
        need(self.publisher is not None and not self.poisoned and self.active is None,
             'original all-attempt publisher unavailable/incomplete')
        self.inspect(deadline)  # Original Rust owners are revalidated again by PUBLISH.
        send(self.child,{'phase':'PUBLISH'})
        row=self.lines.next(deadline)
        need(row.get('phase')=='WORKFLOW_PUBLISHED' and row.get('publication',{}).get('state')=='VALID',
             'original owner-consuming Stage7 publication incomplete')
        need(row['publication'].get('application_handoff',{}).get('status')=='NOT_RUN',
             'workflow publication must defer independent Stage8 authorization')
        need(self.child.wait(timeout=max(.001,deadline-time.monotonic()))==0,'original publisher exit differs')
        self.closed=True
        self.child.stdin.close();self.child.stdout.close();self.auxiliary.close();os.close(self.pidfd)
        self.stderr.flush();os.fsync(self.stderr.fileno());self.stderr.close()
        return row

    def close(self):
        if self.closed: return
        need(self.active is None, 'close the original active Session before releasing its keeper')
        self.verify_live()
        send(self.child, {'phase':'RELEASE'})
        row = self.lines.next(time.monotonic()+10)
        need(row.get('phase') == 'OWNERS_RELEASED' and row.get('owner_retention') == 'ENDED',
             'keeper release incomplete')
        need(self.child.wait(timeout=10) == 0, 'keeper release process failed')
        self.closed = True
        self.child.stdin.close(); self.child.stdout.close(); self.auxiliary.close()
        os.close(self.pidfd); self.stderr.flush(); os.fsync(self.stderr.fileno()); self.stderr.close()
        return row


class _BorrowedNativeProcess:
    """Kernel-checked channels to an existing process, never a Popen replica."""
    def __init__(self,pid,pidfd,stdin_fd,stdout_fd):
        self.pid,self.pidfd=pid,pidfd
        self.stdin=os.fdopen(stdin_fd,'wb',buffering=0)
        self.stdout=os.fdopen(stdout_fd,'rb',buffering=0)
        info=dict(line.split(':',1) for line in Path('/proc/self/fdinfo/'+str(pidfd)).read_text().splitlines() if ':' in line)
        need(int(info.get('Pid','-1'))==pid,'borrowed pidfd identifies another native process')
        for descriptor, stream in ((0,self.stdin),(1,self.stdout)):
            actual=(Path('/proc')/str(pid)/'fd'/str(descriptor)).stat()
            held=os.fstat(stream.fileno())
            need(stat.S_ISFIFO(actual.st_mode) and stat.S_ISFIFO(held.st_mode)
                 and (actual.st_dev,actual.st_ino)==(held.st_dev,held.st_ino),
                 'borrowed native control pipe identifies another process')
    def poll(self):
        # A non-parent cannot invent/reap an exit code. Any observed loss is
        # failure; there is deliberately no wait()/kill() authority here.
        return 2 if probe.pidfd_exited(self.pidfd) else None


class _BorrowedNativeTransport(NativeAttemptKeeper):
    def publish(self,deadline):
        raise ValueError('borrowed transport cannot publish original workflow owners')
    # Only transport operations are lent. Publication, original ownership and
    # keeper lifetime are not serialized or transferred into this wrapper.
    def close(self):
        raise ValueError('borrowed transport cannot release the original keeper')
    def lend(self, task):
        raise ValueError('borrowed transport cannot re-lend original channels')
    def complete_loan(self, binding, deadline):
        raise ValueError('only the original controller can close its descriptor loan')


def attach_native_keeper(config_fd):
    """Adopt exact inherited kernel descriptors, not serialized owner records."""
    seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK
    need(fcntl.fcntl(config_fd,fcntl.F_GET_SEALS)&seals==seals,'sealed native descriptor handoff required')
    with os.fdopen(config_fd,'rb') as stream:raw=stream.read(65537)
    need(0<len(raw)<=65536,'bounded native descriptor handoff required')
    body=worker.parse(raw)
    need(set(body)=={'schema','pid','binary','binary_sha256','nonce','tasks','task','count','root','forbidden_objects','fds'}
         and body['schema']=='realm.native-keeper-descriptors.v1','native descriptor handoff shape differs')
    fds=body['fds']
    need(set(fds)=={'stdin','stdout','pidfd','auxiliary'} and all(type(fd) is int and fd>2 for fd in fds.values())
         and len(set(fds.values()))==4,'distinct inherited native descriptors required')
    for fd in fds.values():os.set_inheritable(fd,False)
    keeper=object.__new__(_BorrowedNativeTransport)
    keeper.child=_BorrowedNativeProcess(body['pid'],fds['pidfd'],fds['stdin'],fds['stdout'])
    keeper.pidfd=fds['pidfd'];keeper.binary=Path(body['binary']);keeper.binary_sha256=body['binary_sha256']
    keeper.root=Path(body['root']);keeper.tasks=body['tasks'];keeper.nonce=body['nonce']
    keeper.count=body['count'];keeper.active=None;keeper.poisoned=False;keeper.closed=False
    keeper.auxiliary=socket.socket(fileno=fds['auxiliary'])
    keeper.forbidden_objects={tuple(x) for x in body['forbidden_objects']}
    log_root=keeper.root/('loan-%02d'%keeper.count)
    metadata=log_root.lstat()
    need(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.geteuid()
         and stat.S_IMODE(metadata.st_mode)==0o700,'private original transport evidence directory required')
    keeper.lines=NativeLines(keeper.child,log_root)
    keeper.verify_live()
    return keeper,body['task']


def publication_result(lines, deadline):
    """Drain the actual native CLI stream through EOF under the driver bound."""
    raw = bytearray(lines.pending)
    lines.pending.clear()
    while True:
        seconds = deadline - time.monotonic()
        need(seconds > 0, 'native publication terminal stream deadline')
        ready, _, _ = select.select([lines.child.stdout], [], [], min(seconds, 1))
        if not ready:
            continue
        part = os.read(lines.child.stdout.fileno(), 8192)
        if not part:
            break
        raw.extend(part)
        need(len(raw) <= 128 * 1024, 'native publication result oversized')
    need(0 < len(raw) <= 128 * 1024, 'native publication result missing')
    result = worker.parse(raw)
    need(type(result) is dict and result.get('state') == 'VALID',
         'native canonical publication did not verify')
    return result


def finish_native_owner(lines, deadline, *, publication=False):
    # A publisher may still be writing after RETIRED. Drain first so a full
    # pipe cannot deadlock wait(), and use the original overall driver bound.
    terminal = publication_result(lines, deadline) if publication else None
    if publication:
        # Preserve the native publication/application distinction even if the
        # original process subsequently exits nonzero for refused application.
        save(lines.root / 'canonical-publication-result.json', terminal)
    timeout = deadline - time.monotonic() if publication else 10
    need(timeout > 0, 'native publication process deadline')
    need(lines.child.wait(timeout=timeout) == 0, 'native owner exited unsuccessfully')
    return terminal


def send(child, row):
    data = worker.encoded(row) + b'\n'
    need(len(data) <= 65536, 'native configuration bound')
    child.stdin.write(data); child.stdin.flush()


def protected(path):
    for p in (path, *path.parents):
        info = p.lstat()
        need(not p.is_symlink() and info.st_uid == 0 and info.st_mode & 0o022 == 0,
             'unprotected native executable/parent')


def publication_options(args):
    names = ('publication_world', 'publication_evidence', 'publication_trust', 'publication_trust_sha256')
    values = [getattr(args, name, None) for name in names]
    need(not any(v is not None for v in values) or all(v is not None for v in values),
         'publication world/evidence/trust and external trust pin must be supplied together')
    if values[0] is None:
        need(not getattr(args, 'publication_only', False), 'publication-only requires explicit publication inputs')
        return None
    need(args.native_relay and args.owned_referee_python is not None,
         'publication requires original native relay and owned referee')
    need(all(p.is_absolute() and '..' not in p.parts and '.' not in p.parts for p in values[:3]) and
         re.fullmatch('[0-9a-f]{64}', values[3]), 'unaliased publication paths and external trust pin required')
    need(re.fullmatch('[0-9a-f]{64}', args.publication_evidence.name),
         'publication evidence child must be the installed grant storage handle')
    need(not any(p.is_relative_to(q) for i, p in enumerate(values[:3])
                 for j, q in enumerate(values[:3]) if i != j),
         'publication world/evidence/trust paths must be separate')
    return dict(zip(names, values))


def native_launch(args, native_state, auxiliary_fd):
    publication = publication_options(args)
    launch = [str(args.native_binary)]
    if publication is not None:
        launch += ['task', 'run-coding-native']
        if getattr(args, 'publication_only', False):
            launch += ['--publication-only']
        launch += [str(args.publication_world), str(args.publication_evidence),
                   str(args.publication_trust), '--native-referee-launch', '--installed-runtime-admission']
    else:
        launch += ['--native-referee-launch' if args.owned_referee_python is not None else '--native-custody-launch']
    launch += [str(native_state), worker.digest(worker.encoded(worker.contract())), probe.sha(Path(worker.__file__)),
               str(args.custodian), '996', '980', str(auxiliary_fd)]
    if args.owned_referee_python is not None:
        launch.append(str(args.owned_referee_python))
    return launch


def application_disposition(args, terminal):
    application = terminal.get('application_handoff')
    need(type(application) is dict, 'native application disposition missing')
    if getattr(args, 'publication_only', False):
        need(application.get('status') == 'NOT_RUN'
             and application.get('application_authorization') == 'NONE'
             and application.get('application_dispatched') is False
             and application.get('receiver_profile') == 'realm.stage8.ordered-create.v1',
             'publication-only must retain independent Stage8 authorization as pending')
    else:
        need(application.get('status') == 'APPLIED_AND_FINAL_VERIFIED'
             and application.get('execution_qualification') == 'QUALIFIED'
             and application.get('application_authorization') == 'AUTHORIZED_INSTALLED_GRANT',
             'native publication did not complete protected receiving/application')
    return application

def run(args, *, session_ready=None, session_closed=None, keeper=None, native_task=None,
        cancelled=None, session_deadline=None):
    need(os.geteuid() == 0 and (platform.system(), platform.machine()) == ('Linux', 'x86_64'),
         'actual root Linux x86_64 required')
    role=getattr(args,'native_task_role',None)
    need(role is None or keeper is not None,'native API/CLI tasks require the original persistent keeper')
    if keeper is not None:
        need(type(native_task) is int and keeper.tasks[native_task].get('role')==role, 'frozen native task role differs')
    deadline = min(time.monotonic()+300, session_deadline) if session_deadline is not None else time.monotonic()+300
    need(time.monotonic() < deadline and (cancelled is None or not cancelled.is_set()), 'native Session expired before preparation')
    publication = publication_options(args)
    need(keeper is None or publication is None,
         'retained workflow cannot invoke the single-run publisher; all-attempt issuer required')
    if publication is not None:
        for path in (args.publication_world, args.publication_evidence, args.publication_trust):
            protected(path)
        need(probe.sha(args.publication_trust) == args.publication_trust_sha256, 'independent publication trust pin differs')
    need(re.fullmatch('[0-9]{3}', args.run), 'three-digit fresh run label required')
    root = Path('/tmp/realm-v7-coding-development-' + args.run)
    inputs = Path('/tmp/realm-v7-coding-inputs-' + args.run)
    state = Path('/var/lib/r7s' + args.run)
    jail = Path('/var/lib/r7j' + args.run)
    cg_parent = Path('/sys/fs/cgroup/realm-v7-native-' + args.run)
    need(all(not p.exists() for p in (root, inputs, state, jail, cg_parent)), 'fresh run paths required')
    for p, pin in ((args.native_binary, args.native_sha256), (args.custodian, args.custodian_sha256)):
        protected(p); need(probe.sha(p) == pin, 'external native executable pin differs')
    if args.owned_referee_python is not None:
        need(args.native_relay, 'owned referee route requires actual native control relay')
        protected(args.owned_referee_python)
        need(probe.sha(args.owned_referee_python) == args.owned_referee_python_sha256,
             'independent checker interpreter pin differs')
    need(derive.sha(args.base / 'guest-inputs.json') == args.base_sha256, 'protected predecessor pin differs')
    source_manifest = worker.parse((args.base / 'guest-inputs.json').read_bytes())
    need(shutil.disk_usage('/tmp').free >= 2 * source_manifest['rootfs_bytes'] + 2 * 1024**3,
         'insufficient scratch margin')
    need(shutil.disk_usage('/var/lib').free >= source_manifest['rootfs_bytes'] + 128 * 1024**2,
         'insufficient native jail/persistent evidence margin')
    kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    try:
        need(fcntl.ioctl(kvm, 0xAE00) == 12, 'actual KVM API12 required')
    finally:
        os.close(kvm)
    need({'cpu', 'memory', 'pids'} <= set(Path('/sys/fs/cgroup/cgroup.subtree_control').read_text().split()),
         'existing delegated root controllers required; no global changes')
    for name, pin in {'firecracker': '99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5',
          'jailer': '65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f',
          'kernel': '9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2'}.items():
        protected(args.assets / name); need(probe.sha(args.assets / name) == pin, 'locked native asset differs: ' + name)
    # Read-only occupancy check. Never stop or take over another process.
    busy = []
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            try:
                if (entry / 'exe').resolve(strict=True).name in (
                        'firecracker', 'realm-vmm', 'jailer', 'llama-cli', 'llama-server', 'cargo', 'rustc'):
                    if keeper is None or int(entry.name) != keeper.child.pid:
                        busy.append(int(entry.name))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
    need(not busy, 'competing VM/model/build workload present; refuse resource window: ' + str(busy))
    account = pwd.getpwnam('realm-fc')
    need(account.pw_uid and account.pw_gid and account.pw_shell == '/usr/sbin/nologin', 'dedicated VMM account required')
    # These exact disposable directories are created fresh; no historical record is chmod-normalized.
    for p in (root, state, jail):
        p.mkdir(mode=0o700); p.chmod(0o700)
    cg_parent.mkdir(); (cg_parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    native_state = state / 'native'; native_state.mkdir(mode=0o700); native_state.chmod(0o700)
    # This successor asks the native owner to create its own custody output,
    # socketpair and cgroup-owned child. No writable custody FD crosses Python.
    custody_dir = output = original = original_object = None
    auxiliary_tx, auxiliary_rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    forbidden_vmm_objects = set(keeper.forbidden_objects) if keeper else set()
    for channel in (auxiliary_tx, auxiliary_rx):
        item = os.fstat(channel.fileno())
        forbidden_vmm_objects.add((item.st_dev, item.st_ino))
    native = custodian = proxy = raw_listener = raw_connection = None
    vmm_fd = None; vmm_pid = None; group = None
    result = {'authority': 'NONE', 'realm_artifact': None, 'status': 'NOT_COMPLETE',
              'run': args.run, 'actual_vm_started': False, 'publication_authority': False,
              'planner_input_capture': 'INCOMPLETE_EXTERNAL_CODEX', 'native_custody': 'NOT_RUN'}
    logs = []
    def log(name):
        f = (root / name).open('xb'); os.fchmod(f.fileno(), 0o600); logs.append(f); return f
    save(root / 'approved-native-plan.json', plan(args))
    probe.enable_child_subreaper()
    try:
        launch = native_launch(args, native_state, auxiliary_rx.fileno())
        if keeper is None:
            native = subprocess.Popen(launch,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log('native.stderr'),
                pass_fds=(auxiliary_rx.fileno(),), start_new_session=True, umask=0o077, env=CHILD_ENV)
            lines = NativeLines(native, root)
        else:
            auxiliary_tx.close()
            native, lines, auxiliary_tx = keeper.begin(native_task, launch, root)
        auxiliary_rx.close()
        lines.cancelled = cancelled
        birth = lines.next(min(deadline, time.monotonic() + 10))
        need(birth.get('phase') == 'BINDING', 'native birth phase differs')
        need(probe.sha(Path('/proc') / str(native.pid) / 'exe') == args.native_sha256,
             'native owner executed bytes differ')
        deferred_inputs=birth.get('task_inputs')
        admission_id = native_admission_identity(birth, required=publication is not None)
        binding = birth['binding']; save(root / 'native-binding.json', binding)
        native_step=birth.get('native_subtask')
        native_inputs=None
        if deferred_inputs is not None:
            need(keeper is not None and keeper.tasks[native_task].get('installed_admission',False)
                 and source_manifest.get('execution_mode')=='immutable-native-bootstrap', 'approved immutable bootstrap image required')
            native_inputs={'root':birth['task_inputs_blake3'],'inputs':deferred_inputs}
            save(root/'native-task-inputs.json',native_inputs)
            inputs=args.base
            manifest=dict(source_manifest)
            manifest['challenge']=binding['challenge_root']
            leaf=manifest.get('rootfs_file')
            need(leaf=='rootfs-'+manifest['rootfs_sha256']+'.ext4','content-addressed immutable image leaf required')
            image=inputs/leaf
            protected(image)
            need(probe.sha(image)==manifest['rootfs_sha256'] and stat.S_IMODE(image.stat().st_mode)==0o444,
                 'immutable rootfs digest/mode differs')
        else:
            derive_command = ['/usr/bin/python3', str(Path(derive.__file__)), '--source', str(args.base),
                 '--source-sha256', args.base_sha256, '--root', str(inputs), '--ephemeral-input-root',
                 '--native-submission-binding', str(root / 'native-binding.json')]
            if native_step is not None:
                save(root/'native-subtask.json',native_step)
                derive_command += ['--native-subtask',str(root/'native-subtask.json')]
            with log('derive.stdout') as out, log('derive.stderr') as err:
                subprocess.run(derive_command, stdout=out, stderr=err, check=True, timeout=45, env=CHILD_ENV)
            manifest = worker.parse((inputs / 'guest-inputs.json').read_bytes())
            image=inputs/'rootfs.ext4'
        pins=manifest['source_files']
        launch=planner.launch_document(manifest['challenge'],{n:pins[n] for n in
            ('host_planned_coding.py','coding_worker.py','coding_guest_boot.py','coding_native_client.py','candidate_channel_guard.py','coding_task_verifier.py','development_task_oracles.py')},binding,native_step,native_inputs)
        planner_run=worker.digest(worker.encoded(launch))
        save(root/'launch.json',launch)
        empty = root / 's0'; empty.mkdir(mode=0o700)
        with (empty / 'output').open('xb') as s0_output:
            os.fchmod(s0_output.fileno(), 0o600); s0_output.flush(); os.fsync(s0_output.fileno())

        workspace = root / 's0.ext4'
        with workspace.open('xb') as stream: stream.truncate(8 * 1024**2)
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-d', str(empty), str(workspace)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, env=CHILD_ENV)
        subprocess.run(['debugfs', '-w', '-R', 'rmdir /lost+found', str(workspace)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, env=CHILD_ENV)
        starting, working = root / 'starting.ext4', root / 'working.ext4'
        shutil.copyfile(workspace, starting); shutil.copyfile(workspace, working)
        for p in (workspace, starting): p.chmod(0o444)
        working.chmod(0o600)
        backend = {'firecracker': str(args.assets / 'firecracker'), 'kernel': str(args.assets / 'kernel'),
             'rootfs': str(image), 'workspace_device': str(workspace),
             'guest_supervisor': str(inputs / 'coding-init'), 'state_dir': str(state),
             'production_jailer': {'jailer': str(args.assets / 'jailer'), 'uid': account.pw_uid, 'gid': account.pw_gid,
                 'chroot_base_dir': str(jail), 'cgroup_parent': cg_parent.name, 'memory_max_bytes': 1024**3, 'pids_max': 32}}
        relay_config = None
        if args.native_relay:
            relay_config = {'planner_socket': str(native_state / 'planner.sock'),
                'guest_hello': {'schema': planner.SCHEMA, 'authority': 'NONE',
                    'run_id': planner_run, 'challenge': manifest['challenge'],
                    'worker_sha256': pins['coding_worker.py'],
                    'protocol_sha256': pins['host_planned_coding.py']}}
            if native_inputs is not None:relay_config['guest_hello']['task_inputs_blake3']=native_inputs['root']
            save(root / 'native-relay-config.json', relay_config)
        need(time.monotonic() < deadline and (cancelled is None or not cancelled.is_set()),
             'native Session expired before measured preparation')
        send(native, {'phase': 'CONFIGURE', 'binding': binding, 'backend': backend,
             'starting_workspace': str(starting), 'working_workspace': str(working),
             's0_root': birth['s0_root'], 'timeout_seconds': min(120, max(1, math.ceil(deadline-time.monotonic()))),
             'coding_scope': prelaunch_scope(args, binding, admission_id,
                 keeper.tasks[native_task] if keeper else None,native_step,birth.get('task_inputs_blake3')), 'native_relay': relay_config})
        prepared = lines.next(min(deadline, time.monotonic() + 45))
        if deferred_inputs is not None:
            need(prepared.get('phase')=='ADMITTED' and prepared.get('binding')==binding
                 and prepared.get('task_inputs_blake3')==birth['task_inputs_blake3'],'original final input admission missing/substituted')
            admission_id=native_admission_identity(prepared,required=True)
            save(root/'admitted-native-inputs.json',prepared)
            prepared=lines.next(min(deadline,time.monotonic()+45))
        need(prepared.get('phase') == 'PREPARED' and prepared['binding'] == binding, 'native measured preparation differs')
        custody_birth = prepared['owned_custody']
        custodian_pid = custody_birth['pid']
        audit_state = Path(custody_birth['frontier_state'])
        need(audit_state == Path(prepared['launch_state']) and audit_state.parent == state,
             'native custody state differs from actual launch')
        custody_dir = audit_state / 'custody'; output = custody_dir / 'output'
        original = output.lstat()
        original_object = {'device': original.st_dev, 'inode': original.st_ino}
        need(original_object == custody_birth['output_object'], 'native original output identity differs')
        save(root / 'custody-output-object.json', original_object)
        forbidden_vmm_objects.add((original.st_dev, original.st_ino))
        custody_process = Path('/proc') / str(custodian_pid)
        need(probe.sha(custody_process / 'exe') == args.custodian_sha256, 'custodian executed bytes differ')
        custody_status = (custody_process / 'status').read_text()
        fields = dict(line.split(':', 1) for line in custody_status.splitlines() if ':' in line)
        need(int(fields['Uid'].split()[1]) == 996 and int(fields['Gid'].split()[1]) == 980 and
             fields['CapEff'].strip() == '0000000000000000' and fields['NoNewPrivs'].strip() == '1',
             'custodian credentials/capabilities differ')
        save(root / 'custodian-process.json', {'pid': custodian_pid, 'status': custody_status,
             'stat': (custody_process / 'stat').read_text(), 'binary_sha256': args.custodian_sha256})
        vmm_pid = prepared['vmm_pid']; vmm_fd = os.pidfd_open(vmm_pid)
        observed = Path('/proc') / str(vmm_pid)
        need(probe.sha(observed / 'exe') == '99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5', 'actual VMM executable differs')
        need(int((observed / 'stat').read_text().rsplit(') ', 1)[1].split()[19]) == prepared['vmm_start_ticks'], 'actual VMM birth differs')
        group_text = (observed / 'cgroup').read_text().strip(); need(group_text.startswith('0::/' + cg_parent.name + '/'), 'foreign native cgroup')
        group = Path('/sys/fs/cgroup') / group_text[4:]
        need((custody_process / 'cgroup').read_text().strip() == group_text,
             'custodian was not born in the actual owned VMM cgroup')

        need(not probe.pidfd_exited(vmm_fd), 'native VMM exited before tool execution')
        # Independently inspect the paused VMM's actual descriptor table. These
        # are the original transferred objects, not matching path strings.
        descriptors = []
        for descriptor in (observed / 'fd').iterdir():
            item = descriptor.stat()
            need((item.st_dev, item.st_ino) not in forbidden_vmm_objects,
                 'VMM inherited broker/custodian channel or custody output')
            descriptors.append({'fd': int(descriptor.name), 'target': os.readlink(descriptor),
                                'device': item.st_dev, 'inode': item.st_ino})
        need(bool(descriptors), 'VMM descriptor inventory unavailable')
        save(root / 'vmm-inherited-fd-control.json', {'authority': 'NONE',
             'forbidden_objects': [list(x) for x in sorted(forbidden_vmm_objects)],
             'observed_vmm_fds': descriptors, 'custody_descriptors_absent': True})
        run_dir = Path(prepared['control_endpoint']).parent
        raw_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw_listener.bind(prepared['raw_endpoint']); os.chown(prepared['raw_endpoint'], account.pw_uid, account.pw_gid)
        os.chmod(prepared['raw_endpoint'], 0o600); raw_listener.listen(1)
        if not args.native_relay:
            proxy = planner.PlannerProxy(root, run_dir, account.pw_uid, account.pw_gid,
                                        guest_path=Path(prepared['control_endpoint']))
        spec = {'planner_run_id': planner_run, 'challenge': manifest['challenge']}
        save(root / 'profile.json', {'authority': 'NONE', 'native_submission_binding': binding,
             'planner_run_id': planner_run, 'challenge': manifest['challenge'], 'inputs_sha256': probe.sha(inputs / 'guest-inputs.json'),
             'rootfs_sha256': manifest['rootfs_sha256'], 'native_binary_sha256': args.native_sha256,
             'custodian_binary_sha256': args.custodian_sha256, 'prepared': prepared})
        need(time.monotonic() < deadline and (cancelled is None or not cancelled.is_set()),
             'native Session expired before guest START')
        send(native, {'phase': 'START', 'binding': binding})
        running = lines.next(min(deadline, time.monotonic() + 20)); need(running.get('phase') == 'RUNNING' and running.get('binding') == binding, 'native start refused')
        result['actual_vm_started'] = True
        if session_ready is not None:
            session_ready({'schema': 'realm.vm-session-ready.v1', 'authority': 'NONE',
                'run_id': planner_run, 'challenge': manifest['challenge'],
                'socket': str(native_state / 'planner.sock'), 'binding': binding})
        raw_received = channel_closed = False
        while not (raw_received and channel_closed):
            need(time.monotonic() < deadline and native.poll() is None, 'native run deadline/exit')
            need(cancelled is None or not cancelled.is_set(), 'original Session cancelled')
            surfaces = [raw_listener, native.stdout]
            if proxy is not None:
                surfaces.extend((proxy.guest_listener, proxy.local))
            ready, _, _ = select.select(surfaces, [], [], min(1, deadline - time.monotonic()))
            if native.stdout in ready:
                row = lines.next(deadline)
                need(row.get('phase') == 'SUBMISSION_CLOSED' and row.get('binding') == binding, 'unexpected native phase')
                channel_closed = True
            if proxy is not None and proxy.guest_listener in ready:
                proxy.accept_guest(vmm_pid, spec, {'worker': pins['coding_worker.py'], 'protocol': pins['host_planned_coding.py']})
            if proxy is not None and proxy.local in ready: proxy.serve_local()
            if raw_listener in ready:
                need(not raw_received, 'second raw connection refused')
                raw_connection, _ = raw_listener.accept()
                peer = struct.unpack('3i', raw_connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(peer == (vmm_pid, account.pw_uid, account.pw_gid), 'foreign raw VMM peer')
                probe.receive_raw_handoff(raw_connection, root, manifest['challenge'], True, min(deadline, time.monotonic() + 30))
                raw_received = True
        if proxy is not None:
            need(not proxy.failed, 'planner transport failed')
            control_listener, control_connection = proxy.detach_native_transports()
            proxy = None
            transfer_auxiliary(auxiliary_tx, (control_listener, control_connection, raw_listener, raw_connection))
        else:
            transfer_auxiliary(auxiliary_tx, (raw_listener, raw_connection), native_control=True)
        raw_listener = raw_connection = None
        auxiliary_tx.close()
        send(native, {'phase': 'RETIRE_AFTER_AUX_HANDOFF', 'binding': binding})
        retired = lines.next(min(deadline, time.monotonic() + (145 if args.owned_referee_python is not None else 25)))
        need(retired.get('phase') in (('RETIRED_SEALED_DIAGNOSTIC','RETIRED_REFUSED_DIAGNOSTIC','RETIRED_API_DIAGNOSTIC') if keeper else ('RETIRED_SEALED_DIAGNOSTIC',))
             and retired['binding'] == binding, 'native retirement/sealing refused')
        if keeper is None:
            terminal = finish_native_owner(lines, deadline, publication=publication is not None)
        else:
            retained_attempt, retained_history = keeper.finish(binding, deadline)
            result.update(retained_attempt=retained_attempt, retained_history=retained_history)
            terminal = None
        need(retired['owned_custody']['publication_capability'] is False and
             retired['owned_custody']['native_wait_verified'] is True and
             retired['owned_custody']['child_exit_status'] == 0 and
             retired['owned_custody']['process'] == custody_birth['process'],
             'native custody/retirement completion differs')
        if publication is not None:
            # Only the original native process can finalize/publish. Preserve
            # its actual terminal verifier output; never substitute a wrapper.
            handoff = worker.parse((args.publication_evidence / 'publication-handoff.json').read_bytes())
            need(handoff.get('run_id') == binding['run_id'] and
                 handoff.get('execution_id') == binding['execution_id'] and
                 handoff.get('runtime_admission_id') == admission_id and
                 handoff.get('exact_head_root') == terminal.get('reconstructed_head_root') and
                 handoff.get('destination_policy') is None and handoff.get('approval_id') is None and
                 handoff.get('application_dispatched') is False, 'native publication handoff binding differs')
            need((args.publication_evidence / 'accepted.realm').is_file() and
                 (args.publication_evidence / 'transfer-proof.json').is_file(), 'native publication outputs absent')
            application = application_disposition(args, terminal)
            result['protected_application'] = application
            result.update(canonical_publication='VERIFIED_BY_ORIGINAL_NATIVE_CLI',
                          realm_artifact=str(args.publication_evidence / 'accepted.realm'),
                          publication_evidence=str(args.publication_evidence))
        need(probe.pidfd_exited(vmm_fd), 'held VMM pidfd lacks exit')
        result.update(retirement=retired, raw_ack_sent=True, vmm_pidfd_exit=True,
                      native_custody='REFUSE_PENDING_INDEPENDENT_AUDIT')
        if args.owned_referee_python is not None:
            check = retired.get('owned_referee')
            need(type(check) is dict and check.get('check', {}).get('finite_check') in
                 (('OWNED_CHILD_FINISHED','OWNED_CHILD_REFUSED_SEMANTIC_PREDICATE','OWNED_API_CHILD_FINISHED') if keeper else ('OWNED_CHILD_FINISHED',)),
                 'owned independent referee did not complete')
            need(check['check']['authority'] == 'NONE' and not retired['publication_authority'],
                 'finite checker must not invent publication authority')
            result['owned_referee'] = check
            result['owned_referee_outcome'] = ('REFUSED' if retired['phase']=='RETIRED_REFUSED_DIAGNOSTIC' else 'PASS')
        need(retired['output_object'] == original_object, 'native output descriptor/object differs')
        rows = [worker.parse(x) for x in (audit_state / (binding['run_id'] + '.frontier.jsonl')).read_bytes().splitlines()]
        need(rows and all(r['mediation_manifest_root'] == prepared['measurement_root'] and
             r['launch_identity'] == binding['execution_id'] and r['starting_generation'] == birth['s0_root']
             for r in rows), 'frontier does not bind this native measured session')
        paths = [native_state / 'binding.json', output, custody_dir / 'custody.jsonl',
                 audit_state / (binding['run_id'] + '.frontier.jsonl')]
        def snapshot():
            out = {}
            for p in paths:
                m = p.lstat()
                need(stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and stat.S_IMODE(m.st_mode) == 0o600,
                     'original native evidence mode/type refused')
                out[str(p)] = {'sha256': probe.sha(p), 'stat': [m.st_dev, m.st_ino, m.st_mode, m.st_uid,
                     m.st_gid, m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns]}
            return out
        before_audit = snapshot()
        alternate = dict(binding, run_id='0' * 64)
        foreign = root / 'foreign-binding.json'; save(foreign, alternate)
        reports = []
        for label, contract, inode, packet_digest, head, expected in [
            ('original', native_state / 'binding.json', original.st_ino, retired['packet_blake3'], retired['transcript_head'], 0),
            ('foreign-run', foreign, original.st_ino, retired['packet_blake3'], retired['transcript_head'], 2),
            ('wrong-packet', native_state / 'binding.json', original.st_ino, '0' * 64, retired['transcript_head'], 2),
            ('wrong-head', native_state / 'binding.json', original.st_ino, retired['packet_blake3'], '0' * 64, 2),
            ('wrong-object', native_state / 'binding.json', original.st_ino + 1, retired['packet_blake3'], retired['transcript_head'], 2)]:
            command = [str(args.native_binary), '--audit-measured-owned', str(audit_state), str(contract),
                       str(original.st_dev), str(inode), packet_digest, head,
                       custody_birth['broker_monitor'], custody_birth['broker_session_root']]
            check = subprocess.run(command, capture_output=True, timeout=15, env=CHILD_ENV)
            report = {'case': label, 'argv': command, 'exit': check.returncode,
                      'stdout': check.stdout.decode(), 'stderr': check.stderr.decode()}
            reports.append(report)
            save(root / ('native-audit-' + label + '.json'), report)
            need(check.returncode == expected, 'independent native custody control failed: ' + label)
            if expected == 0:
                facts = worker.parse(check.stdout)
                need(facts['custody_head'] == retired['custody_head'] and
                     facts['frontier_head'] == retired['frontier_head'] and facts['committed_write_count'] == 1,
                     'independent native custody heads differ')
        need(snapshot() == before_audit, 'original native records changed during read-only audit')
        save(root / 'native-independent-audit.json', {'authority': 'NONE', 'original_records_unchanged': True,
             'cases': reports, 'original_files': before_audit, 'scope': 'custody integrity; no semantic or publication authority'})
        result['native_custody'] = 'PASS_INDEPENDENT_INTEGRITY_AUDIT_NON_AUTHORIZING'
        result.update(status='NATIVE_CODING_RETIRED_CUSTODY_AUDITED', binding=binding, retirement=retired,
                      raw_ack_sent=True, native_owner_exit=None if keeper else 0, custodian_exit=0,
                      vmm_pidfd_exit=True, source_rootfs_unchanged=probe.sha(image) == manifest['rootfs_sha256'])
        need(result['source_rootfs_unchanged'], 'source rootfs changed')
    except BaseException as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        def attempt(label, operation):
            try:
                return operation()
            except Exception as error:
                result.setdefault('cleanup_errors', []).append(label + ': ' + type(error).__name__ + ': ' + str(error))
                return None
        if proxy: attempt('planner close', proxy.close)
        if raw_listener: attempt('raw close', raw_listener.close)
        if raw_connection: attempt('raw connection close', raw_connection.close)
        attempt('auxiliary sender close', auxiliary_tx.close)
        attempt('auxiliary receiver close', auxiliary_rx.close)
        # Never turn forced or unknown cleanup into a successful custody run.
        if vmm_fd is not None and attempt('VMM precleanup poll', lambda: probe.pidfd_exited(vmm_fd)) is False:
            result['forced_vmm_cleanup'] = True
            attempt('exact VMM kill', lambda: signal.pidfd_send_signal(vmm_fd, signal.SIGKILL))
        if group is not None and group.exists():
            members = attempt('owned group members', lambda: (group / 'cgroup.procs').read_text())
            if members:
                result['forced_cgroup_cleanup'] = True
                attempt('owned group kill', lambda: (group / 'cgroup.kill').write_text('1'))
        if keeper is not None and 'retained_attempt' not in result:
            attempt('poison original retained workflow', lambda: keeper.poison(result.get('failure','missing attempt closure')))
        if keeper is None and native is not None and native.poll() is None:
            attempt('native control EOF', native.stdin.close)
            def wait_native():
                try:
                    native.wait(timeout=130 if vmm_fd is None else 15)
                except subprocess.TimeoutExpired:
                    need(vmm_fd is not None and probe.pidfd_exited(vmm_fd),
                         'native cleanup UNKNOWN: no exited held VMM; refuse unobserved owner kill')
                    native.kill(); native.wait(timeout=10); result['forced_native_cleanup'] = True
            attempt('owned native wait', wait_native)
        if custodian is not None and custodian.poll() is None:
            def wait_custodian():
                try: custodian.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    custodian.kill(); custodian.wait(timeout=10); result['forced_custodian_cleanup'] = True
            attempt('owned custodian wait', wait_custodian)
        # These are live cleanup observations, never inferred from wrapper exit.
        result['cleanup_observation'] = {
            'held_vmm_exited': attempt('terminal pidfd poll', lambda: probe.pidfd_exited(vmm_fd)) if vmm_fd is not None else None,
            'owned_cgroup_empty': (attempt('terminal owned group read', lambda: not (group / 'cgroup.procs').read_text().strip())
                                   if group is not None and group.exists() else True if group is not None else None),
            'native_owner_reaped': native is not None and native.poll() is not None,
            'native_owner_retained': bool(keeper is not None and 'retained_attempt' in result
                                          and keeper.child.poll() is None and not keeper.poisoned),
            'authority': 'NONE'}
        if vmm_fd is not None: attempt('pidfd close', lambda: os.close(vmm_fd))
        for f in logs:
            if not f.closed:
                attempt('log fsync', lambda: (f.flush(), os.fsync(f.fileno())))
                attempt('log close', f.close)
        result['native_owner_exit'] = native.poll() if native else None
        result['custodian_exit'] = custodian.poll() if custodian else None
        if result.get('cleanup_errors') or any(result.get(k) for k in
             ('forced_native_cleanup', 'forced_vmm_cleanup', 'forced_cgroup_cleanup', 'forced_custodian_cleanup')):
            result['status'] = 'REFUSE_NATIVE_CLEANUP_BOUNDARY'
        save(root / 'native-run-result.json', result)
        if session_closed is not None:
            session_closed(worker.parse(worker.encoded(result)))
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    print(json.dumps(result))
    return result


def native_admission_identity(birth, *, required):
    # A retained workflow uses the all-attempt publisher, not publication_options
    # on each Session. Preserve its ORIGINAL keeper-issued admission nonetheless.
    identity=birth.get('runtime_admission_id')
    if required or identity is not None:
        need(type(identity) is str and re.fullmatch('[0-9a-f]{64}',identity),
             'installed native birth omitted actual admission identity')
    return identity


def prelaunch_scope(args, binding, admission_id=None, retained_task=None,native_subtask=None,task_inputs_blake3=None):
    need(re.fullmatch('[0-9a-f]{40}', args.source_commit), 'frozen source commit required')
    scope = {'submission': binding, 'source_commit': args.source_commit,
             'checker_sha256': probe.sha(Path(referee.__file__)),
             'checker_scope_sha256': worker.digest(worker.encoded(referee.native_api_scope() if getattr(args,'native_task_role',None)=='api' else referee.describe()))}
    if retained_task is not None:
        need(retained_task['task_sha256'] == worker.digest(worker.encoded(worker.contract()))
             and retained_task['worker_sha256'] == probe.sha(Path(worker.__file__))
             and retained_task['source_commit'] == args.source_commit
             and retained_task['checker_sha256'] == scope['checker_sha256'],
             'retained task/source differs from installed native task')
        scope['checker_scope_sha256'] = retained_task['checker_scope_sha256']
    if native_subtask is not None:
        need(retained_task is not None and retained_task.get('role')==native_subtask.get('role'), 'native task role differs from keeper')
        scope['native_subtask']=native_subtask
    if task_inputs_blake3 is not None:
        need(native_subtask is not None and re.fullmatch('[0-9a-f]{64}',task_inputs_blake3),'registered task input commitment required')
        scope['task_inputs_blake3']=task_inputs_blake3
    if admission_id is not None:
        need(type(admission_id) is str and re.fullmatch('[0-9a-f]{64}', admission_id),
             'canonical installed admission identity required')
        scope['runtime_admission_id'] = admission_id
    return scope


def plan(args):
    scripts = Path(__file__).resolve().parent
    names = ('coding_native_run.py', 'host_planned_coding.py', 'derive_host_planned_guest.py',
             'coding_guest_probe.py', 'coding_worker.py', 'coding_guest_boot.py',
             'coding_guest_init.c', 'coding_native_client.py', 'candidate_channel_guard.py',
             'coding_task_verifier.py','development_task_oracles.py')
    return {'schema': 'realm.native-coding-run-plan/v1', 'authority': 'NONE', 'run': args.run,
            'task_sha256': worker.digest(worker.encoded(worker.contract())),
            'native_task_role':getattr(args,'native_task_role',None),
            'source_files': {name: probe.sha(scripts / name) for name in names},
            'native_binary': str(args.native_binary), 'native_sha256': args.native_sha256,
            'canonical_publication': {k: str(v) for k, v in publication_options(args).items()} if publication_options(args) else None,
            'application_mode': (('INDEPENDENT_STAGE8' if getattr(args, 'publication_only', False)
                                  else 'LEGACY_INSTALLED_RECEIVER') if publication_options(args) else 'NOT_REQUESTED'),
            'native_relay': {'owner':'held-current-native-ELF', 'enabled':args.native_relay,
                             'socket':'/var/lib/r7s' + args.run + '/native/planner.sock'},
            'custody_owner': 'native-cgroup-owned-before-seal-and-retirement/v1',
            'coding_prelaunch': prelaunch_scope(args, None),
            'owned_referee': {'python':str(args.owned_referee_python) if args.owned_referee_python else None,
                             'sha256':args.owned_referee_python_sha256, 'maximum_seconds':120,
                             'authority':'NONE'},
            'broker': 'measured-one-packet-write-close/v1',
            'custodian': str(args.custodian), 'custodian_sha256': args.custodian_sha256,
            'base': str(args.base), 'base_sha256': args.base_sha256, 'assets': str(args.assets),
            'vm': {'architecture': 'x86_64', 'vcpu_count': 2, 'memory_mib': 512, 'network_interfaces': [],
                   'model_api_calls': 0, 'cgroup_memory_max': 1024**3, 'pids_max': 32,
                   'supervisor_timeout_seconds': 120, 'driver_deadline_seconds': 300},
            'approval_scope': (('one installed-admission native coding execution and canonical publication; no host application'
                                if getattr(args, 'publication_only', False) else
                                'one installed-admission native coding execution and canonical publication; separate installed destination grant required')
                               if publication_options(args) else 'one native coding closure/custody experiment; no publication or host application')}


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['draft', 'run'])
    p.add_argument('--run', required=True)
    p.add_argument('--approve')
    for name in ('native-binary', 'custodian', 'assets', 'base'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('native-sha256', 'custodian-sha256', 'base-sha256', 'source-commit'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--native-relay', action='store_true')
    p.add_argument('--native-task-role',choices=['api','cli'])
    p.add_argument('--owned-referee-python', type=Path)
    p.add_argument('--owned-referee-python-sha256')
    for name in ('publication-world', 'publication-evidence', 'publication-trust'):
        p.add_argument('--' + name, type=Path)
    p.add_argument('--publication-trust-sha256')
    p.add_argument('--publication-only', action='store_true',
                   help='retain canonical publication without dispatching application; independent Stage8 authorization required')
    args = p.parse_args(argv)
    need((args.owned_referee_python is None) == (args.owned_referee_python_sha256 is None),
         'checker interpreter and independent digest must be supplied together')
    if args.owned_referee_python is not None:
        need(args.owned_referee_python.is_absolute() and
             re.fullmatch('[0-9a-f]{64}', args.owned_referee_python_sha256),
             'absolute checker interpreter and canonical SHA256 required')
    return args


def main():
    args = parse_args()
    proposal = plan(args); approval = worker.digest(worker.encoded(proposal))
    if args.command == 'draft':
        print(json.dumps({'plan': proposal, 'approval': approval}, indent=2))
    else:
        need(args.approve == approval, 'exact native coding run-plan approval required')
        run(args)


if __name__ == '__main__':
    main()
