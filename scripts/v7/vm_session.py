#!/usr/bin/env python3
"""Stage 2/3 controller API. Native and development profiles never substitute.

This module runs in the trusted control plane, never in the coding agent. It
owns processes and records, but issues no execution/publication authority.
Native execution delegates to the existing measured Firecracker owner.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

import coding_worker as worker
import host_planned_coding as protocol

HERE = Path(__file__).resolve().parent
LIMIT = 128 * 1024
PROFILES = ('firecracker-measured', 'development-kernel-child')


class SessionError(RuntimeError):
    pass


@dataclass(frozen=True)
class SessionRequest:
    profile: str
    task_sha256: str
    lifetime_seconds: int = 120
    state: str = 'fresh'  # No snapshot/rollback claim; every attempt is new.
    development_task: Path | None = None
    development_task_sha256: str | None = None

    def validate(self):
        if (self.profile not in PROFILES or self.state != 'fresh'
                or type(self.lifetime_seconds) is not int
                or not 1 <= self.lifetime_seconds <= 300
                or (self.development_task is None) != (self.development_task_sha256 is None)
                or (self.profile == 'firecracker-measured' and self.development_task is not None)):
            raise SessionError('REFUSE: unsupported profile/task/lifetime/state')
        # Reuse the owner's task validator in an isolated module. Do not mutate
        # a shared controller's global Worker task across concurrent sessions.
        spec = importlib.util.spec_from_file_location('session_task_contract', worker.__file__)
        definition = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(definition)
        if self.development_task is not None:
            definition.configure_development_task(Path(self.development_task), self.development_task_sha256)
        if self.task_sha256 != worker.digest(worker.encoded(definition.contract())):
            raise SessionError('REFUSE: exact task contract pin differs')


def host_support(profile):
    """Read-only hints only. Native owner performs actual kernel validation."""
    if profile not in PROFILES:
        raise SessionError('REFUSE: unknown runtime profile')
    system, arch = platform.system(), platform.machine()
    native = profile == 'firecracker-measured'
    reasons = []
    if native:
        if (system, arch) != ('Linux', 'x86_64'):
            reasons.append('requires Linux x86_64; no fallback')
        if os.geteuid() != 0:
            reasons.append('requires installed root control plane outside agent authority')
        for p in ('/dev/kvm', '/sys/fs/cgroup/cgroup.controllers'):
            if not Path(p).exists():
                reasons.append('missing ' + p)
    elif system not in ('Darwin', 'Linux'):
        reasons.append('Worker kernel sandbox unavailable')
    return {'profile': profile, 'host': [system, arch],
            'status': 'UNSUPPORTED' if reasons else 'PREFLIGHT_REQUIRED',
            'reasons': reasons, 'actual_vm': 'NOT_RUN', 'qualification': 'NOT_RUN', 'authority': 'NONE'}


class _Lines:
    def __init__(self, pipe):
        self.pipe, self.pending = pipe, bytearray()

    def read(self, deadline):
        while b'\n' not in self.pending:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.pipe], [], [], max(0, left))[0]:
                raise TimeoutError('session response deadline; dispatched outcome UNKNOWN')
            part = os.read(self.pipe.fileno(), 8192)
            if not part:
                raise SessionError('session process closed its response channel')
            self.pending.extend(part)
            if len(self.pending) > LIMIT:
                raise SessionError('session response exceeds bound')
        raw, _, rest = self.pending.partition(b'\n')
        self.pending = bytearray(rest)
        return worker.parse(raw)


class Session:
    """Opaque trusted-controller handle; expose only execute() to the agent.

    No path, executable, policy, environment or transport override is an agent
    operation. collect() returns evidence references, not verification authority.
    """
    def __init__(self, request, evidence):
        request.validate()
        self.request = request
        self.evidence = Path(evidence).absolute()
        self.evidence.mkdir(mode=0o700)  # Never reuse or delete research state.
        self.id = uuid.uuid4().hex
        self.deadline = time.monotonic() + request.lifetime_seconds
        self.child = None
        self.lock = threading.RLock()
        self.closed = False
        self.finished = False
        self.terminal = None
        self.sequence = 0
        self.calls = 0
        self.inflight = None
        self.journal = (self.evidence / 'session.jsonl').open('xb', buffering=0)
        self.head = '0' * 64
        self.timer = None
        self.failure = None
        self.ready = None
        self.event('REQUEST', {'profile': request.profile, 'task_sha256': request.task_sha256,
                               'state': request.state, 'lifetime_seconds': request.lifetime_seconds})

    def event(self, phase, data):
        row = {'session': self.id, 'sequence': self.sequence, 'previous': self.head,
               'phase': phase, 'data': data, 'authority': 'NONE'}
        self.head = worker.digest(worker.encoded(row))
        self.journal.write(worker.encoded({**row, 'sha256': self.head}) + b'\n')
        os.fsync(self.journal.fileno())
        self.sequence += 1

    @classmethod
    def start(cls, request, evidence, *, installed_profile=None, profile_sha256=None,
              native_keeper=None, native_task=None):
        request.validate()
        if native_keeper is not None and request.profile != 'firecracker-measured':
            raise SessionError('development Session cannot consume a native keeper')
        if (native_keeper is None) != (native_task is None):
            raise SessionError('original native keeper and registered task index required together')
        support = host_support(request.profile)
        if support['status'] == 'UNSUPPORTED':
            raise SessionError(json.dumps(support))
        s = cls(request, evidence)
        try:
            if request.profile == 'development-kernel-child':
                if installed_profile is not None or profile_sha256 is not None:
                    raise SessionError('development session cannot consume native provisioning')
                argv = [sys.executable, '-I', '-B', str(HERE / 'vm_session_host.py'),
                        'development', str(s.evidence / 'worker'), request.task_sha256, str(s.deadline)]
                if request.development_task is not None:
                    argv += [str(Path(request.development_task).resolve()), request.development_task_sha256]
            else:
                s._protected_profile(installed_profile, profile_sha256)
                argv = [sys.executable, '-I', '-B', str(HERE / 'vm_session_host.py'),
                        'native', str(installed_profile), profile_sha256,
                        str(s.deadline)]
            pass_fds = ()
            if native_keeper is not None:
                import coding_native_run as native
                if not isinstance(native_keeper, native.NativeAttemptKeeper):
                    raise SessionError('original live native keeper transport required')
                if (type(native_task) is not int or not 0 <= native_task < len(native_keeper.tasks)
                    or native_keeper.tasks[native_task]['task_sha256'] != request.task_sha256
                    or native_keeper.binary != s.native_args.native_binary.resolve()
                    or native_keeper.binary_sha256 != s.native_args.native_sha256):
                    raise SessionError('installed native Session differs from original keeper')
                if native.publication_options(s.native_args) is not None:
                    raise SessionError('all-attempt issuer required; single-run publisher cannot discard history')
                s.native_keeper = native_keeper
                config_fd, pass_fds = native_keeper.lend(native_task)
                s.keeper_config_fd = config_fd
                argv[4] = 'native-retained'  # same independent host alarm/cleanup
                argv += [str(config_fd)]
            s.stderr = (s.evidence / 'host.stderr').open('xb')
            env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
            s.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=s.stderr, env=env, close_fds=True,
                                       pass_fds=pass_fds, start_new_session=True)
            if hasattr(s,'keeper_config_fd'):
                os.close(s.keeper_config_fd); del s.keeper_config_fd
            s.lines = _Lines(s.child.stdout)
            s.ready = s.lines.read(s.deadline)
            if s.ready.get('schema') != 'realm.vm-session-ready.v1' or s.ready.get('authority') != 'NONE':
                raise SessionError('session readiness envelope differs')
            if request.profile == 'firecracker-measured':
                expected = '/var/lib/r7s' + s.native_args.run + '/native/planner.sock'
                if s.ready.get('socket') != expected:
                    raise SessionError('native endpoint differs from installed run')
                s.socket = expected
            elif s.ready.get('profile') != request.profile:
                raise SessionError('development profile differs')
            s.event('READY', s.ready)
            s.timer = threading.Timer(max(0, s.deadline-time.monotonic()), s._expire)
            s.timer.daemon = True
            s.timer.start()
            return s
        except BaseException as e:
            s.failure = str(e)
            s.close()
            raise

    def _protected_profile(self, path, pin):
        # Installed root-owned source/profile authority, not a key minted here.
        import coding_native_run as native
        if path is None or not isinstance(pin, str) or len(pin) != 64:
            raise SessionError('independently pinned installed native profile required')
        path = Path(path)
        native.protected(path)
        native.protected(Path(sys.executable).resolve())
        for source in HERE.glob('*.py'):
            native.protected(source)
        raw = path.read_bytes()
        if len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != pin:
            raise SessionError('installed profile pin differs')
        profile = worker.parse(raw)
        if set(profile) != {'schema', 'argv', 'source_sha256'} or profile['schema'] != 'realm.vm-profile.v1':
            raise SessionError('native profile schema differs')
        if type(profile['argv']) is not list or not all(type(a) is str for a in profile['argv']):
            raise SessionError('native profile argv differs')
        # Pin the complete trusted Python surface; no writable import fallback.
        sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.glob('*.py')}
        if profile['source_sha256'] != sources:
            raise SessionError('installed source pins differ')
        args = native.parse_args(profile['argv'])
        if args.command != 'run' or not args.native_relay or args.owned_referee_python is None:
            raise SessionError('session requires existing native relay/referee')
        # If configured, publication still occurs only in the original native
        # CLI, under its installed admission and verifier. This wrapper never
        # constructs qualification, proofs or destination grants.
        native.publication_options(args)
        if args.approve != worker.digest(worker.encoded(native.plan(args))):
            raise SessionError('installed exact native plan pin differs')
        self.native_args = args
        self.profile_pin = pin

    def execute(self, action):
        with self.lock:
            if self.closed or self.finished or time.monotonic() >= self.deadline:
                raise SessionError('session closed/finished/expired; start a fresh attempt')
            if self.calls >= worker.MAX_REQUESTS:
                raise SessionError('session request budget exhausted')
            self.calls += 1
            # Existing restricted-tool grammar; no arbitrary commands or network.
            try:
                protocol.valid_action(action)
            except (ValueError, TypeError) as e:
                self.event('REFUSED_BEFORE_DISPATCH', {'error': str(e)})
                return {'status': 'REFUSED_BEFORE_DISPATCH', 'authority': 'NONE', 'error': str(e)}
            self.event('DISPATCH_INTENT', {'action': action})
            self.inflight = action['tool']
            try:
                if self.request.profile == 'development-kernel-child':
                    self.child.stdin.write(worker.encoded(action) + b'\n')
                    self.child.stdin.flush()
                    result = self.lines.read(self.deadline)
                else:
                    import coding_native_run as native
                    native.protected(Path(self.socket))
                    envelope = {k: self.ready[k] for k in ('run_id', 'challenge')}
                    envelope.update(request_id=os.urandom(32).hex(), action=action)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                        channel.settimeout(max(0.001, self.deadline-time.monotonic()))
                        channel.connect(self.socket)
                        protocol.send(channel, envelope)
                        reply = protocol.receive(channel)
                    if (not isinstance(reply, dict) or reply.get('authority') != 'NONE'
                            or any(reply.get(k) != envelope[k] for k in ('run_id', 'challenge', 'request_id'))):
                        raise SessionError('native reply/run/request binding differs; outcome UNKNOWN')
                    result = reply['result']
                self.event('REPLY', {'result': result})
                self.inflight = None
                if action['tool'] == 'finish' and result.get('status') == 'DEVELOPMENT_TASK_CHECKED':
                    self.finished = True
                return result
            except BaseException as e:
                self.failure = str(e)
                self.event('UNKNOWN_AFTER_DISPATCH', {'error': str(e), 'retry_allowed': False})
                self.close()
                raise

    def _expire(self):
        with self.lock:
            if not self.closed:
                self.failure = 'absolute session lifetime expired'
                self.close()

    def collect(self):
        with self.lock:
            return {'schema': 'realm.vm-session-result.v1', 'session': self.id,
                    'profile': self.request.profile, 'task_sha256': self.request.task_sha256,
                    'installed_profile_sha256': getattr(self, 'profile_pin', None),
                    'runtime_binding': self.ready.get('binding') if self.ready else None,
                    'guest_identity': ({k: self.ready[k] for k in ('run_id','challenge')}
                                       if self.ready and self.request.profile == 'firecracker-measured' else None),
                    'state': 'CLOSED' if self.closed else 'RUNNING',
                    'actual_vm': ('STARTED_UNQUALIFIED' if self.ready and self.request.profile == 'firecracker-measured'
                                  else 'NOT_RUN'),
                    'task_finished': self.finished, 'failure': self.failure,
                    'terminal': self.terminal, 'authority': 'NONE', 'qualification': 'NOT_RUN',
                    'journal': str(self.evidence / 'session.jsonl'), 'journal_head': self.head,
                    'ordered_effects_journal': (str(self.evidence/'worker/events.jsonl')
                                                if self.request.profile == 'development-kernel-child' else None),
                    'worker_records': str(self.evidence / 'worker') if self.request.profile == 'development-kernel-child' else None,
                    'original_native_result': self.terminal.get('native_record') if self.terminal else None,
                    'native_records': '/tmp/realm-v7-coding-development-' + self.native_args.run if hasattr(self, 'native_args') else None}

    def close(self):
        with self.lock:
            if self.closed:
                return self.collect()
            if self.timer:
                self.timer.cancel()
            native = self.request.profile == 'firecracker-measured'
            code, gone = None, True
            if self.child:
                try:
                    if self.child.poll() is None:
                        if native and not self.finished:
                            # Existing native driver catches TERM and runs its
                            # held-pidfd/cgroup cleanup. Never SIGKILL its owner.
                            self.child.terminate()
                        elif not native:
                            self.child.stdin.close()
                        if native:
                            # Drain owner output while it retires; never wait on
                            # a full pipe or substitute post-hoc evidence.
                            self.native_terminal_output = self.child.communicate(timeout=180)[0].decode(errors='replace')
                        else:
                            try:
                                self.child.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                os.killpg(self.child.pid, signal.SIGKILL)
                                self.child.wait(timeout=5)
                    code = self.child.returncode
                    if not native:
                        try:
                            os.killpg(self.child.pid, 0)
                            gone = False
                            os.killpg(self.child.pid, signal.SIGKILL)
                            self.failure = self.failure or 'unexpected owned development descendants'
                        except ProcessLookupError:
                            gone = True
                except (OSError, subprocess.TimeoutExpired) as e:
                    self.failure = 'cleanup UNKNOWN: ' + str(e)
                    gone = False
                finally:
                    for channel in (self.child.stdin, self.child.stdout):
                        if channel and not channel.closed:
                            try:
                                channel.close()
                            except OSError as e:
                                self.failure = self.failure or ('channel close: ' + str(e))
            if hasattr(self,'keeper_config_fd'):
                os.close(self.keeper_config_fd); del self.keeper_config_fd
            if hasattr(self, 'stderr'):
                self.stderr.close()
            native_record = None
            if native and hasattr(self, 'native_args'):
                p = Path('/tmp/realm-v7-coding-development-' + self.native_args.run) / 'native-run-result.json'
                if p.exists():
                    native_record = worker.parse(p.read_bytes())
                # A dead wrapper alone never proves native resource closure.
                observation = (native_record or {}).get('cleanup_observation', {})
                gone = bool(code is not None and observation.get('held_vmm_exited') is True
                            and observation.get('owned_cgroup_empty') is True
                            and (observation.get('native_owner_reaped') is True
                                 if not hasattr(self,'native_keeper') else
                                 observation.get('native_owner_retained') is True))
                if hasattr(self,'native_keeper'):
                    if code == 0 and gone and not self.failure:
                        try:
                            # Inspect original Rust owners via the same live
                            # kernel descriptors. Session JSON never restores
                            # ownership or substitutes for this validation.
                            self.retained_native = self.native_keeper.complete_loan(
                                native_record.get('binding'), time.monotonic()+10)
                        except (ValueError,OSError) as error:
                            gone=False; self.failure='retained owner unavailable: '+str(error)
                    else:
                        self.native_keeper.abandon_loan('Session driver failed or closure incomplete')
                        gone=False
                if not native_record or native_record.get('status') != 'NATIVE_CODING_RETIRED_CUSTODY_AUDITED':
                    self.failure = self.failure or 'native run did not complete original custody/retirement checks'
            if not native and self.inflight == 'check':
                # Worker candidate subprocesses have their own process group.
                # A dead Worker group alone cannot attest their retirement.
                gone = False
                self.failure = self.failure or 'candidate closure UNKNOWN after interrupted check'
            retained = hasattr(self,'native_keeper')
            closure_status = 'PASS_EXECUTION_CLOSED_OWNER_RETAINED' if retained else 'PASS'
            self.terminal = {'status': closure_status if gone and code == 0 and not self.failure else 'INCOMPLETE',
                             'owner_exit': None if retained else code,
                             'driver_exit': code,
                             'owned_processes_closed': gone if not retained else False,
                             'execution_processes_closed': gone,
                             'original_owner_retained': bool(retained and gone),
                             'retained_native':getattr(self,'retained_native',None),
                             'native_record': native_record, 'evidence_retained': True}
            self.event('CLOSED', self.terminal)
            self.closed = True
            result = self.collect()
            with (self.evidence / 'result.json').open('xb') as f:
                f.write(worker.encoded(result)); f.flush(); os.fsync(f.fileno())
            self.journal.close()
            return result

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
