#!/usr/bin/env python3
"""Trusted Stage 8 sandbox supervisor. No model, shell tools, native authority issuer.

The executor supplies bounded protocol requests only. The controller supplies the
independent Grant; a proposal from the broker is never itself authorization.
All effects use the Rust ordered-create engine. Unsupported sandbox startup or
conformance refuses BEFORE activation. Root/hostile same-UID concurrency and
power loss are outside this exclusive-operator development qualification.
"""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from coding_worker import Sandbox, encoded, parse

MAC_RUNTIME_PROFILE = 'realm.stage8.macos-seatbelt-stdio.v1'
LINUX_RUNTIME_PROFILE = 'realm.stage8.linux-bwrap-seccomp-stdio.v1'


def require(ok, message):
    if not ok:
        raise ValueError(message)


# Fixed syscall probes, independently checked against protected sentinels by the
# test/controller. Reads for the interpreter and empty /work are explicit runtime
# capabilities inherited from Sandbox. Destination/policy are never mounted.
PROBE = '''import os,json,socket,subprocess,sys
c=json.load(sys.stdin); results={}
def attempt(name, fn):
    try:
        fn()
    except OSError as e:
        results[name]={"outcome":"DENIED","errno":e.errno,"error":str(e)}
    else:
        results[name]={"outcome":"ALLOWED","errno":None}
attempt("extra-write",lambda:os.open(c["extra"],os.O_WRONLY|os.O_CREAT,0o600))
attempt("protected-read",lambda:open(c["protected"],"rb").read())
attempt("shell",lambda:subprocess.run(["/bin/sh","-c","echo breached > "+c["shell_marker"]],check=False))
attempt("direct-shell-exec",lambda:os.execv("/bin/sh",["/bin/sh","-c","echo breached > "+c["shell_marker"]]))
attempt("network",lambda:socket.create_connection(("127.0.0.1",c["port"]),0.25))
attempt("modify",lambda:os.open(c["protected"],os.O_WRONLY|os.O_TRUNC))
attempt("delete",lambda:os.unlink(c["protected"]))
attempt("artifact-replace",lambda:os.replace(c["replacement"],c["artifact"]))
attempt("policy-write",lambda:os.open(c["policy"],os.O_WRONLY|os.O_TRUNC))
attempt("verification-write",lambda:os.open(c["verification"],os.O_WRONLY|os.O_TRUNC))
attempt("symlink",lambda:os.symlink(c["protected"],c["link"]))
attempt("traversal",lambda:os.open(c["traversal"],os.O_WRONLY|os.O_CREAT,0o600))
attempt("signal-broker",lambda:os.kill(c["broker_pid"],signal.SIGKILL))
print(json.dumps(results))
'''.replace('import os,json,socket,subprocess,sys', 'import os,json,socket,subprocess,sys,signal')


class Supervisor:
    """Trusted controller interface. Do not run this object in the executor."""
    def __init__(self, broker, arguments, runtime_directory):
        runtime_directory = Path(runtime_directory)
        require(runtime_directory.is_dir() and not list(runtime_directory.iterdir()),
                'Stage 8 runtime directory must be empty')
        self.sandbox = Sandbox(runtime_directory)
        self.guard_source = None
        if self.sandbox.backend == 'Darwin':
            self.runtime_profile = MAC_RUNTIME_PROFILE
            self.sandbox.profile = self.sandbox.profile.replace('(subpath "/opt/homebrew/Cellar")', '')
            self.sandbox.profile += '(deny signal)(deny ipc*)(deny mach-lookup)'
            self.sandbox.prefix[2] = self.sandbox.profile
        elif self.sandbox.backend == 'Linux':
            import candidate_channel_guard as guard
            guard.stage8_instructions()  # Unknown ABIs refuse before broker preparation.
            self.runtime_profile = LINUX_RUNTIME_PROFILE
            self.guard_source = Path(guard.__file__).read_text()
            # Reuse the original bwrap namespace owner, narrow its runtime-read
            # roots, then install the immutable syscall policy AFTER Python
            # startup and BEFORE any executor/probe source runs. No fallback.
            prefix = self.sandbox.prefix[:self.sandbox.prefix.index('--ro-bind')]
            # This profile categorically forbids executor-created descendants.
            # Run it as namespace PID 1 rather than adding a separate bwrap
            # init whose orphaned zombie would depend on an external reaper.
            prefix += ['--as-pid-1']
            require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal')
                    and Path('/proc/self/task').is_dir(), 'UNSUPPORTED: owned Linux launcher cleanup')
            self.sandbox.linux_stage8_pid1 = True
            roots = [Path('/usr/lib'), Path('/usr/lib64')]
            if str(self.sandbox.python).startswith('/usr/local/'):
                roots.append(Path('/usr/local/lib'))
            for path in roots + [self.sandbox.python, Path('/etc/ld.so.cache')]:
                if path.exists(): prefix += ['--ro-bind', str(path), str(path)]
            for path in (Path('/lib'), Path('/lib64')):
                if path.is_symlink(): prefix += ['--symlink', os.readlink(path), str(path)]
                elif path.exists(): prefix += ['--ro-bind', str(path), str(path)]
            prefix += ['--dev', '/dev', '--tmpfs', '/tmp',
                       '--ro-bind', str(runtime_directory.resolve()), '/work', '--chdir', '/work',
                       str(self.sandbox.python), '-I', '-B', '-S']
            self.sandbox.prefix = prefix
            self.sandbox.profile = 'bubblewrap:unshare-all,executor-pid1,no-proc,readonly-runtime-and-work,no-capabilities,close-range-stdio-only,' + guard.STAGE8_POLICY
        else:
            raise ValueError('UNSUPPORTED: strict Stage8 kernel backend')
        self.process = subprocess.Popen([str(broker), *map(str, arguments)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.started = time.monotonic()
        try:
            self.prepared = self.read()
            require(self.prepared['status'] == 'PREPARED_REQUIRES_INDEPENDENT_GRANT', 'broker did not prepare')
        except BaseException:
            self.close()
            raise
        self.active = False
        self.probed = False

    def read(self):
        require(bool(self.selector.select(5)), 'broker timeout; not a success')
        line = self.process.stdout.readline(65537)
        if not line:
            error = self.process.stderr.read(65536).decode(errors='replace')
            raise ValueError('broker refused: ' + error)
        require(len(line) <= 65536 and line.endswith(b'\n'), 'broker frame size')
        return parse(line)

    def send(self, value):
        require(time.monotonic() - self.started < 30, 'supervisor time budget')
        raw = encoded(value) + b'\n'
        require(len(raw) <= 4096, 'request byte budget')
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        return self.read()

    def probe(self, context):
        context = dict(context, broker_pid=self.process.pid)
        data = encoded(context)
        require(len(data) <= 32768, 'Stage8 probe input byte budget')
        code, out, err = self.sandbox.execute(self.guarded(PROBE), data)
        require(code == 0, 'UNSUPPORTED: sandbox probe failed: ' + err.decode(errors='replace'))
        results = parse(out)
        denied = (1, 2, 13) if self.sandbox.backend == 'Linux' else (1, 13)
        require(len(results) == 13 and all(r['outcome'] == 'DENIED' and r['errno'] in denied
                    for r in results.values()), 'REFUSE: sandbox capability probe allowed an operation')
        self.probed = True
        return {'exit': code, 'stdout': out.decode(), 'stderr': err.decode(), 'results': results,
                'profile': self.sandbox.profile, 'python': str(self.sandbox.python)}

    def guarded(self, source):
        if self.guard_source is None:
            return source
        return ('import os,sys,json,socket,subprocess,time,resource,fcntl,ctypes\n'
                '_realm_guard={}\nexec(compile(' + repr(self.guard_source) +
                ',"<installed-stage8-guard>","exec"),_realm_guard)\n'
                '_realm_guard["install_stage8"]()\nexec(compile(' + repr(source) +
                ',"<stage8-executor>","exec"),{"__name__":"__main__"})\n')

    def activate(self, grant):
        require(self.probed and not self.active, 'kernel conformance required before independent grant')
        require(grant['runtime_profile'] == self.runtime_profile
                and grant['child_cpu_seconds'] == 2 and grant['child_wall_millis'] == 3000
                and grant['child_output_bytes'] == 32768 and grant['broker_wall_seconds'] == 10,
                'UNSUPPORTED: requested runtime limits/profile')
        result = self.send(grant)
        require(result['status'] == 'ACTIVE', 'grant refused')
        self.active = True
        return result

    def execute(self, source, context):
        require(self.active, 'session not active')
        try:
            require(type(source) is str and 0 < len(source.encode()) <= 32768,
                    'Stage8 executor source byte budget')
            data = encoded(context)
            require(len(data) <= 32768, 'Stage8 executor input byte budget')
            code, out, err = self.sandbox.execute(self.guarded(source), data)
            require(code == 0, 'executor failed; session cannot become success: ' + err.decode(errors='replace'))
            frames = out.splitlines()
            require(1 <= len(frames) <= 8, 'executor request budget')
            requests = [parse(line) for line in frames]
            results = [self.send(request) for request in requests]
            return {'exit': code, 'stdout': out.decode(), 'stderr': err.decode(), 'results': results}
        except BaseException:
            self.active = False
            self.close()
            raise

    def verify(self):
        require(self.active, 'failed executor session cannot verify')
        self.active = False
        self.process.stdin.close()
        return self.read()

    def close(self):
        if hasattr(self, 'process'):
            if self.process.poll() is None:
                try:
                    # The trusted Rust broker never spawns descendants.
                    self.process.kill()
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Darwin may report EPERM for a just-exited zombie.
                    if self.process.poll() is None:
                        raise
            self.process.wait(timeout=5)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if not stream.closed:
                    stream.close()
        if hasattr(self, 'selector'):
            self.selector.close()


def apply_development_procedure(broker, artifact, artifact_pin, expectations, expectations_pin,
                                procedure, procedure_pin, output, *, attempt_history_pin):
    """Actual Stage7 -> Stage8 handoff, under explicit disposable test permission.

    Pins come from the trusted controller's original publisher output. There is
    no narrative-to-proof translation, native proof issuer or production grant.
    The existing Rust procedure verifier runs before any destination allocation.
    """
    import hashlib
    import socket
    from verify_stage8_state import outputs
    broker = Path(broker).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(mode=0o700)
    def save(name, value):
        path = output/name
        with path.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded(value) + b'\n')
            stream.flush(); os.fsync(stream.fileno())
    def b3(raw):
        return subprocess.check_output([str(broker), 'hash-stdin'], input=raw, timeout=5).decode().strip()
    raw = Path(artifact).read_bytes()
    external = Path(expectations).read_bytes()
    proc_raw = Path(procedure).read_bytes()
    require(b3(raw) == artifact_pin and b3(external) == expectations_pin and b3(proc_raw) == procedure_pin,
            'Stage7 external artifact/expectations/procedure pin differs')
    expected = outputs(raw)
    task_pin = parse(external)['task_sha256']
    source_procedure = parse(proc_raw)
    # Reuse Stage2/3's independent audit against a pin retained OUTSIDE the
    # artifact; a missing, omitted or foreign attempt history cannot be promoted.
    from project_history import audit_procedure
    history = source_procedure['metadata']['attempt_history']
    require(source_procedure['metadata']['attempt_history_sha256'] == attempt_history_pin,
            'Stage8 external attempt-history binding differs')
    history_check = audit_procedure(source_procedure, attempt_history_pin)
    save('attempt-history-audit.json', history_check)
    frozen = output/'frozen.realm'
    with frozen.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    runtime, parent, protected = output/'runtime', output/'operator', output/'protected'
    for path in (runtime, parent, protected): path.mkdir(mode=0o700)
    sentinel = protected/'canary'; sentinel.write_bytes(b'NO_PRODUCTION_EXECUTION_AUTHORITY')
    policy = protected/'policy.json'; policy.write_bytes(encoded({'authority':'NONE'}))
    verification = protected/'verification.json'; verification.write_bytes(encoded({'status':'INCOMPLETE'}))
    replacement = protected/'replacement'; replacement.write_bytes(b'UNAUTHORIZED')
    protected_before = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in protected.iterdir()}
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(.01)
    supervisor = None
    try:
        supervisor = Supervisor(broker, ['disposable-procedure', frozen, artifact_pin,
            Path(expectations).absolute(), expectations_pin, procedure_pin, parent], runtime)
        prepared = supervisor.prepared
        save('prepared.json', prepared)
        destination, state = Path(prepared['destination']), Path(prepared['state'])
        probe = supervisor.probe({'protected':str(sentinel), 'extra':str(destination/'extra'),
            'shell_marker':str(protected/'shell-marker'), 'port':listener.getsockname()[1],
            'artifact':str(frozen), 'replacement':str(replacement), 'policy':str(policy),
            'verification':str(verification), 'link':str(destination/'totals.py'),
            'traversal':str(destination/'../escape')})
        save('kernel-probe.json', probe)
        grant = prepared['grant_proposal']
        require(grant['artifact_blake3'] == artifact_pin and grant['task_sha256'] == task_pin
                and prepared['plan'].get('authorization') is None, 'Stage8 proposal identity differs')
        operations = prepared['plan']['operations']
        require(len(operations) == len(source_procedure['operations']) == 3, 'Stage8 operation scope differs')
        for i, (op, source_op) in enumerate(zip(operations, source_procedure['operations'])):
            require(source_op['kind'] == 'create-file' and op == {key:source_op[key] for key in op}
                    and op['index'] == i and op['requires_completed'] == i
                    and op['bytes'] == len(expected[op['path']])
                    and op['content_blake3'] == b3(expected[op['path']]), 'Stage8 operation differs from frozen Stage7 procedure')
        require(grant['destination']['inode'] == destination.stat().st_ino
                and grant['destination']['device'] == destination.stat().st_dev
                and grant['state']['inode'] == state.stat().st_ino, 'operator destination/state identity differs')
        save('independent-disposable-grant.json', grant)
        supervisor.activate(grant)
        # Send the ACTUAL development provenance and separate disposable grant
        # to the existing production endpoint. They are never reconstructed as
        # native proof/policy. Rejection at typed intake is the expected result.
        native_provenance = Path(artifact).parent/'session/result.json'
        production_command = [str(broker), 'production', str(frozen), str(native_provenance),
            str(output/'independent-disposable-grant.json'), str(protected), str(state)]
        refused = subprocess.run(production_command, capture_output=True, timeout=10)
        save('production-refusal.json', {'command':production_command, 'exit':refused.returncode,
            'stdout':refused.stdout.decode(), 'stderr':refused.stderr.decode(),
            'proof_class':'ACTUAL_UNQUALIFIED_DEVELOPMENT_SESSION_RECORD',
            'policy_class':'ACTUAL_SEPARATE_DISPOSABLE_GRANT',
            'native_verifier':'NOT_RUN_NO_NATIVE_PROOF_OR_POLICY'})
        require(refused.returncode != 0 and not refused.stdout, 'unqualified production authorization accepted')
        requests = [{'approval':grant['approval'], 'operation':op} for op in operations]
        # Trusted scheduling, untrusted isolated request process, immutable bytes
        # in the broker. The process cannot write the destination or a verdict.
        source = 'import json,sys\nc=json.load(sys.stdin)\nfor request in c["requests"]: print(json.dumps(request))\n'
        executed = supervisor.execute(source, {'requests':requests})
        save('executor.json', executed)
        require(all(r['status'] in ('STEP_COMPLETE', 'COMPLETE_PENDING_INDEPENDENT_VERIFICATION')
                    and r['authority'] == 'NONE' for r in executed['results']), 'Stage8 step refused')
        observed = supervisor.verify()
        save('broker-final.json', observed)
        require(observed['status'] == 'VERIFIED_FINAL_STATE' and observed['authority'] == 'NONE', 'Stage8 physical verification failed')
        command = [sys.executable, '-B', Path(__file__).with_name('verify_stage8_state.py'), frozen, destination, state, broker]
        independent = subprocess.run(list(map(str, command)), capture_output=True, timeout=15)
        save('independent-verifier.json', {'command':list(map(str,command)), 'exit':independent.returncode,
                                         'stdout':independent.stdout.decode(), 'stderr':independent.stderr.decode()})
        require(independent.returncode == 0, 'independent final-state process refused')
        try: listener.accept()
        except TimeoutError: pass
        else: raise ValueError('Stage8 executor made a network connection')
        protected_after = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in protected.iterdir()}
        require(protected_after == protected_before, 'protected destination changed')
        result = {'status':'PASS_STAGE8_DISPOSABLE_ENFORCEMENT', 'authority':'NONE',
            'artifact':str(Path(artifact).absolute()), 'artifact_blake3':artifact_pin,
            'expectations_blake3':expectations_pin,'procedure_blake3':procedure_pin,
            'destination':str(destination), 'state':str(state), 'protected_before':protected_before,
            'protected_after':protected_after, 'independent':parse(independent.stdout),
            'production_application':'NOT_RUN','native_qualification':'NOT_RUN',
            'production_authorization':'REFUSE_UNQUALIFIED_DEVELOPMENT_RECORDS',
            'attempt_history_sha256':attempt_history_pin, 'history_check':history_check,
            'runtime_profile':grant['runtime_profile'], 'broker_sha256':hashlib.sha256(broker.read_bytes()).hexdigest()}
        save('RESULT.json', result)
        return result
    finally:
        if supervisor is not None: supervisor.close()
        listener.close()
