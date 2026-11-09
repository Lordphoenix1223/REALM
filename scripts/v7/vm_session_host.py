#!/usr/bin/env python3
"""Private session host. Not an agent-accessible executable/policy selector."""
import os
import math
import time
from pathlib import Path
import resource
import signal
import sys

# -I removes user site, PYTHONPATH and cwd imports. Only this installed tree.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import coding_worker as worker


def emit(row):
    sys.stdout.buffer.write(worker.encoded(row) + b'\n')
    sys.stdout.buffer.flush()


class SessionStop(BaseException):
    pass


def stop(signum, frame):
    # Let the original owner unwind; repeated TERM cannot interrupt cleanup.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.alarm(0)
    raise SessionStop('owned session cancelled/deadline')


def main():
    mode = sys.argv[1]
    if mode in ('native','native-retained'):
        from vm_session import Session, host_support
        if host_support('firecracker-measured')['status'] == 'UNSUPPORTED':
            raise ValueError('NOT_RUN: root Linux x86_64/KVM required')
        if len(sys.argv) != (6 if mode=='native-retained' else 5):
            raise ValueError('native lifetime bound')
        lifetime = float(sys.argv[4]) - time.monotonic()
        if not math.isfinite(lifetime) or not 0 < lifetime <= 300:
            raise ValueError('native absolute lifetime bound')
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGALRM, stop)
        signal.setitimer(signal.ITIMER_REAL, lifetime)
        validated = object.__new__(Session)
        validated._protected_profile(Path(sys.argv[2]), sys.argv[3])
        import coding_native_run as native
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGALRM, stop)
        # Independent of the caller's response loop, bounded on this host.
        # Experimental cloud lifetime still requires provider controls.
        # Keep the original alarm: profile validation time consumes the same bound.
        try:
            if mode=='native-retained':
                keeper, task = native.attach_native_keeper(int(sys.argv[5]))
                if keeper.binary != validated.native_args.native_binary.resolve() or keeper.binary_sha256 != validated.native_args.native_sha256:
                    raise ValueError('installed native executable differs from borrowed keeper')
                native.run(validated.native_args, session_ready=emit,keeper=keeper,native_task=task,
                           session_deadline=float(sys.argv[4]))
            else:
                native.run(validated.native_args, session_ready=emit)
        finally:
            signal.alarm(0)
        return
    if mode != 'development' or len(sys.argv) not in (5, 7):
        raise ValueError('unsupported private session mode')
    lifetime = float(sys.argv[4]) - time.monotonic()
    if not math.isfinite(lifetime) or not 0 < lifetime <= 300:
        raise ValueError('development absolute lifetime bound')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGALRM, stop)
    signal.setitimer(signal.ITIMER_REAL, lifetime)
    if len(sys.argv) == 7:
        worker.configure_development_task(Path(sys.argv[5]), sys.argv[6])
    w = worker.Worker(Path(sys.argv[2]), sys.argv[3])
    try:
        # Sandbox construction fails closed; no unconfined command fallback.
        sandbox = worker.Sandbox(w.candidate)
        emit({'schema': 'realm.vm-session-ready.v1', 'authority': 'NONE',
              'profile': 'development-kernel-child', 'actual_vm': 'NOT_RUN',
              'sandbox': sandbox.profile})
        while not w.done and w.count < worker.MAX_REQUESTS:
            raw = sys.stdin.buffer.readline(worker.MAX_BYTES * 3 + 1)
            if not raw:
                break
            if len(raw) > worker.MAX_BYTES * 3 or not raw.endswith(b'\n'):
                raise ValueError('request framing bound')
            try:
                result = w.request(worker.parse(raw))
            except (ValueError, OSError, TypeError) as e:
                result = {'status': 'REFUSED', 'error': str(e), 'authority': 'NONE'}
                w.event({'refusal': result, 'request_sha256': worker.digest(raw)})
            emit(result)
    finally:
        w.close()
        signal.alarm(0)


if __name__ == '__main__':
    try:
        main()
    except BaseException as e:
        print('REFUSE: ' + type(e).__name__ + ': ' + str(e), file=sys.stderr)
        sys.exit(2)
