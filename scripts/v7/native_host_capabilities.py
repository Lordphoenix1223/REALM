#!/usr/bin/env python3
"""Bounded, non-authorizing Linux x86 kernel capability experiment.

No jailer/Firecracker/guest or REALM task runs here. The original official-jailer
diagnostic and production qualification must be authorized separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time

CAPABILITIES = (
    'KVM', 'PIDFD_GETFD', 'KCMP', 'PTRACE_WAITID', 'CGROUPS', 'NAMESPACES',
    'PIVOT_ROOT', 'PRIVILEGE_DROP', 'LANDLOCK', 'SECCOMP', 'TERMINAL_CLOSURE',
)
INTERNAL = ('PTRACE_CLOSURE', 'CGROUP_CLOSURE')
VERDICTS = {'PASS', 'FAIL', 'UNSUPPORTED', 'NOT_RUN'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify(rows, exit_code, timed_out=False):
    """Project actual stage events; missing/dependency-skipped work never passes."""
    states = {name: {'status': 'NOT_RUN', 'reason': 'stage not reached'}
              for name in (*CAPABILITIES, *INTERNAL)}
    started, completed, errors = set(), set(), []
    for row in rows:
        if not isinstance(row, dict):
            errors.append('non-object diagnostic row')
            continue
        event, name = row.get('event'), row.get('capability')
        if event in ('capability_started', 'capability_result'):
            if name not in states or name == 'TERMINAL_CLOSURE':
                errors.append('unknown capability event')
                continue
            if event == 'capability_started':
                if name in started:
                    errors.append('duplicate capability start: ' + name)
                started.add(name)
                states[name] = {'status': 'NOT_RUN', 'reason': 'started; no terminal result'}
            else:
                status = row.get('status')
                if name not in started or status not in VERDICTS:
                    errors.append('invalid terminal capability result: ' + name)
                    continue
                if name in completed:
                    # Multiple failure observations are retained; a later PASS
                    # cannot repair an earlier failure or unsupported feature.
                    if status == 'PASS' or states[name]['status'] == 'PASS':
                        errors.append('contradictory capability results: ' + name)
                if states[name]['status'] not in ('FAIL', 'UNSUPPORTED'):
                    states[name] = {k: row[k] for k in ('status', 'reason', 'errno') if k in row}
                completed.add(name)
        elif row.get('test') and row.get('status') == 'FAIL':
            # A child can die by signal without executing its terminal emitter.
            for pending in started - completed:
                states[pending] = {'status': 'FAIL', 'reason': 'probe child exited without a result',
                                   'raw_wait_status': row.get('raw_wait_status')}
                completed.add(pending)
    for pending in started - completed:
        states[pending] = {'status': 'FAIL',
                           'reason': 'diagnostic timeout' if timed_out else 'missing terminal observation'}
    closure = {name: states[name] for name in INTERNAL}
    closure_statuses = [v['status'] for v in closure.values()]
    closure_status = ('FAIL' if 'FAIL' in closure_statuses else
                      'UNSUPPORTED' if 'UNSUPPORTED' in closure_statuses else
                      'PASS' if closure_statuses == ['PASS', 'PASS'] else 'NOT_RUN')
    states['TERMINAL_CLOSURE'] = {'status': closure_status,
                                 'reason': 'requires both ptrace and cgroup kill/reap/closure',
                                 'components': closure}
    capabilities = {name: states[name] for name in CAPABILITIES}
    statuses = [v['status'] for v in capabilities.values()]
    observations = [r.get('observation') for r in rows if isinstance(r, dict) and 'observation' in r]
    if all(status == 'PASS' for status in statuses):
        if sorted(observations) != ['cgroup', 'isolation', 'kvm', 'ptrace']:
            errors.append('complete PASS lacks exact raw observation groups')
        expected = {
            'kvm': {'api': 12, 'empty_vm_created_and_closed': True,
                    'vcpu_created': False, 'guest_executed': False},
            'ptrace': {'held_exec_join': True, 'waitid_pidfd_ownership': True,
                       'pidfd_getfd_cross_process': True, 'kcmp_file_shared': True,
                       'proc_task_fdinfo_maps_read': True,
                       'continued_after_exec_stop': False, 'pidfd_killed_and_reaped': True},
            'isolation': {'new_mnt_net_ipc_pid': True, 'network_route_denied': True,
                          'pid': 1, 'pivot_root_and_detach': True, 'uid': 65534,
                          'groups': 0, 'capabilities_zero': True, 'no_new_privs': True,
                          'inherited_fds_closed': True, 'landlock_allowed_and_denied': True,
                          'seccomp_denied': True},
            'cgroup': {'live_membership': True, 'memory_max': 134217728, 'pids_max': 16,
                       'cpu_max': '100000 100000', 'cgroup_kill': True,
                       'terminal_empty': True, 'fresh_subtree_removed': True},
        }
        actual = {r['observation']: r for r in rows
                  if isinstance(r, dict) and 'observation' in r}
        if any(actual.get(name, {}).get(key) != value for name, fields in expected.items()
               for key, value in fields.items()):
            errors.append('complete PASS lacks mandatory observed values')
    status = ('FAIL' if errors or timed_out or 'FAIL' in statuses else
              'UNSUPPORTED' if 'UNSUPPORTED' in statuses else
              'PASS' if all(v == 'PASS' for v in statuses) and exit_code == 0 else
              'NOT_RUN' if not started else 'FAIL')
    return {'status': status, 'capabilities': capabilities, 'capture_errors': errors,
            'kernel_exit_code': exit_code, 'diagnostic_timed_out': timed_out,
            'qualification': 'NOT_RUN', 'authority': 'NONE'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script-sha256', required=True)
    parser.add_argument('--c-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check-source-only', action='store_true')
    args = parser.parse_args()
    source = Path(__file__).resolve()
    native = source.with_suffix('.c')
    for pin in [args.script_sha256, args.c_sha256]:
        if not re.fullmatch('[0-9a-f]{64}', pin):
            raise ValueError('independent exact source pins required')
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit):
        raise ValueError('immutable Git source revision required')
    if digest(source) != args.script_sha256 or digest(native) != args.c_sha256:
        raise ValueError('REFUSE_SOURCE_PIN')
    if os.geteuid() == 0:
        # actions/checkout uses a detached HEAD for an immutable commit. Read
        # that exact value without running Git config/hooks as root or disabling
        # Git's ownership safeguard for the runner-owned checkout.
        actual = (source.parents[2] / '.git/HEAD').read_text().strip()
    else:
        actual = subprocess.check_output(
            ['git', '-C', str(source.parent), 'rev-parse', 'HEAD'], timeout=5,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}).decode().strip()
    if actual != args.source_commit:
        raise ValueError('REFUSE_SOURCE_COMMIT')
    if args.check_source_only:
        print(json.dumps({'source_pins': 'PASS', 'kernel_probe': 'NOT_RUN', 'authority': 'NONE'}))
        return 0
    if args.output is None or not args.output.is_absolute():
        raise ValueError('fresh absolute output required')
    args.output.mkdir(mode=0o700)  # Exclusive: never overwrite prior evidence.
    out = args.output
    os.umask(0o077)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
    records = []

    def save(name, raw):
        with (out / name).open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    def run(label, command, timeout):
        start = time.monotonic()
        paths = [out / (label + '.stdout'), out / (label + '.stderr')]
        streams = [path.open('xb') for path in paths]
        timed_out = False
        offsets = [0, 0]

        def forward():
            for i, path in enumerate(paths):
                with path.open('rb') as reader:
                    reader.seek(offsets[i])
                    chunk = reader.read()
                offsets[i] += len(chunk)
                if chunk:
                    os.fsync(streams[i].fileno())
                    print(label, 'stdout' if i == 0 else 'stderr',
                          chunk.decode(errors='replace'), flush=True)

        child = subprocess.Popen(command, stdout=streams[0], stderr=streams[1],
                                 env=env, start_new_session=True)
        try:
            while child.poll() is None:
                forward()
                if time.monotonic() - start >= timeout:
                    timed_out = True
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
                    break
                time.sleep(0.05)
            forward()
        finally:
            for stream in streams:
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
        stdout = paths[0].read_bytes()
        records.append({'stage': label, 'argv': [str(x) for x in command],
                        'exit_code': child.returncode, 'timed_out': timed_out,
                        'elapsed_seconds': time.monotonic() - start})
        if timed_out:
            raise TimeoutError(label + ': bounded process group killed/reaped')
        return child.returncode, stdout

    verdict = classify([], None)
    error = None
    try:
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            verdict['status'] = 'UNSUPPORTED'
            raise ValueError('unsupported host: requires native Linux x86_64; no emulation')
        if os.geteuid() != 0:
            raise ValueError('NOT_RUN: root privilege precondition absent')
        run('uname', ['/usr/bin/uname', '-a'], 3)
        memory = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemAvailable:'))
        free = os.statvfs(out).f_bavail * os.statvfs(out).f_frsize
        save('resources.json', json.dumps({'mem_available_kib': memory, 'scratch_free_bytes': free}).encode())
        if memory < 2 * 1024**2 or free < 2 * 1024**3:
            raise ValueError('requires >=2GiB available RAM and fresh scratch')
        save('initial-status.txt', Path('/proc/self/status').read_bytes())
        save('initial-mountinfo.txt', Path('/proc/self/mountinfo').read_bytes())
        compiler = Path('/usr/bin/cc').resolve(strict=True)
        save('compiler.json', json.dumps({'path': str(compiler), 'sha256': digest(compiler)}).encode())
        binary = out / 'kernel-capability-probe'
        code, _ = run('compile', [str(compiler), '-std=c11', '-O2', '-static', '-pthread',
                                 '-Wall', '-Wextra', '-Werror', str(native), '-o', str(binary)], 20)
        if code:
            raise ValueError('static compiler prerequisites failed')
        save('executed-elf.json', json.dumps({'path': str(binary), 'sha256': digest(binary)}).encode())
        code, raw = run('kernel', [str(binary), str(out)], 55)
        verdict = classify([json.loads(line) for line in raw.splitlines()], code)
    except (OSError, ValueError, StopIteration, TimeoutError, subprocess.SubprocessError) as exc:
        error = repr(exc)
        # Reopen available raw rows even after a timeout or malformed trailing
        # line. Preserve completed capabilities and never promote missing work.
        raw = out / 'kernel.stdout'
        if raw.exists():
            rows = []
            malformed = False
            for line in raw.read_bytes().splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    malformed = True
            verdict = classify(rows, None, timed_out=isinstance(exc, TimeoutError))
            if malformed:
                verdict['status'] = 'FAIL'
                verdict['capture_errors'].append('malformed or truncated diagnostic row')
        elif isinstance(exc, TimeoutError):
            verdict = classify([], None, timed_out=True)
    finally:
        result = {**verdict, 'error': error,
                  'schema': 'realm.native-host-capabilities.v1',
                  'source_commit': actual, 'script_sha256': args.script_sha256,
                  'c_sha256': args.c_sha256, 'stages': records,
                  'official_jailer': 'NOT_RUN', 'guest': 'NOT_RUN',
                  'production_qualification': 'NOT_RUN', 'destination_application': 'NOT_RUN',
                  'runtime_assets_and_pinned_rust_1_97_1': 'REQUIRE_SEPARATE_PREFLIGHT',
                  'provider_timeout': {'status': 'NOT_RUN',
                                       'reason': 'requires independent provider terminal evidence'}}
        save('RESULT.json', (json.dumps(result, indent=2) + '\n').encode())
        hashes = {p.name: digest(p) for p in out.iterdir() if p.is_file()}
        save('SHA256SUMS.json', (json.dumps(hashes, indent=2) + '\n').encode())
        print(json.dumps(result), flush=True)
    return 0 if verdict['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
