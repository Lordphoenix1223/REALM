#!/usr/bin/env python3
"""Development guest entry and bounded raw-evidence transport. No REALM issuer."""
import hashlib
import io
import json
import pathlib
import socket
import signal
import stat
import struct
import sys
import tarfile
import traceback

sys.path.insert(0, '/controller')
import offline_coding_agent as agent
import coding_worker as worker
from fetch_offline_coder import assets_for

ROOT = pathlib.Path('/run/realm-task')
MAX_PAYLOAD = 64 * 1024 * 1024


class GuestDeadline(RuntimeError):
    """Not a per-request timeout; the controller must unwind and export."""


def bounded_agent(seconds):
    # Stop early enough to close the owned model process and export failed RAM
    # evidence before the outer VMM deadline. No existing timer is displaced.
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise ValueError('existing guest timer; refuse replacement')
    previous = signal.getsignal(signal.SIGALRM)
    previous_stop = signal.getsignal(signal.SIGINT)
    def timeout(signum, _frame):
        reason = 'guest stop signal received' if signum == signal.SIGINT else 'guest soft deadline exceeded'
        raise GuestDeadline(reason + '; export failure evidence')
    signal.signal(signal.SIGALRM, timeout)
    signal.signal(signal.SIGINT, timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return agent.inside()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        signal.signal(signal.SIGINT, previous_stop)


def main():
    # Explicit guest-local CAD mode: the future x86 stop action must signal
    # PID 1 rather than reboot and discard its RAM evidence. Not authority.
    stop_mode = pathlib.Path('/proc/sys/kernel/ctrl-alt-del')
    stop_mode.write_text('0\n')
    if stop_mode.read_text().strip() != '0':
        raise ValueError('guest stop mode did not bind SIGINT delivery')
    spec = json.loads(pathlib.Path('/controller/guest-inputs.json').read_text())
    if spec.get('execution_mode') == 'immutable-native-bootstrap':
        import host_planned_coding as tools
        connection=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
        connection.settimeout(120)
        connection.connect((socket.VMADDR_CID_HOST,9001))
        try:
            envelope=tools.receive(connection)
            if type(envelope) is not dict or set(envelope)!={'root','inputs'}:raise ValueError('native input envelope')
            data=envelope['inputs']
            spec={'execution_mode':'host-planned','raw_handoff_protocol':'durable-ack-cad-v1','authority':'NONE',
                  'challenge':data['submission']['challenge_root'],'native_submission_binding':data['submission'],
                  'native_subtask':data['native_subtask'],'native_inputs':envelope}
            return host_planned_main(spec,connection)
        finally:connection.close()
    if spec.get('execution_mode') == 'host-planned':
        return host_planned_main(spec)
    agent.MODEL_NAME = spec['model_name']
    agent.ASSETS = assets_for(agent.MODEL_NAME)
    agent.CONTEXT = 'firecracker-development-guest'
    source = {name: agent.file_hash(pathlib.Path('/controller') / name)
              for name in ('offline_coding_agent.py', 'coding_worker.py', 'fetch_offline_coder.py')}
    source['coding_guest_boot.py'] = agent.file_hash(pathlib.Path(__file__))
    soft_timeout = agent.contract()['run_timeout_seconds'] - 180
    launch = {'authority': 'NONE', 'guest_soft_timeout_seconds': soft_timeout,
              'contract': agent.contract(),
              'approval': worker.digest(worker.encoded(agent.contract())),
              'source_files': source, 'challenge': spec['challenge'],
              'command': ['/coding-init', '/usr/bin/python3', '/controller/coding_guest_boot.py']}
    (ROOT / 'launch.json').write_bytes(worker.encoded(launch))
    print('DEVELOPMENT_CODING_CONTROLLER_START; AUTHORITY=NONE', flush=True)
    try:
        bounded_agent(soft_timeout)
    except Exception as error:
        (ROOT / 'guest-failure.txt').write_text(traceback.format_exc())
        report_path = ROOT / 'agent-report.json'
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        report.update(status='NOT_COMPLETE', authority='NONE', realm_artifact=None,
                      failure=type(error).__name__ + ': ' + str(error))
        report_path.write_bytes(worker.encoded(report))
        print('DEVELOPMENT_CODING_CONTROLLER_FAILED; AUTHORITY=NONE', flush=True)
    export_raw(spec)


def require_raw_ack(connection, header):
    # This proves only bounded diagnostic receipt, never publication authority.
    import host_planned_coding as tools
    ack = tools.receive(connection)
    expected = {'schema': 'realm.coding-raw-received.v1', 'authority': 'NONE',
                'challenge': header['challenge'], 'sha256': header['sha256'],
                'size': header['size']}
    if worker.encoded(ack) != worker.encoded(expected):
        raise ValueError('raw handoff acknowledgment differs; outcome UNKNOWN')


def export_raw(spec):
    # This is only a raw snapshot. The receiver cannot turn it into authority.
    buffer = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for path in sorted(ROOT.rglob('*')):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('unsupported raw evidence object')
            total += info.st_size
            if total > MAX_PAYLOAD:
                raise ValueError('raw evidence size limit')
            item = tarfile.TarInfo(str(path.relative_to(ROOT)))
            item.size = info.st_size
            item.mode = 0o600
            with path.open('rb') as stream:
                archive.addfile(item, stream)
    data = buffer.getvalue()
    if len(data) > MAX_PAYLOAD:
        raise ValueError('transport size limit')
    acknowledged = spec.get('raw_handoff_protocol') == 'durable-ack-cad-v1'
    header_fields = {'schema': 'realm.coding-guest-development-raw.v2' if acknowledged else 'realm.coding-guest-development-raw.v1',
        'authority': 'NONE', 'realm_artifact': None, 'challenge': spec['challenge'],
        'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    header = worker.encoded(header_fields)
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        connection.connect((socket.VMADDR_CID_HOST, 9000))
        connection.sendall(struct.pack('!I', len(header)) + header + data)
        if acknowledged:
            require_raw_ack(connection, header_fields)
    print(('DEVELOPMENT_RAW_ACKNOWLEDGED' if acknowledged else 'DEVELOPMENT_RAW_SENT') + '; AUTHORITY=NONE', flush=True)


def host_planned_main(spec, connection=None):
    import host_planned_coding as tools
    names = ['host_planned_coding.py', 'coding_worker.py', 'coding_guest_boot.py']
    if spec.get('native_submission_binding') is not None:
        names += ['coding_native_client.py', 'candidate_channel_guard.py','coding_task_verifier.py','development_task_oracles.py']
    source = {name: agent.file_hash(pathlib.Path('/controller') / name) for name in names}
    launch = tools.launch_document(spec['challenge'], source, spec.get('native_submission_binding'),spec.get('native_subtask'),spec.get('native_inputs'))
    (ROOT / 'launch.json').write_bytes(worker.encoded(launch))
    print('HOST_PLANNED_GUEST_TOOLS_START; AUTHORITY=NONE', flush=True)
    previous = signal.getsignal(signal.SIGALRM)
    previous_stop = signal.getsignal(signal.SIGINT)
    def stop(_signum, _frame):
        raise GuestDeadline('host-planned guest stop/deadline; export diagnostics')
    signal.signal(signal.SIGALRM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.setitimer(signal.ITIMER_REAL, 1620)
    try:
        tools.guest(ROOT, launch,connection)
    except Exception as error:
        (ROOT / 'guest-failure.txt').write_text(traceback.format_exc())
        report_path = ROOT / 'agent-report.json'
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        report.update(status='NOT_COMPLETE', authority='NONE', realm_artifact=None,
                      failure=type(error).__name__ + ': ' + str(error))
        report_path.write_bytes(worker.encoded(report))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        signal.signal(signal.SIGINT, previous_stop)
    export_raw(spec)


if __name__ == '__main__':
    main()
