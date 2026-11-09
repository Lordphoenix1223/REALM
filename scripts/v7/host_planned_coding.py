#!/usr/bin/env python3
"""Host-planned, guest-executed DEVELOPMENT tools. No execution authority.

Only the guest owns candidate files and invokes checks. No arbitrary shell,
network tools, publisher, destination applier, model API or reference solution.
The root-owned host proxy binds its actual VMM peer and run/challenge, but is
not a qualified reference monitor or native REALM publication producer.
"""
import argparse
import os
import pathlib
import re
import socket
import stat
import struct
import sys

import coding_worker as worker

LIMIT = 128 * 1024
SCHEMA = 'realm.host-planned-coding-development.v1'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def exact(stream, size):
    parts = []
    while size:
        part = stream.recv(min(size, 65536))
        require(bool(part), 'short tool frame; dispatched outcome UNKNOWN')
        parts.append(part)
        size -= len(part)
    return b''.join(parts)


def receive(stream):
    size = struct.unpack('!I', exact(stream, 4))[0]
    require(0 < size <= LIMIT, 'tool frame limit')
    return worker.parse(exact(stream, size))


def send(stream, value):
    data = worker.encoded(value)
    require(0 < len(data) <= LIMIT, 'tool response limit')
    stream.sendall(struct.pack('!I', len(data)) + data)


def hex64(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def valid_action(action):
    require(type(action) is dict, 'object tool required')
    fields = {'list': {'tool'}, 'read': {'tool', 'path'},
              'write': {'tool', 'path', 'text'}, 'check': {'tool'}, 'finish': {'tool'}}
    tool = action.get('tool')
    require(type(tool) is str and tool in fields and set(action) == fields[tool], 'tool fields differ')
    if tool in ('read', 'write'):
        require(type(action['path']) is str and action['path'] in worker.FILES, 'path outside scope')
    if tool == 'write':
        require(type(action['text']) is str and len(action['text'].encode()) <= worker.MAX_BYTES,
                'unsupported content or size')



def launch_document(challenge, source, native_binding=None, native_subtask=None, native_inputs=None):
    document = {'authority': 'NONE', 'contract': worker.contract(),
            'execution_mode': 'host-planned', 'planner': 'external Codex',
            'guest_soft_timeout_seconds': 1620, 'source_files': source,
            'challenge': challenge,
            'command': ['/coding-init', '/usr/bin/python3', '/controller/coding_guest_boot.py']}
    if native_binding is not None:
        import coding_native_client as native
        import candidate_channel_guard as guard
        native.binding(native_binding)
        require(native_binding['task_sha256'] == worker.digest(worker.encoded(worker.contract())) and
                native_binding['worker_sha256'] == source['coding_worker.py'], 'native source/task binding differs')
        require({'coding_native_client.py', 'candidate_channel_guard.py'} <= source.keys(), 'native source pins missing')
        document.update(native_submission_binding=native_binding, candidate_channel_policy=guard.POLICY,
                        native_submission_scope='diagnostic transport only; operator labels are not capabilities')
    if native_subtask is not None:
        require(native_binding is not None and native_subtask.get('role') in ('api','cli'), 'registered native role required')
        document['native_subtask']=native_subtask
    if native_inputs is not None:
        require(type(native_inputs) is dict and set(native_inputs)=={'root','inputs'} and hex64(native_inputs['root']), 'native input envelope differs')
        inputs=native_inputs['inputs']
        require(type(inputs) is dict and set(inputs)=={'schema','submission','native_subtask','runtime_blake3','policy_blake3'}
                and inputs['schema']=='realm.native-task-inputs/v1' and inputs['submission']==native_binding
                and inputs['native_subtask']==native_subtask and hex64(inputs['runtime_blake3']) and hex64(inputs['policy_blake3']),
                'native input/runtime/predecessor binding differs')
        document['native_inputs']=native_inputs
    return document


def guest(base, launch, connection=None):
    run_id = worker.digest(worker.encoded(launch))
    challenge = launch['challenge']
    report = {'authority': 'NONE', 'realm_artifact': None, 'status': 'NOT_COMPLETE',
              'planner': 'external Codex; guest executes every candidate operation/check',
              'run_id': run_id, 'turns': []}
    (base / 'agent-report.json').write_bytes(worker.encoded(report))
    native_binding = launch.get('native_submission_binding')
    w = worker.Worker(base / 'run', worker.digest(worker.encoded(worker.contract())),
                      evidence_channel_guard=native_binding is not None,native_subtask=launch.get('native_subtask'))
    initial = w.tree()
    try:
        supplied=connection is not None
        with (connection if supplied else socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)) as connection:
            connection.settimeout(1200)
            if not supplied:connection.connect((socket.VMADDR_CID_HOST, 9001))
            hello={'schema': SCHEMA, 'authority': 'NONE', 'run_id': run_id,
                 'challenge': challenge, 'worker_sha256': launch['source_files']['coding_worker.py'],
                 'protocol_sha256': launch['source_files']['host_planned_coding.py']}
            if 'native_inputs' in launch:hello['task_inputs_blake3']=launch['native_inputs']['root']
            send(connection,hello)
            for sequence in range(1, worker.MAX_REQUESTS + 1):
                message = receive(connection)
                require(type(message) is dict and set(message) ==
                        {'run_id', 'challenge', 'sequence', 'request_id', 'action'}, 'guest tool envelope')
                require(message['run_id'] == run_id and message['challenge'] == challenge and
                        type(message['sequence']) is int and message['sequence'] == sequence and
                        hex64(message['request_id']), 'guest tool binding/order differs')
                action = message['action']
                try:
                    valid_action(action)
                    if action['tool'] == 'finish':
                        step=launch.get('native_subtask')
                        required=('totals.py','test_totals.py') if step and step['role']=='api' else ('report.py','test_totals.py') if step else worker.FILES
                        require(all(w.tree()[name] != initial[name] for name in required),
                                'registered changed-file precondition differs')
                    result = w.request(action)
                except (ValueError, OSError, TypeError) as error:
                    result = {'status': 'REFUSED', 'authority': 'NONE', 'error': str(error)}
                    w.event({'refusal': result, 'request_sha256': worker.digest(worker.encoded(action))})
                reply = {'run_id': run_id, 'challenge': challenge, 'sequence': sequence,
                         'request_id': message['request_id'], 'authority': 'NONE', 'result': result}
                report['turns'].append({'request_id': message['request_id'], 'action': action, 'result': result})
                if w.done:
                    report.update(status='DEVELOPMENT_TASK_CHECKED', files=w.tree())
                (base / 'agent-report.json').write_bytes(worker.encoded(report))
                send(connection, reply)
                if w.done:
                    break
            require(w.done, 'guest tool request limit; task unfinished')
        if native_binding is not None:
            import coding_native_client as native
            try:
                receipt = native.submit_checked_worker(w, native_binding)
            except (native.NotDispatched, native.DeliveryUnknown) as error:
                receipt = {'authority': 'NONE', 'realm_artifact': None,
                           'status': type(error).__name__, 'error': str(error)}
                report.update(status='DEVELOPMENT_TASK_CHECKED_NATIVE_INCOMPLETE')
            report['native_submission'] = receipt
            (base / 'agent-report.json').write_bytes(worker.encoded(report))
    finally:
        w.close()


class PlannerProxy:
    """Diagnostic relay. Root operator trusted; guest replies never authorize."""
    def __init__(self, root, run_dir, uid, gid, *, guest_path=None):
        self.root, self.uid, self.gid = root, uid, gid
        self.guest_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.guest_path = run_dir / 'vsock_9001' if guest_path is None else pathlib.Path(guest_path)
        require(self.guest_path.parent == run_dir and
                self.guest_path.name in ('vsock_9001', 'realm.task_9001'), 'unsupported control endpoint')
        self.guest_listener.bind(str(self.guest_path))
        os.chown(self.guest_path, uid, gid)
        self.guest_path.chmod(0o600)
        self.guest_listener.listen(1)
        self.local = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.local_path = root / 'planner.sock'
        self.local.bind(str(self.local_path))
        self.local_path.chmod(0o600)
        self.local.listen(1)
        self.connection = None
        self.identity = None
        self.seen = set()
        self.sequence = 0
        self.failed = False
        self.journal = (root / 'planner-transport.jsonl').open('xb')
        os.chmod(self.journal.name, 0o600)

    def event(self, row):
        self.journal.write(worker.encoded(row) + b'\n')
        self.journal.flush()
        os.fsync(self.journal.fileno())

    def accept_guest(self, pid, spec, pins):
        require(self.connection is None, 'guest reconnect refused')
        connection, _ = self.guest_listener.accept()
        try:
            peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer == (pid, self.uid, self.gid), 'tool connection is not owned measured VMM peer')
            connection.settimeout(90)
            hello = receive(connection)
            require(type(hello) is dict and set(hello) == {'schema', 'authority', 'run_id', 'challenge',
                    'worker_sha256', 'protocol_sha256'} and hello['schema'] == SCHEMA and
                    hello['authority'] == 'NONE' and hello['run_id'] == spec['planner_run_id'] and
                    hello['challenge'] == spec['challenge'] and hello['worker_sha256'] == pins['worker'] and
                    hello['protocol_sha256'] == pins['protocol'], 'tool hello differs from pinned guest')
            self.identity = hello
            self.connection = connection
            (self.root / 'planner-hello.json').write_bytes(worker.encoded(hello))
            os.chmod(self.root / 'planner-hello.json', 0o600)
            self.event({'phase': 'GUEST_CONNECTED', 'peer': peer, 'hello': hello, 'authority': 'NONE'})
        except BaseException:
            connection.close()
            raise

    def serve_local(self):
        local, _ = self.local.accept()
        with local:
            local.settimeout(90)
            dispatched = False
            request = None
            try:
                peer = struct.unpack('3i', local.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(peer[1] == 0, 'root operator tool client required')
                require(self.connection is not None and not self.failed, 'guest not ready or transport failed')
                request = receive(local)
                require(type(request) is dict and set(request) ==
                        {'run_id', 'challenge', 'request_id', 'action'}, 'operator tool fields differ')
                require(request['run_id'] == self.identity['run_id'] and
                        request['challenge'] == self.identity['challenge'] and hex64(request['request_id']) and
                        request['request_id'] not in self.seen and self.sequence < worker.MAX_REQUESTS,
                        'operator run/challenge/request replay differs')
                valid_action(request['action'])
                self.seen.add(request['request_id'])
                self.sequence += 1
                message = {**request, 'sequence': self.sequence}
                self.event({'phase': 'DISPATCH_INTENT', 'message': message, 'authority': 'NONE'})
                dispatched = True
                send(self.connection, message)
                reply = receive(self.connection)
                require(type(reply) is dict and set(reply) ==
                        {'run_id', 'challenge', 'request_id', 'sequence', 'authority', 'result'} and
                        all(reply[k] == message[k] for k in ('run_id', 'challenge', 'request_id', 'sequence')) and
                        type(reply['sequence']) is int and reply['authority'] == 'NONE', 'guest reply identity differs')
                self.event({'phase': 'GUEST_REPLY', 'reply': reply, 'authority': 'NONE'})
                send(local, reply)
            except (ValueError, OSError, KeyError, TypeError) as error:
                if dispatched:
                    self.failed = True
                result = {'status': 'UNKNOWN' if dispatched else 'REFUSED_BEFORE_DISPATCH',
                          'authority': 'NONE', 'realm_artifact': None, 'error': str(error)}
                self.event({'phase': result['status'], 'request': request, 'result': result})
                try:
                    send(local, result)
                except OSError:
                    pass

    def detach_native_transports(self):
        """Move actual guest socket ownership to the native closure caller.

        The local operator listener and durable journal stop here. The caller
        must close both returned aliases after SCM_RIGHTS transfer; this does
        not attest to complete external planner inputs or create authority.
        """
        require(self.connection is not None and not self.failed,
                'healthy accepted guest transport required for native handoff')
        self.local.close()
        self.journal.flush()
        os.fsync(self.journal.fileno())
        self.journal.close()
        self.local_path.unlink()
        transports = self.guest_listener, self.connection
        self.guest_listener = self.connection = None
        return transports

    def close(self):
        if self.connection:
            self.connection.close()
        if self.guest_listener:
            self.guest_listener.close()
        self.local.close()
        self.journal.close()
        self.local_path.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--socket', required=True, type=pathlib.Path)
    p.add_argument('--request', required=True, type=pathlib.Path)
    p.add_argument('--ephemeral-run-root', action='store_true',
                   help='explicit diagnostic socket in an exact fresh root-owned private /tmp run root')
    args = p.parse_args()
    require(os.geteuid() == 0, 'root operator client required')
    if args.ephemeral_run_root:
        require(bool(re.fullmatch(r'/tmp/realm-v7-coding-development-[0-9]{3}/planner.sock', str(args.socket))),
                'unsupported scratch planner endpoint')
        owned = args.socket.parent.lstat()
        require(stat.S_ISDIR(owned.st_mode) and owned.st_uid == 0 and
                stat.S_IMODE(owned.st_mode) == 0o700 and not args.socket.parent.is_symlink(),
                'scratch run root is not private')
    for path in [args.socket, *args.socket.parents]:
        m = path.lstat()
        sticky_scratch_parent = (args.ephemeral_run_root and path == pathlib.Path('/tmp') and
                                stat.S_ISDIR(m.st_mode) and m.st_mode & stat.S_ISVTX)
        require(not path.is_symlink() and m.st_uid == 0 and
                (not m.st_mode & 0o022 or sticky_scratch_parent), 'unprotected planner endpoint')
    require(stat.S_ISSOCK(args.socket.lstat().st_mode), 'planner socket required')
    # The request is operator input, never executable on this host.
    require(args.request.stat().st_size <= LIMIT and not args.request.is_symlink(), 'request file limit')
    request = worker.parse(args.request.read_bytes())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(90)
        connection.connect(str(args.socket))
        send(connection, request)
        try:
            result = receive(connection)
        except (ValueError, OSError) as error:
            result = {'status': 'UNKNOWN', 'authority': 'NONE', 'realm_artifact': None, 'error': str(error)}
        print(worker.encoded(result).decode())


if __name__ == '__main__':
    main()
