"""Owned diagnostic transport launcher using existing native broker/custodian.

Never issues measured execution, semantics, complete mediation, .realm or apply.
The root operator is trusted; no planner confinement is inferred.
"""
import os
import fcntl
import pathlib
import socket
import struct
import subprocess

import coding_worker as worker


def blocking_handoff(stream):
    # Python timeout mode sets O_NONBLOCK on the shared open description.
    # A native synchronous reader must not inherit that mode accidentally.
    before = fcntl.fcntl(stream.fileno(), fcntl.F_GETFL)
    stream.settimeout(None)
    after = fcntl.fcntl(stream.fileno(), fcntl.F_GETFL)
    if after & os.O_NONBLOCK or stream.gettimeout() is not None:
        raise ValueError('native custody socket remains nonblocking')
    return {'before_flags': before, 'after_flags': after, 'authority': 'NONE'}


class NativeProbe:
    def __init__(self, root, run_dir, spec, binaries):
        self.root = root / 'native'
        self.root.mkdir(mode=0o700)
        self.spec, self.binaries = spec, binaries
        self.children = []
        self.logs = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.path = run_dir / 'vsock_9002'
        self.listener.bind(str(self.path))
        os.chown(self.path, spec['vmm_uid'], spec['vmm_gid'])
        self.path.chmod(0o600)
        self.listener.listen(1)
        self.dispatched = False

    def accept(self, pid, pidfd):
        if self.dispatched:
            raise ValueError('native reconnect refused')
        self.dispatched = True
        connection, _ = self.listener.accept()
        self.listener.close()
        self.listener = None
        with connection:
            peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer != (pid, self.spec['vmm_uid'], self.spec['vmm_gid']):
                raise ValueError('native endpoint peer differs from owned VMM')
            start = pathlib.Path('/proc/' + str(pid) + '/stat').read_text().rsplit(') ', 1)[1].split()[19]
            custody_dir = self.root / 'custody'
            custody_dir.mkdir(mode=0o700)
            os.chown(custody_dir, 996, 980)
            output = custody_dir / 'output'
            with output.open('xb') as file:
                os.chmod(output, 0o600)
                file.flush(); os.fsync(file.fileno())
            os.chown(output, 996, 980)
            native_fd = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            client, server = socket.socketpair()
            try:
                command = ['/usr/bin/setpriv', '--reuid', '996', '--regid', '980', '--clear-groups',
                           '--inh-caps=-all', '--bounding-set=-all', '--no-new-privs',
                           str(self.binaries['native_custodian']), 'output', 'custody.jsonl',
                           self.spec['native_submission_binding']['run_id'], '120000']
                child = self.spawn(command, server, custody_dir, 'custodian')
                server.close()
                client.settimeout(10)
                ready = b'REALM-C0-CUSTODIAN-READY-V1\n'
                from coding_native_client import exact
                if exact(client, len(ready)) != ready:
                    raise ValueError('custodian launch gate differs')
                observation = {'authority': 'NONE', 'pid': child.pid,
                    'status': pathlib.Path('/proc/' + str(child.pid) + '/status').read_text(),
                    'stat': pathlib.Path('/proc/' + str(child.pid) + '/stat').read_text(),
                    'executable_sha256': self.file_sha(pathlib.Path('/proc/' + str(child.pid) + '/exe'))}
                self.save('custodian-process.json', observation)
                if observation['executable_sha256'] != self.spec['native_binary_pins']['native_custodian']:
                    raise ValueError('custodian executed bytes differ')
                client.sendall(b'REALM-C0-CUSTODIAN-START-V1\n')
                self.save('binding.json', self.spec['native_submission_binding'])
                self.save('custody-handoff-flags.json', blocking_handoff(client))
                command = [str(self.binaries['native_broker']), str(self.root), str(self.root / 'binding.json'),
                           str(pid), start, str(peer[1]), str(peer[2]), str(native_fd),
                           str(client.fileno()), str(pidfd)]
                self.spawn(command, connection, self.root, 'broker', (native_fd, client.fileno(), pidfd))
                self.save('connection.json', {'authority': 'NONE', 'peer': list(peer), 'start_ticks': start,
                    'planner_run_id': self.spec['planner_run_id'], 'native_binding': self.spec['native_submission_binding']})
            finally:
                os.close(native_fd); client.close(); server.close()

    @staticmethod
    def file_sha(path):
        import hashlib
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def save(self, name, value):
        with (self.root / name).open('xb') as stream:
            os.chmod(stream.name, 0o600)
            stream.write(worker.encoded(value)); stream.flush(); os.fsync(stream.fileno())

    def spawn(self, command, stdin, cwd, name, fds=()):
        out = (self.root / (name + '.stdout')).open('xb')
        err = (self.root / (name + '.stderr')).open('xb')
        # The fresh private parent can inherit a default ACL. Do this before
        # handing either descriptor to a child or writing any log bytes.
        os.fchmod(out.fileno(), 0o600)
        os.fchmod(err.fileno(), 0o600)
        self.logs += [out, err]
        child = subprocess.Popen(command, stdin=stdin, stdout=out, stderr=err,
                                 cwd=cwd, close_fds=True, pass_fds=fds, start_new_session=True, umask=0o077)
        self.children.append((name, child))
        return child

    def close_after_vmm_cleanup(self):
        rows = []
        for name, child in reversed(self.children):
            forced = False
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=5); forced = True
            rows.append({'role': name, 'pid': child.pid, 'exit': child.returncode,
                         'forced_owned_cleanup': forced, 'authority': 'NONE'})
        for stream in self.logs:
            stream.close()
        if self.listener:
            self.listener.close()
        self.save('process-results.json', rows)
        return rows
