"""Diagnostic adapter for the EXISTING Rust coding_submission/BrokerRpc wire format.

No new executor, verifier, publisher, host consumer or authority capability.
Even a matching write/Close acknowledgment remains DEVELOPMENT/NONE.
No connector, guest endpoint, launch path or authority installation is exposed.
"""
import struct

import coding_worker as worker

MAX_PACKET = 128 * 1024
MAX_FRAME = 2 * 1024 * 1024
KEYS = {'run_id', 'execution_id', 'challenge_root', 'task_sha256', 'worker_sha256'}


class NotDispatched(ValueError):
    pass


class DeliveryUnknown(ValueError):
    pass


def hex64(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def binding(value):
    if type(value) is not dict or set(value) != KEYS or not all(hex64(v) for v in value.values()):
        raise NotDispatched('invalid external native binding')


def exact(stream, size):
    parts = []
    while size:
        part = stream.recv(min(size, 65536))
        if not part:
            raise OSError('short native broker frame')
        parts.append(part)
        size -= len(part)
    return b''.join(parts)


def frame(stream, limit):
    size = struct.unpack('!I', exact(stream, 4))[0]
    if not 0 < size <= limit:
        raise ValueError('native frame size limit')
    return exact(stream, size)


def packet(value, expected):
    binding(expected)
    if not 0 < len(value) <= MAX_PACKET:
        raise NotDispatched('native packet size limit')
    body = worker.parse(value)
    if type(body) is not dict or set(body) != {'schema', 'binding', 'transcript_head', 'files'} or \
            body['schema'] != 'realm.coding-submission.v1' or body['binding'] != expected or \
            not hex64(body['transcript_head']) or type(body['files']) is not list or len(body['files']) != 3:
        raise NotDispatched('native packet identity/shape differs')
    for row, name in zip(body['files'], worker.FILES):
        if type(row) is not dict or set(row) != {'path', 'text', 'mode'} or row['path'] != name or \
                type(row['mode']) is not int or row['mode'] != 0o600 or type(row['text']) is not str or \
                not 0 < len(row['text'].encode()) <= worker.MAX_BYTES:
            raise NotDispatched('native packet projection differs')
    return body


def bootstrap(stream, expected):
    lines = frame(stream, 512).decode('ascii').split('\n')
    if len(lines) != 10 or lines[0] != 'REALM-C0-BOOTSTRAP-V2' or lines[-1] != '':
        raise NotDispatched('unsupported native bootstrap')
    run, execution, serial, birth, capability, challenge, input_version, output_version = lines[1:9]
    if (run, execution, challenge) != (expected['run_id'], expected['execution_id'], expected['challenge_root']) or \
            not hex64(input_version) or not hex64(output_version):
        raise NotDispatched('native bootstrap binding differs')
    numbers = []
    for value in (serial, birth, capability):
        if not value.isascii() or not value.isdecimal() or not 0 < int(value) < 2**64 or str(int(value)) != value:
            raise NotDispatched('native bootstrap process/capability differs')
        numbers.append(int(value))
    if numbers[0] != 1:
        raise NotDispatched('unsupported native initial process')
    return {'run_id': run, 'process': {'launch': execution, 'serial': numbers[0], 'birth': numbers[1]},
            'capability': numbers[2], 'challenge_root': challenge}, output_version


def send_packet(stream, expected, value):
    # Validate the untrusted packet before consuming the host bootstrap or
    # sending any request. This is protocol checking, not task verification.
    try:
        packet(value, expected)
        identity, version = bootstrap(stream, expected)
    except (ValueError, OSError, UnicodeError) as error:
        raise NotDispatched(str(error)) from error
    for operation, kind, payload, sequence in [('coding:submit', 'write_range', value, 2),
                                               ('coding:close', 'close', b'', 3)]:
        request = {**identity, 'operation_id': operation, 'kind': kind, 'object_id': 'output',
                   'expected_version': version, 'offset': 0,
                   'requested_length': len(payload), 'bytes': list(payload)}
        data = worker.encoded(request)
        try:
            # Any error from this first attempted send onward is UNKNOWN.
            stream.sendall(struct.pack('!I', len(data)) + data)
            reply = worker.parse(frame(stream, MAX_FRAME))
            if type(reply) is not dict or set(reply) != {'run_id', 'operation_id', 'status', 'completed',
                    'resulting_version', 'evidence_sequence', 'bytes'} or reply['run_id'] != expected['run_id'] or \
                    reply['operation_id'] != operation or reply['status'] != 'ok' or \
                    type(reply['completed']) is not int or reply['completed'] != len(payload) or \
                    type(reply['evidence_sequence']) is not int or reply['evidence_sequence'] != sequence or \
                    reply['bytes'] != [] or not hex64(reply['resulting_version']) or \
                    (sequence == 3 and reply['resulting_version'] != version):
                raise ValueError('native broker reply differs')
            version = reply['resulting_version']
        except (ValueError, OSError, UnicodeError) as error:
            raise DeliveryUnknown(str(error)) from error
    return {'status': 'DEVELOPMENT_NATIVE_SUBMISSION_ACKNOWLEDGED', 'authority': 'NONE',
            'realm_artifact': None, 'run_id': expected['run_id'], 'execution_id': expected['execution_id'],
            'packet_sha256': worker.digest(value), 'output_version': version}
