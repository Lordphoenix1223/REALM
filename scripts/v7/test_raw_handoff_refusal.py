"""Independent raw-receipt controls. Receipt is diagnostic, never authority."""
import hashlib
import json
import os
import pathlib
import socket
import stat
import struct
import tempfile
import time
import unittest
from unittest import mock

import coding_guest_probe as probe


class RawHandoffRefusalTests(unittest.TestCase):
    payload = b'independent durable receipt control; not a .realm'
    challenge = 'a' * 64

    def header(self, **changes):
        return {'schema': 'realm.coding-guest-development-raw.v2',
                'authority': 'NONE', 'realm_artifact': None,
                'challenge': self.challenge, 'size': len(self.payload),
                'sha256': hashlib.sha256(self.payload).hexdigest(), **changes}

    def wire(self, raw_header, payload=None):
        data = raw_header if isinstance(raw_header, bytes) else json.dumps(raw_header).encode()
        left, right = socket.socketpair()
        left.settimeout(.5); right.settimeout(.5)
        left.sendall(struct.pack('!I', len(data)) + data + (self.payload if payload is None else payload))
        left.shutdown(socket.SHUT_WR)
        self.addCleanup(left.close); self.addCleanup(right.close)
        return left, right

    def no_ack(self, client):
        # The peer remains open: any bytes instead of a timeout would be an ACK.
        with self.assertRaises(TimeoutError):
            client.recv(1)

    def test_valid_receipt_reopens_files_before_any_ack(self):
        left, right = self.wire(self.header())
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            saved_fsync = os.fsync
            synced = []
            def sync(fd):
                synced.append(os.fstat(fd))
                return saved_fsync(fd)
            def send(connection, ack):
                self.assertEqual((root / 'guest-raw.tar.gz').read_bytes(), self.payload)
                self.assertEqual(json.loads((root / 'raw-header.json').read_bytes()), self.header())
                self.assertEqual(len(synced), 3)
                self.assertTrue(stat.S_ISREG(synced[0].st_mode))
                self.assertTrue(stat.S_ISREG(synced[1].st_mode))
                self.assertTrue(stat.S_ISDIR(synced[2].st_mode))
                expected_directory = root.stat()
                self.assertEqual((synced[2].st_dev, synced[2].st_ino),
                                 (expected_directory.st_dev, expected_directory.st_ino))
                self.assertEqual(ack, {'schema': 'realm.coding-raw-received.v1',
                                      'authority': 'NONE', 'challenge': self.challenge,
                                      'sha256': self.header()['sha256'], 'size': len(self.payload)})
            with mock.patch.object(probe.os, 'fsync', side_effect=sync), mock.patch.object(probe.planner, 'send', side_effect=send) as ack:
                probe.receive_raw_handoff(right, root, self.challenge)
            ack.assert_called_once()
            self.assertEqual((root / 'guest-raw.tar.gz').stat().st_mode & 0o777, 0o600)

    def test_foreign_corrupt_short_and_duplicate_records_never_ack(self):
        duplicate = json.dumps(self.header()).encode().replace(b'"authority": "NONE"', b'"authority": "NONE", "authority": "NONE"')
        cases = [
            (self.header(challenge='b' * 64), self.payload),
            (self.header(authority='PASS'), self.payload),
            (self.header(realm_artifact='forged.realm'), self.payload),
            (self.header(size=True), self.payload),
            (self.header(size=64 * 1024**2 + 1), self.payload),
            (self.header(schema='realm.coding-guest-development-raw.v1'), self.payload),
            (self.header(), self.payload[:-1]),
            (self.header(), b'Z' * len(self.payload)),
            (duplicate, self.payload),
        ]
        for header, payload in cases:
            with self.subTest(header=header), tempfile.TemporaryDirectory() as name:
                left, right = self.wire(header, payload)
                with mock.patch.object(probe.planner, 'send') as ack:
                    with self.assertRaises((ValueError, OSError)):
                        probe.receive_raw_handoff(right, pathlib.Path(name), self.challenge)
                ack.assert_not_called()
                self.assertEqual(list(pathlib.Path(name).iterdir()), [])
                self.no_ack(left)

    def test_each_failed_fsync_preserves_failure_without_ack(self):
        for which in (1, 2, 3):
            with self.subTest(which=which), tempfile.TemporaryDirectory() as name:
                left, right = self.wire(self.header())
                saved_fsync, seen = os.fsync, []
                def fail(fd):
                    seen.append(fd)
                    if len(seen) == which:
                        raise OSError('independent injected persistence failure')
                    return saved_fsync(fd)
                with mock.patch.object(probe.os, 'fsync', side_effect=fail), mock.patch.object(probe.planner, 'send') as ack:
                    with self.assertRaisesRegex(OSError, 'persistence failure'):
                        probe.receive_raw_handoff(right, pathlib.Path(name), self.challenge)
                ack.assert_not_called()
                self.assertEqual(len(seen), which)
                self.no_ack(left)

    def test_existing_raw_file_is_not_overwritten_or_acknowledged(self):
        left, right = self.wire(self.header())
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            original = root / 'guest-raw.tar.gz'
            original.write_bytes(b'original failed or previous receipt')
            with mock.patch.object(probe.planner, 'send') as ack:
                with self.assertRaises(FileExistsError):
                    probe.receive_raw_handoff(right, root, self.challenge)
            self.assertEqual(original.read_bytes(), b'original failed or previous receipt')
            ack.assert_not_called(); self.no_ack(left)

    def test_expired_budget_never_reads_or_acks(self):
        left, right = self.wire(self.header())
        with tempfile.TemporaryDirectory() as name, mock.patch.object(probe.planner, 'send') as ack:
            with self.assertRaisesRegex(TimeoutError, 'deadline'):
                probe.receive_raw_handoff(right, pathlib.Path(name), self.challenge,
                                          deadline=time.monotonic() - 1)
            ack.assert_not_called()
            self.assertEqual(list(pathlib.Path(name).iterdir()), [])
            self.no_ack(left)

    def test_persistence_delay_exhausts_same_budget_before_ack(self):
        left, right = self.wire(self.header())
        saved_fsync = os.fsync
        def slow_sync(fd):
            saved_fsync(fd)
            time.sleep(.03)
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            with mock.patch.object(probe.os, 'fsync', side_effect=slow_sync), mock.patch.object(probe.planner, 'send') as ack:
                with self.assertRaisesRegex(TimeoutError, 'deadline'):
                    probe.receive_raw_handoff(right, root, self.challenge,
                                              deadline=time.monotonic() + .07)
            ack.assert_not_called()
            self.assertEqual((root / 'guest-raw.tar.gz').read_bytes(), self.payload)
            self.no_ack(left)


if __name__ == '__main__':
    unittest.main(verbosity=2)
