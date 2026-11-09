"""Adversarial controls for the independent audit's allocation changes."""
import itertools
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_coding_development as verifier


class JournalMemoryControls(unittest.TestCase):
    def test_binary_line_boundaries_match_python(self):
        # Includes adjacent/terminal CR, LF, CRLF, empty lines, and bytes that
        # str.splitlines() treats as boundaries but bytes.splitlines() does not.
        for size in range(8):
            for values in itertools.product((b'x', b'\r', b'\n'), repeat=size):
                data = b''.join(values)
                self.assertEqual(list(verifier.journal_lines(data)), data.splitlines())
        for value in range(256):
            data = b'x' + bytes([value]) + b'y\n'
            self.assertEqual(list(verifier.journal_lines(data)), data.splitlines())
            if b'\r' not in data:
                self.assertEqual(list(verifier.journal_lines(data, has_cr=False)),
                                 data.splitlines())

    def test_partial_reads_and_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence'
            path.write_bytes(b'abcdefgh')
            original = os.read
            with patch.object(verifier.os, 'read',
                              lambda fd, size: original(fd, min(size, 3))):
                self.assertEqual(verifier.read_regular(path, 8), b'abcdefgh')
            path.write_bytes(b'')
            self.assertEqual(verifier.read_regular(path, 0), b'')
            path.write_bytes(b'x')
            with self.assertRaisesRegex(ValueError, 'size limit'):
                verifier.read_regular(path, 0)

    def test_overwrite_refuses_even_with_identical_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence'
            path.write_bytes(b'abc')
            original_read = os.read
            frozen_metadata = path.stat()
            def overwrite(fd, size):
                data = original_read(fd, size)
                if data:
                    path.write_bytes(b'xyz')
                return data
            # Simulate same-jiffy metadata, not just a change detected by stat.
            with patch.object(verifier.os, 'fstat', return_value=frozen_metadata), \
                 patch.object(verifier.os, 'stat', return_value=frozen_metadata), \
                 patch.object(verifier.os, 'read', overwrite):
                with self.assertRaisesRegex(ValueError, 'bytes changed'):
                    verifier.read_regular(path, 3)

    def test_short_read_and_growth_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence'
            path.write_bytes(b'abc')
            with patch.object(verifier.os, 'read', return_value=b''):
                with self.assertRaisesRegex(ValueError, 'short evidence read'):
                    verifier.read_regular(path, 3)
            original = os.read
            first = True
            def grow(fd, size):
                nonlocal first
                data = original(fd, size)
                if first:
                    first = False
                    with path.open('ab') as stream:
                        stream.write(b'd')
                return data
            with patch.object(verifier.os, 'read', grow):
                with self.assertRaisesRegex(ValueError, 'grew during read'):
                    verifier.read_regular(path, 3)


if __name__ == '__main__':
    unittest.main()
