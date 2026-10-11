"""Enforce bounded control reads and portable link rejection."""
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import release_common as common


class CommonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ricevanta-control-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / 'control.json'

    def test_control_identity_and_checksum_exact_byte_limits(self):
        # Inject a small allowance into the shared reader instead of large files.
        for label in ('record', 'inventory', 'event', 'expected identity', 'SHA256SUMS'):
            with self.subTest(label=label):
                self.path.write_bytes(b' ' * 62 + b'{}')
                self.assertEqual(common.bounded_read(self.path, 64), b' ' * 62 + b'{}')
                self.path.write_bytes(b' ' * 63 + b'{}')
                with self.assertRaises(ValueError): common.bounded_read(self.path, 64)
        self.path.write_bytes(b'{}')
        with patch.object(Path, 'open', side_effect=AssertionError('oversize opened')):
            with self.assertRaises(ValueError): common.bounded_read(self.path, 1)

    def test_one_byte_probe_never_retained(self):
        self.path.write_bytes(b'{}')
        calls = []
        class Growing(io.BytesIO):
            def read(self, count=-1):
                calls.append(count)
                if count < 0 or count > 65536: raise AssertionError('unbounded read')
                return super().read(count)
        with patch.object(Path, 'open', return_value=Growing(b'x' * 65)):
            with self.assertRaises(ValueError): common.bounded_read(self.path, 64)
        self.assertEqual(calls, [64, 1])

    def test_reparse_file_and_parent_rejected(self):
        self.path.write_bytes(b'{}')
        original = Path.lstat
        for target in (self.path, self.path.parent):
            def reparse(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                if path == target:
                    return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
                return info
            with patch.object(Path, 'lstat', reparse):
                with self.assertRaises(ValueError): common.regular(self.path)

    def test_strict_unicode_numbers_nested_duplicates_and_trailing_json(self):
        for raw in (b'{"x":{"a":1,"a":2}}', b'\xef\xbb\xbf{}', b'\xff', b'{}{}',
                    b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}',
                    b'{"a":"\\ud800"}', b'{"\\udfff":1}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): common.decode(raw, 'fixture')
        self.assertEqual(common.decode(b'{"nested":{"a":1}}', 'fixture'), {'nested': {'a': 1}})

    def test_device_filename_rejected_before_filesystem_access(self):
        for name in ('CoN.txt', 'pRn.JSON', 'aUx', 'Nul.bin', 'COM1.exe', 'lPt9'):
            with self.subTest(name=name), patch.object(common, 'parents', side_effect=AssertionError('device path inspected')):
                with self.assertRaises(ValueError): common.regular(self.path.with_name(name))


if __name__ == '__main__':
    unittest.main()
