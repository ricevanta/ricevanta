"""The console artifact digest includes hidden bytes and refuses ambiguous trees."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import tree_digest


class TreeDigestTests(unittest.TestCase):
    def test_windows_forbidden_names_do_not_require_impossible_file_creation(self):
        write_bytes = Path.write_bytes
        def windows_write(path, data):
            if path.name in ('back\\slash', 'line\nbreak'):
                raise AssertionError('Windows cannot create this forbidden filename')
            return write_bytes(path, data)
        with mock.patch.object(sys, 'platform', 'win32'), mock.patch.object(Path, 'write_bytes', windows_write):
            self.test_invalid_entries()

    def test_exact_records_and_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.vite').mkdir()
            (root / '.vite/manifest.json').write_bytes(b'{}')
            (root / 'index.html').write_bytes(b'html')
            records = b''.join(name.encode('ascii') + b'\0' + hashlib.sha256(data).hexdigest().encode('ascii') + b'\n'
                               for name, data in [('.vite/manifest.json', b'{}'), ('index.html', b'html')])
            original = 'sha256:' + hashlib.sha256(records).hexdigest()
            self.assertEqual(tree_digest.digest(root), original)
            (root / 'empty').mkdir()
            self.assertEqual(tree_digest.digest(root), original)
            (root / '.vite/manifest.json').write_bytes(b'{ }')
            self.assertNotEqual(tree_digest.digest(root), original)
            (root / '.vite/manifest.json').write_bytes(b'{}')
            (root / 'extra').write_bytes(b'x')
            self.assertNotEqual(tree_digest.digest(root), original)
            (root / 'extra').unlink()
            self.assertEqual(tree_digest.digest(root), original)
            (root / 'index.html').unlink()
            self.assertNotEqual(tree_digest.digest(root), original)

    def test_invalid_entries(self):
        for name in ['é', 'back\\slash', 'line\nbreak']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                if sys.platform == 'win32' and name in ('back\\slash', 'line\nbreak'):
                    entry = mock.Mock()
                    entry.name = name
                    with mock.patch.object(Path, 'iterdir', return_value=[entry]):
                        with self.assertRaises(ValueError): tree_digest.digest(Path(tmp))
                    entry.lstat.assert_not_called()
                else:
                    (Path(tmp) / name).write_bytes(b'x')
                    with self.assertRaises(ValueError): tree_digest.digest(Path(tmp))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            try: (root / 'link').symlink_to('absent')
            except OSError: pass  # Windows may lack symlink privileges.
            else:
                with self.assertRaises(ValueError): tree_digest.digest(root)
                (root / 'link').unlink()
            if hasattr(os, 'mkfifo'):
                os.mkfifo(root / 'fifo')
                with self.assertRaises(ValueError): tree_digest.digest(root)

    def test_expected_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for value in ['', 'sha256:BAD', 'sha256:' + '0' * 64]:
                with self.subTest(value=value), mock.patch.dict(os.environ, EXPECTED_DIST_DIGEST=value):
                    with self.assertRaises(ValueError): tree_digest.check(root, 'EXPECTED_DIST_DIGEST')
            with mock.patch.dict(os.environ, EXPECTED_DIST_DIGEST=tree_digest.digest(root)):
                self.assertEqual(tree_digest.check(root, 'EXPECTED_DIST_DIGEST'), tree_digest.digest(root))
