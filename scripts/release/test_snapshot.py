"""Keep admitted bytes in trusted custody through verification and consumption."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import snapshot
import verify
import test_verify


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_verify.VerifyTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.temp = tempfile.TemporaryDirectory(prefix='ricevanta-custody-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'snapshot'

    def copy(self, destination=None):
        result = snapshot.Snapshot(destination or self.root)
        self.addCleanup(result.close)
        result.copy(self.fixture.records, self.fixture.artifacts)
        return result

    def test_unfinished_writer_refuses_seal_and_verification(self):
        result = self.copy()
        with result.writer():
            with self.assertRaises(ValueError): result.seal()
            with self.assertRaises(ValueError):
                result.use(lambda records, artifacts: self.fail('verifier invoked'))
        self.assertEqual(result.state, 'discarded')

    def test_source_replacement_during_parse_cannot_change_upload(self):
        result = self.copy()
        result.seal()
        before = (result.artifacts / 'console.tar.gz').read_bytes()
        original = verify.archive_identities
        def replace_source(path, recipe, expected):
            original(path, recipe, expected)
            self.fixture.pack(dict(self.fixture.identity, sourceEpoch=2))
            self.fixture.save()
        with patch.object(verify, 'archive_identities', side_effect=replace_source):
            result.use(lambda records, artifacts: verify.verify(records, artifacts,
                       self.fixture.inventory_path, self.fixture.expected))
        uploaded = result.consume(lambda records, artifacts: (artifacts / 'console.tar.gz').read_bytes())
        self.assertEqual(uploaded, before)
        self.assertNotEqual(uploaded, (self.fixture.artifacts / 'console.tar.gz').read_bytes())
        self.assertEqual(result.state, 'consumed')
        with self.assertRaises(ValueError): result.use(lambda *args: None)

    def test_postseal_writer_discards(self):
        result = self.copy()
        result.seal()
        with self.assertRaises(ValueError):
            with result.writer(): pass
        self.assertEqual(result.state, 'discarded')

    def test_links_and_lost_custody_rejected(self):
        result = self.copy()
        linked = self.fixture.root / 'linked'
        linked.hardlink_to(result.artifacts / 'console.tar.gz')
        with self.assertRaises(ValueError): result.seal()
        linked.unlink()
        result = self.copy(self.root.parent / 'second')
        result.seal()
        path = result.artifacts / 'console.tar.gz'
        path.chmod(0o600)
        path.write_bytes(b'tampered')
        with self.assertRaises(ValueError): result.use(lambda *args: self.fail('lost custody accepted'))

    def test_second_job_revalidates_transfer(self):
        first = self.copy()
        first.seal()
        second = snapshot.Snapshot(self.root.parent / 'receiver')
        self.addCleanup(second.close)
        first.use(lambda records, artifacts: second.copy(records, artifacts))
        second.seal()
        second.use(lambda records, artifacts: verify.verify(records, artifacts,
                   self.fixture.inventory_path, self.fixture.expected))
        third = snapshot.Snapshot(self.root.parent / 'tampered-transfer')
        self.addCleanup(third.close)
        first.use(lambda records, artifacts: third.copy(records, artifacts))
        path = third.artifacts / 'console.tar.gz'
        path.write_bytes(b'changed in transfer')
        with self.assertRaises(ValueError): third.seal()

    def test_linked_source_copy_rejected(self):
        linked = self.fixture.root / 'linked'
        linked.hardlink_to(self.fixture.artifacts / 'console.tar.gz')
        with self.assertRaises(ValueError): self.copy()

    def test_directory_write_access_invalidates_sealed_custody(self):
        import os
        result = self.copy()
        result.seal()
        result.artifacts.chmod(0o700)
        if os.name != 'nt':
            with self.assertRaises(ValueError): result.use(lambda *args: self.fail('directory write access accepted'))

    def test_external_writer_cannot_change_bytes_during_consumption(self):
        result = self.copy()
        result.seal()
        def mutate(records, artifacts):
            path = artifacts / 'console.tar.gz'
            path.chmod(0o600)
            path.write_bytes(b'tampered')
        with self.assertRaises(ValueError): result.consume(mutate)
        self.assertEqual(result.state, 'discarded')

    def test_unfinished_download_thread_and_open_handle_prevent_verification(self):
        import threading
        result = self.copy()
        ready = threading.Event()
        finished = threading.Event()
        def download():
            with result.writer(), (result.artifacts / 'pending').open('wb') as stream:
                stream.write(b'pending download')
                ready.set()
                finished.wait(5)
        worker = threading.Thread(target=download)
        worker.start()
        self.assertTrue(ready.wait(5))
        try:
            with self.assertRaises(ValueError): result.seal()
            with self.assertRaises(ValueError): result.use(lambda *args: self.fail('verifier invoked'))
        finally:
            finished.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())

    def test_directory_replacement_loses_custody(self):
        result = self.copy()
        result.seal()
        moved = result.root.with_name('moved')
        result.root.rename(moved)
        result.root.mkdir()
        with self.assertRaises(ValueError): result.use(lambda *args: self.fail('replacement accepted'))
        # The trusted fixture owns the moved directory; close must not touch the replacement.
        result.root.rmdir()
        moved.rename(result.root)


if __name__ == '__main__':
    unittest.main()
