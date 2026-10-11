"""Trusted job handoff for private, sealed verification and consumer bytes.

Callers isolate this job from producers and candidate execution. Registered
writers must finish before sealing. Permissions and fingerprints detect lost
custody; they do not isolate another process running as the same principal.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import stat

from release_common import SCHEMA, basename, fail, parents, regular

BUFFER = 65536
# Archive and control admission impose their narrower limits before parsing.
# Copying also supports SBOM files up to the build record's integer ceiling.
MAX_FILE = SCHEMA['$defs']['artifact']['properties']['bytes']['maximum']


def fingerprint(path):
    info = regular(path).stat()
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(BUFFER):
            hasher.update(chunk)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            getattr(info, 'st_uid', None), hasher.hexdigest())


class Snapshot:
    def __init__(self, root):
        self.root = parents(root)
        self.root.mkdir(mode=0o700)
        self.records = self.root / 'records'
        self.artifacts = self.root / 'artifacts'
        self.records.mkdir(mode=0o700)
        self.artifacts.mkdir(mode=0o700)
        self.state = 'copying'
        self.writers = 0
        self.files = {}
        self.directories = {p: self._directory_identity(p) for p in (self.root, self.records, self.artifacts)}

    @staticmethod
    def _directory_identity(path):
        info = parents(path).lstat()
        if not stat.S_ISDIR(info.st_mode):
            fail(str(path), 'snapshot directory lost')
        return info.st_dev, info.st_ino, getattr(info, 'st_uid', None)

    def discard(self, reason):
        self.state = 'discarded'
        fail('snapshot', reason)

    @contextmanager
    def writer(self):
        if self.state != 'copying':
            self.discard('write attempted after sealing')
        self.writers += 1
        try:
            yield
        except BaseException:
            self.state = 'discarded'
            raise
        finally:
            self.writers -= 1

    def copy(self, records, artifacts):
        with self.writer():
            for source, destination in ((records, self.records), (artifacts, self.artifacts)):
                parents(source)
                if not source.is_dir():
                    self.discard('source must be directory')
                for index, path in enumerate(source.iterdir(), 1):
                    if index > 64 * 256 + 256 + 65:
                        self.discard('source file count exceeded')
                    basename(path.name, 'snapshot source')
                    regular(path)
                    before = path.stat()
                    if before.st_size > MAX_FILE:
                        self.discard('source file byte limit exceeded')
                    output = destination / path.name
                    hasher = hashlib.sha256()
                    total = 0
                    with path.open('rb') as reader, output.open('xb') as writer:
                        opened = reader.fileno()
                        info = os.fstat(opened)
                        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or info.st_nlink != 1:
                            self.discard('source changed before copy')
                        while chunk := reader.read(min(BUFFER, max(1, before.st_size - total))):
                            if len(chunk) > before.st_size - total:
                                self.discard('source grew during copy')
                            writer.write(chunk)
                            hasher.update(chunk)
                            total += len(chunk)
                    after = path.stat()
                    if total != before.st_size or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) != (
                            after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size):
                        self.discard('source changed during copy')
                    copied = fingerprint(output)
                    if copied[-1] != hasher.hexdigest():
                        self.discard('copy integrity failed')
                    self.files[output] = copied

    def custody(self):
        try:
            for path, expected in self.directories.items():
                if self._directory_identity(path) != expected:
                    self.discard('directory ownership changed')
                # Windows private-directory ACLs come from mkdir(0700) and job
                # custody; chmod there controls only the file read-only bit.
                if self.state == 'sealed' and os.name != 'nt' and path.stat().st_mode & 0o222:
                    self.discard('snapshot directory write permission restored')
            if set(self.root.iterdir()) != {self.records, self.artifacts}:
                self.discard('snapshot directory set changed')
            actual = set(self.records.iterdir()) | set(self.artifacts.iterdir())
            if actual != set(self.files):
                self.discard('snapshot file set changed')
            for path, expected in self.files.items():
                if fingerprint(path) != expected:
                    self.discard('snapshot bytes or ownership changed')
                if self.state == 'sealed' and path.stat().st_mode & 0o222:
                    self.discard('snapshot write permission restored')
        except (OSError, ValueError):
            self.state = 'discarded'
            raise

    def seal(self):
        if self.state != 'copying' or self.writers:
            self.discard('unfinished writer or invalid sealing state')
        self.custody()
        for path in self.files:
            path.chmod(0o400)
        for path in (self.records, self.artifacts, self.root):
            path.chmod(0o500)
        self.state = 'sealed'
        self.custody()

    def use(self, consumer):
        if self.state != 'sealed' or self.writers:
            self.discard('consumer requires sealed snapshot with closed writers')
        self.custody()
        try:
            result = consumer(self.records, self.artifacts)
            self.custody()
            return result
        except BaseException:
            self.state = 'discarded'
            raise

    def consume(self, consumer):
        result = self.use(consumer)
        self.state = 'consumed'
        return result

    def close(self):
        # Cleanup only the retained directory identity, never a substituted path.
        if not self.root.exists():
            return
        if self._directory_identity(self.root) != self.directories[self.root]:
            return
        for path, expected in self.directories.items():
            if path.exists() and self._directory_identity(path) == expected:
                path.chmod(0o700)
        for path in self.files:
            if path.exists() and not path.is_symlink():
                path.chmod(0o600)
        shutil.rmtree(self.root)
        if self.state != 'consumed':
            self.state = 'discarded'
