"""Bounded, non-extracting ZIP and USTAR/local-PAX admission.

The public check runs the parser in a supervised process. The parser keeps only
bounded structural records and identity documents; ordinary bodies are streamed.
"""
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zlib

from release_common import bounded_read, check_identity, decode, fail, member_name, regular


@dataclass(frozen=True)
class Limits:
    stored: int = 4 * 1073741824
    members: int = 16384
    member: int = 2 * 1073741824
    expanded: int = 8 * 1073741824
    identity: int = 65536
    structural: int = 16 * 1048576
    extension: int = 65536
    buffer: int = 65536
    work: int = 16 * 1073741824
    calls: int = 1000000
    seconds: float = 120


class Budget:
    def __init__(self, limits, clock=time.monotonic):
        self.limits = limits
        self.clock = clock
        self.start = clock()
        self.counts = dict(members=0, expanded=0, structural=0, work=0, calls=0)

    def deadline(self):
        if self.clock() - self.start >= self.limits.seconds:
            fail('archive', 'deadline exceeded')

    def charge(self, key, amount):
        self.deadline()
        if amount < 0 or amount > getattr(self.limits, key) - self.counts[key]:
            fail('archive', key + ' budget exceeded')
        self.counts[key] += amount

    def decompress(self, decoder, data, cap):
        self.deadline()
        if cap <= 0 or cap > self.limits.buffer:
            fail('archive', 'invalid decoder output reservation')
        self.charge('calls', 1)
        self.charge('work', len(data) + cap)
        try:
            output = decoder.decompress(data, cap)
        except zlib.error as error:
            fail('archive', 'decompression integrity: ' + str(error))
        if len(output) > cap:
            fail('archive', 'decoder exceeded output reservation')
        self.counts['work'] -= cap - len(output)
        consumed = len(data) - len(decoder.unconsumed_tail) - len(decoder.unused_data)
        if consumed <= 0 and not output and not decoder.eof:
            fail('archive', 'decoder made no progress')
        self.deadline()
        return output


def read_exact(stream, size, budget):
    if size < 0:
        fail('archive', 'negative read length')
    result = bytearray()
    while len(result) < size:
        budget.deadline()
        chunk = stream.read(min(budget.limits.buffer, size - len(result)))
        if not chunk:
            fail('archive', 'truncated stream')
        result.extend(chunk)
    return bytes(result)


class Tree:
    def __init__(self, wanted):
        self.nodes = {}
        self.wanted = set(wanted)
        self.found = set()

    def admit(self, name, directory):
        if directory and name.endswith('/'):
            name = name[:-1]
        member_name(name, 'archive')
        parts = name.split('/')
        for index in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:index])
            folded = prefix.casefold()
            final = index == len(parts)
            if parts[index - 1].casefold() in ('identity.json', 'build-info.json') and not final:
                fail(name, 'identity metadata cannot be a directory')
            previous = self.nodes.get(folded)
            if previous:
                spelling, kind, explicit = previous
                if spelling != prefix or kind == 'file':
                    fail(name, 'case collision or file/directory prefix conflict')
                if final and (not directory or explicit):
                    fail(name, 'duplicate or file/directory prefix conflict')
            if final:
                self.nodes[folded] = (prefix, 'directory' if directory else 'file', True)
            elif not previous:
                self.nodes[folded] = (prefix, 'directory', False)
        base = parts[-1]
        metadata = base.casefold() in ('identity.json', 'build-info.json')
        if metadata and (base not in ('identity.json', 'build-info.json') or directory):
            fail(name, 'identity metadata must be lowercase regular file')
        if name in self.wanted and directory:
            fail(name, 'listed identity must be regular file')
        return name, metadata or name in self.wanted

    def identity(self, name, data, expected):
        check_identity(decode(data, name), expected, name)
        self.found.add(name)

    def finish(self):
        if self.wanted - self.found:
            fail('archive', 'missing embedded identity ' + ', '.join(sorted(self.wanted - self.found)))


def body_size(size, metadata, budget):
    if size > budget.limits.member or size < 0:
        fail('archive', 'member byte limit exceeded')
    if metadata and size > budget.limits.identity:
        fail('archive', 'identity byte limit exceeded')


class TarReader:
    """Present raw or single-member gzip bytes with bounded decoder output."""
    def __init__(self, stream, compressed, budget):
        self.stream = stream
        self.budget = budget
        self.decoder = zlib.decompressobj(31) if compressed else None
        self.pending = b''
        self.output = b''
        self.done = False
        if compressed:
            # Bound optional gzip header metadata before invoking zlib.
            start = stream.tell()
            fixed = read_exact(stream, 10, budget)
            if fixed[:3] != b'\x1f\x8b\x08' or fixed[3] & 0xe0:
                fail('gzip', 'invalid header')
            length = 10
            if fixed[3] & 4:
                extra = struct.unpack('<H', read_exact(stream, 2, budget))[0]
                length += 2 + extra
                if length > budget.limits.extension:
                    fail('gzip', 'header byte limit exceeded')
                read_exact(stream, extra, budget)
            for bit in (8, 16):
                if fixed[3] & bit:
                    while True:
                        length += 1
                        if length > budget.limits.extension:
                            fail('gzip', 'header byte limit exceeded')
                        if read_exact(stream, 1, budget) == b'\0':
                            break
            if fixed[3] & 2:
                length += 2
                read_exact(stream, 2, budget)
            if length > budget.limits.extension:
                fail('gzip', 'header byte limit exceeded')
            budget.charge('structural', length + 8)
            stream.seek(start)

    def read(self, count):
        if count <= 0 or count > self.budget.limits.buffer:
            fail('tar', 'invalid read request')
        if not self.decoder:
            self.budget.deadline()
            remaining = self.budget.limits.expanded - self.budget.counts['expanded']
            if remaining == 0:
                # Raw files are seekable. Check EOF without allocating beyond the budget.
                position = self.stream.tell()
                end = self.stream.seek(0, 2)
                self.stream.seek(position)
                if position != end:
                    fail('archive', 'expanded budget exceeded')
                return b''
            data = self.stream.read(min(count, remaining))
            self.budget.charge('expanded', len(data))
            return data
        while not self.output and not self.done:
            if not self.pending:
                self.pending = self.stream.read(self.budget.limits.buffer)
            remaining = self.budget.limits.expanded - self.budget.counts['expanded']
            cap = min(self.budget.limits.buffer, max(1, remaining))
            self.output = self.budget.decompress(self.decoder, self.pending, cap)
            self.pending = self.decoder.unconsumed_tail
            self.budget.charge('expanded', len(self.output))
            if self.decoder.eof:
                if self.decoder.unused_data or self.pending or self.stream.read(1):
                    fail('gzip', 'trailing bytes or concatenated member')
                self.done = True
        data, self.output = self.output[:count], self.output[count:]
        return data


def octal(raw):
    text = raw.strip(b' \0')
    if not text:
        return 0
    if not re.fullmatch(b'[0-7]+', text):
        fail('tar', 'invalid octal number')
    return int(text, 8)


def tar_text(raw):
    prefix, _, trailing = raw.partition(b'\0')
    if trailing.strip(b'\0'):
        fail('tar', 'nonzero bytes after text terminator')
    try:
        return prefix.decode('utf-8')
    except UnicodeError:
        fail('tar', 'invalid UTF-8')


def pax_values(data):
    values = {}
    offset = 0
    while offset < len(data):
        space = data.find(b' ', offset)
        if space < 0 or not re.fullmatch(b'[1-9][0-9]*', data[offset:space]):
            fail('PAX', 'invalid record length')
        length = int(data[offset:space])
        end = offset + length
        if end > len(data) or end <= space + 1 or data[end - 1:end] != b'\n':
            fail('PAX', 'invalid record extent')
        raw = data[space + 1:end - 1]
        if b'\0' in raw or b'=' not in raw:
            fail('PAX', 'invalid value')
        try:
            key, value = raw.decode('utf-8').split('=', 1)
        except UnicodeError:
            fail('PAX', 'invalid UTF-8')
        if key not in ('path', 'size', 'mtime', 'uid', 'gid', 'uname', 'gname') or key in values:
            fail('PAX', 'unknown or duplicate key')
        if key == 'path':
            member_name(value[:-1] if value.endswith('/') else value, 'PAX')
        elif key in ('size', 'uid', 'gid', 'mtime'):
            pattern = r'(?:0|[1-9][0-9]*)' + (r'(?:\.[0-9]{1,9})?' if key == 'mtime' else '')
            if not re.fullmatch(pattern, value):
                fail('PAX', 'invalid numeric value')
        elif not re.fullmatch(r'[\x20-\x7e]{0,240}', value):
            fail('PAX', 'invalid owner text')
        values[key] = value
        offset = end
    return values


def parse_tar(stream, compressed, tree, expected, budget):
    reader = TarReader(stream, compressed, budget)
    pending = None
    position = 0
    while True:
        header = read_exact(reader, 512, budget)
        position += 512
        if header == b'\0' * 512:
            if pending is not None:
                fail('tar', 'orphan PAX header')
            if read_exact(reader, 512, budget) != b'\0' * 512:
                fail('tar', 'missing second terminal zero block')
            position += 512
            padding = (-position) % 10240
            if read_exact(reader, padding, budget).strip(b'\0'):
                fail('tar', 'nonzero trailing padding')
            if reader.read(1):
                fail('tar', 'trailing stream or excess padding')
            break
        budget.charge('members', 1)
        budget.charge('structural', 512)
        checksum = octal(header[148:156])
        if sum(header[:148]) + 8 * 32 + sum(header[156:]) != checksum:
            fail('tar', 'header checksum mismatch')
        if header[257:263] != b'ustar\0' or header[263:265] != b'00':
            fail('tar', 'USTAR header required')
        for start, end in ((100, 108), (108, 116), (116, 124), (136, 148), (329, 337), (337, 345)):
            octal(header[start:end])
        name = tar_text(header[:100])
        prefix = tar_text(header[345:500])
        if prefix:
            name = prefix + '/' + name
        tar_text(header[265:297])
        tar_text(header[297:329])
        size = octal(header[124:136])
        kind = header[156:157]
        if kind == b'x':
            if pending is not None:
                fail('tar', 'stacked PAX headers')
            if size > budget.limits.extension:
                fail('tar', 'extension byte limit exceeded')
            budget.charge('structural', size)
            pending = pax_values(read_exact(reader, size, budget))
        else:
            if kind not in (b'0', b'\0', b'5') or header[157:257].strip(b'\0'):
                fail('tar', 'link, sparse or unsupported member')
            if pending is not None:
                name = pending.get('path', name)
                size = int(pending.get('size', size))
                pending = None
            directory = kind == b'5'
            name, metadata = tree.admit(name, directory)
            if directory and size:
                fail(name, 'nonempty directory')
            body_size(size, metadata, budget)
            # Reserve actual declared extent before reading the body.
            if size > budget.limits.expanded - budget.counts['expanded'] and not compressed:
                fail(name, 'expanded budget exceeded')
            identity = bytearray() if metadata else None
            left = size
            while left:
                data = read_exact(reader, min(left, budget.limits.buffer), budget)
                if identity is not None:
                    identity.extend(data)
                left -= len(data)
            if identity is not None:
                tree.identity(name, bytes(identity), expected)
        position += size
        padding = (-size) % 512
        if read_exact(reader, padding, budget).strip(b'\0'):
            fail('tar', 'nonzero member padding')
        position += padding


def extra_fields(data):
    offset = 0
    fields = {}
    while offset < len(data):
        if offset + 4 > len(data):
            fail('zip', 'truncated extra field')
        key, size = struct.unpack_from('<HH', data, offset)
        offset += 4
        if offset + size > len(data) or key in fields:
            fail('zip', 'invalid or duplicate extra field')
        fields[key] = data[offset:offset + size]
        offset += size
    return fields


def zip_sizes(size, stored, offset, disk, extras):
    raw = extras.get(1, b'')
    position = 0
    output = []
    for value, sentinel, width in ((size, 0xffffffff, 8), (stored, 0xffffffff, 8),
                                    (offset, 0xffffffff, 8), (disk, 0xffff, 4)):
        if value == sentinel:
            if position + width > len(raw):
                fail('zip', 'missing ZIP64 value')
            value = int.from_bytes(raw[position:position + width], 'little')
            position += width
        output.append(value)
    if position != len(raw):
        fail('zip', 'unexpected ZIP64 value')
    return output


def parse_zip(stream, stored_size, tree, expected, budget):
    tail_size = min(stored_size, 65557)
    stream.seek(stored_size - tail_size)
    tail = read_exact(stream, tail_size, budget)
    index = tail.rfind(b'PK\5\6')
    if index < 0 or index + 22 > len(tail):
        fail('zip', 'missing end record')
    values = struct.unpack_from('<4s4H2IH', tail, index)
    _, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = values
    if index + 22 + comment != len(tail) or disk or cd_disk or disk_count != count:
        fail('zip', 'invalid end record or trailing bytes')
    end_offset = stored_size - tail_size + index
    end_start = end_offset
    if count == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        if end_offset < 20:
            fail('zip', 'missing ZIP64 locator')
        stream.seek(end_offset - 20)
        locator = read_exact(stream, 20, budget)
        signature, zip_disk, zip_offset, disks = struct.unpack('<4sIQI', locator)
        if signature != b'PK\6\7' or zip_disk or disks != 1:
            fail('zip', 'invalid ZIP64 locator')
        stream.seek(zip_offset)
        fixed = read_exact(stream, 56, budget)
        signature, length, _, _, disk, cd_disk, disk_count, count, cd_size, cd_offset = struct.unpack('<4sQ2H2I4Q', fixed)
        if signature != b'PK\6\6' or length < 44 or length > budget.limits.extension or disk or cd_disk or disk_count != count:
            fail('zip', 'invalid ZIP64 end record')
        if zip_offset + 12 + length != end_offset - 20:
            fail('zip', 'invalid ZIP64 end extent')
        read_exact(stream, length - 44, budget)
        end_start = zip_offset
    if count > budget.limits.members or cd_size > budget.limits.structural:
        fail('zip', 'central directory budget exceeded')
    if cd_offset + cd_size != end_start:
        fail('zip', 'central directory extent mismatch')
    budget.charge('structural', stored_size - cd_offset)
    budget.charge('expanded', stored_size - cd_offset)
    # Count actual entries before building a table or retaining member metadata.
    stream.seek(cd_offset)
    position, actual = cd_offset, 0
    while position < end_start:
        fixed = read_exact(stream, 46, budget)
        if fixed[:4] != b'PK\1\2':
            fail('zip', 'invalid central header')
        name_len, extra_len, comment_len = struct.unpack_from('<HHH', fixed, 28)
        length = 46 + name_len + extra_len + comment_len
        if position + length > end_start:
            fail('zip', 'central entry exceeds directory')
        budget.charge('members', 1)
        actual += 1
        position += length
        stream.seek(position)
    if position != end_start or actual != count:
        fail('zip', 'central member count mismatch')
    entries = []
    stream.seek(cd_offset)
    for _ in range(actual):
        fixed = read_exact(stream, 46, budget)
        flags, method = struct.unpack_from('<HH', fixed, 8)
        crc, stored, size = struct.unpack_from('<III', fixed, 16)
        name_len, extra_len, comment_len, disk = struct.unpack_from('<4H', fixed, 28)
        attrs, offset = struct.unpack_from('<II', fixed, 38)
        if name_len > 1025 or extra_len > budget.limits.extension or comment_len > budget.limits.extension:
            fail('zip', 'structural record byte limit exceeded')
        raw_name = read_exact(stream, name_len, budget)
        extras = extra_fields(read_exact(stream, extra_len, budget))
        read_exact(stream, comment_len, budget)
        size, stored, offset, disk = zip_sizes(size, stored, offset, disk, extras)
        if disk or flags & ~0x080e or method not in (0, 8) or (method == 0 and flags & 6):
            fail('zip', 'encrypted or unsupported member')
        try:
            name = raw_name.decode('utf-8' if flags & 0x800 else 'ascii')
        except UnicodeError:
            fail('zip', 'invalid member name encoding')
        directory = name.endswith('/')
        if attrs & 0x10 and not directory:
            fail(name, 'DOS directory attribute disagrees with member name')
        mode = stat.S_IFMT(attrs >> 16)
        if mode not in ((0, stat.S_IFDIR) if directory else (0, stat.S_IFREG)):
            fail(name, 'link or special member')
        name, metadata = tree.admit(name, directory)
        if directory and size:
            fail(name, 'nonempty directory')
        body_size(size, metadata, budget)
        entries.append((offset, raw_name, flags, method, crc, stored, size, name, metadata))
    end = 0
    for offset, raw_name, flags, method, crc, stored, size, name, metadata in sorted(entries):
        if offset != end or offset + 30 > cd_offset:
            fail(name, 'overlapping or unaccounted local region')
        stream.seek(offset)
        fixed = read_exact(stream, 30, budget)
        if fixed[:4] != b'PK\3\4':
            fail(name, 'invalid local header')
        local_flags, local_method = struct.unpack_from('<HH', fixed, 6)
        local_crc, local_stored, local_size = struct.unpack_from('<III', fixed, 14)
        name_len, extra_len = struct.unpack_from('<HH', fixed, 26)
        if name_len > 1025 or extra_len > budget.limits.extension:
            fail(name, 'local metadata byte limit exceeded')
        local_length = 30 + name_len + extra_len
        if offset + local_length + stored > cd_offset:
            fail(name, 'local member extent overlaps directory')
        budget.charge('structural', local_length)
        budget.charge('expanded', local_length)
        local_name = read_exact(stream, name_len, budget)
        extras = extra_fields(read_exact(stream, extra_len, budget))
        local_size, local_stored, _, _ = zip_sizes(local_size, local_stored, 0, 0, extras)
        if local_name != raw_name or local_flags != flags or local_method != method:
            fail(name, 'local/central header disagreement')
        if flags & 8:
            if local_crc not in (0, crc) or local_size not in (0, size) or local_stored not in (0, stored):
                fail(name, 'local/central size disagreement')
        elif (local_crc, local_stored, local_size) != (crc, stored, size):
            fail(name, 'local/central size or CRC disagreement')
        if size > budget.limits.expanded - budget.counts['expanded']:
            fail(name, 'expanded budget exceeded')
        retained = bytearray() if metadata else None
        actual_size, actual_crc = 0, 0
        decoder = zlib.decompressobj(-15) if method == 8 else None
        pending = b''
        left = stored
        while left or pending or (decoder and not decoder.eof):
            if not pending and left:
                pending = read_exact(stream, min(left, budget.limits.buffer), budget)
                left -= len(pending)
            if decoder:
                cap = min(budget.limits.buffer, max(1, size - actual_size))
                data = budget.decompress(decoder, pending, cap)
                pending = decoder.unconsumed_tail
                if decoder.eof and (decoder.unused_data or pending or left):
                    fail(name, 'trailing compressed member data')
            else:
                data, pending = pending, b''
            if len(data) > size - actual_size:
                fail(name, 'actual member size exceeds declaration')
            budget.charge('expanded', len(data))
            actual_size += len(data)
            actual_crc = zlib.crc32(data, actual_crc)
            if retained is not None:
                retained.extend(data)
        if actual_size != size or actual_crc != crc or (decoder and not decoder.eof):
            fail(name, 'member size, CRC or compressed end mismatch')
        end = offset + local_length + stored
        if flags & 8:
            wide = fixed[18:26] == b'\xff' * 8
            prefix = read_exact(stream, 4, budget)
            signed = prefix == b'PK\7\10'
            descriptor_size = (24 if wide else 16) - (0 if signed else 4)
            if end + descriptor_size > cd_offset:
                fail(name, 'descriptor overlaps directory')
            raw = read_exact(stream, descriptor_size - 4, budget)
            descriptor = raw if signed else prefix + raw
            parsed = struct.unpack('<IQQ' if wide else '<III', descriptor)
            if parsed != (crc, stored, size):
                fail(name, 'descriptor/central disagreement')
            budget.charge('structural', descriptor_size)
            budget.charge('expanded', descriptor_size)
            end += descriptor_size
        if retained is not None:
            tree.identity(name, bytes(retained), expected)
    if end != cd_offset:
        fail('zip', 'unaccounted local bytes')


def parse(path, kind, wanted, expected, limits=None):
    budget = Budget(limits or Limits())
    path = regular(path)
    stored = path.stat().st_size
    if stored > budget.limits.stored:
        fail(path.name, 'stored archive byte limit exceeded')
    tree = Tree(wanted)
    with path.open('rb') as stream:
        if kind == 'zip':
            parse_zip(stream, stored, tree, expected, budget)
        elif kind in ('tar', 'tar.gz'):
            parse_tar(stream, kind == 'tar.gz', tree, expected, budget)
        else:
            fail(path.name, 'unsupported archive format')
    tree.finish()
    budget.deadline()


_REQUEST_LIMIT = 16 * 1048576
_RESULT_LIMIT = 65536
_ERROR_LIMIT = 4096


def _worker_environment():
    # The absolute, isolated interpreter needs no parent variables on POSIX.
    # Windows needs SystemRoot for interpreter DLL and side-by-side loading.
    allowed = {'linux': (), 'darwin': (), 'win32': ('SYSTEMROOT',)}.get(sys.platform, ())
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _launch_worker(request_path, result):
    worker = Path(__file__).resolve().with_name('archive_worker.py')
    return subprocess.Popen([sys.executable, '-I', '-B', str(worker),
                             str(request_path), str(result)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=_worker_environment())


def check(path, kind, wanted, expected, limits=None):
    """Terminate stalled decoding independently of the parser's own clock."""
    limits = limits or Limits()
    path = Path(path).absolute()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='ricevanta-archive-worker-') as directory:
        root = Path(directory).resolve()
        request_path = root / 'request.json'
        result = root / 'result.json'
        values = dict(path=str(path), kind=kind, wanted=list(wanted), expected=expected,
                      limits=asdict(limits))
        written = 0
        with request_path.open('xb') as stream:
            for text in json.JSONEncoder(allow_nan=False).iterencode(values):
                data = text.encode('utf-8')
                if len(data) > _REQUEST_LIMIT - written:
                    fail(path.name, 'archive worker request byte limit exceeded')
                stream.write(data)
                written += len(data)
        process = _launch_worker(request_path, result)
        try:
            try:
                process.wait(timeout=max(0, limits.seconds - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                fail(path.name, 'archive supervisor deadline exceeded')
            if process.returncode != 0:
                fail(path.name, 'archive parser failed')
            try:
                data = bounded_read(result, _RESULT_LIMIT)
            except FileNotFoundError:
                fail(path.name, 'archive parser exited without result')
            except ValueError:
                fail(path.name, 'invalid parser result')
            try:
                response = decode(data, 'archive parser result')
                if not isinstance(response, dict) or set(response) != {'error'}:
                    raise ValueError('invalid result fields')
                error = response['error']
                if error is not None and (not isinstance(error, str) or
                                          len(error.encode('utf-8')) > _ERROR_LIMIT):
                    raise ValueError('invalid result error')
            except (ValueError, UnicodeError):
                fail(path.name, 'invalid parser result')
            if error is not None:
                fail(path.name, error)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
