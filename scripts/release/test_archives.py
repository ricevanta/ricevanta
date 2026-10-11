"""Reject unsafe archive structures before retaining unbounded candidate bytes."""
import dataclasses
import gzip
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import warnings
from unittest.mock import patch
import zipfile
import zlib

import archives

IDENTITY = {'version': '0.1.0-alpha.1', 'commit': '1' * 40,
            'channel': 'prerelease', 'sourceEpoch': 1}


def tar_bytes(members):
    data = bytearray()
    for name, body, kind in members:
        header = tarfile.TarInfo(name)
        header.type = kind
        header.size = len(body)
        data.extend(header.tobuf(format=tarfile.USTAR_FORMAT))
        data.extend(body)
        data.extend(b'\0' * (-len(body) % 512))
    data.extend(b'\0' * 1024)
    data.extend(b'\0' * (-len(data) % 10240))
    return bytes(data)


def pax(key, value):
    tail = f' {key}={value}\n'.encode()
    count = len(tail) + 1
    while len(str(count)) + len(tail) != count:
        count = len(str(count)) + len(tail)
    return str(count).encode() + tail


def zip_bytes(members, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(out, 'w', compression=compression) as archive:
        warnings.filterwarnings('ignore', message='Duplicate name:', category=UserWarning)
        for name, body in members:
            archive.writestr(name, body)
    return out.getvalue()


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ricevanta-archive-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / 'fixture'

    def parse(self, data, kind='tar', **limits):
        self.path.write_bytes(data)
        archives.parse(self.path, kind, [], IDENTITY,
                       dataclasses.replace(archives.Limits(), **limits))

    def reject(self, data, kind='tar', **limits):
        with self.assertRaises(ValueError):
            self.parse(data, kind, **limits)

    def test_stored_member_header_expanded_and_structural_boundaries(self):
        tar = tar_bytes([('a', b'x' * 512, tarfile.REGTYPE)])
        zipdata = zip_bytes([('a', b'x' * 512)])
        for kind, data in (('tar', tar), ('zip', zipdata)):
            for field, boundary in (('stored', len(data)), ('members', 1), ('member', 512)):
                with self.subTest(kind=kind, field=field):
                    self.parse(data, kind, **{field: boundary})
                    self.reject(data, kind, **{field: boundary - 1})
        self.parse(tar, expanded=len(tar))
        self.reject(tar, expanded=len(tar) - 1)
        # ZIP structural bytes are central + local headers + end record.
        structural = len(zipdata) - 512
        self.parse(zipdata, 'zip', structural=structural, expanded=len(zipdata))
        self.reject(zipdata, 'zip', structural=structural - 1)
        self.reject(zipdata, 'zip', expanded=len(zipdata) - 1)

    def test_path_length_depth_and_segment_boundaries(self):
        for kind in ('tar', 'zip'):
            for name in ('a/' * 31 + 'b', 'a' * 240 + '/' + 'b' * 240 + '/' + 'c' * 240 + '/' + 'd' * 240 + '/' + 'e' * 60):
                data = zip_bytes([(name, b'')]) if kind == 'zip' else tar_bytes([('pax', pax('path', name), tarfile.XHDTYPE), ('a', b'', tarfile.REGTYPE)])
                self.parse(data, kind)
            for name in ('a/' * 32 + 'b', 'a' * 241, 'a' * 240 + '/' + 'b' * 240 + '/' + 'c' * 240 + '/' + 'd' * 240 + '/' + 'e' * 61,
                         'CoN.txt', 'dir/lPt9.exe', '../a', 'a//b', 'a\\b', '/a', 'C:a'):
                data = zip_bytes([(name, b'')]) if kind == 'zip' else tar_bytes([('pax', pax('path', name), tarfile.XHDTYPE), ('a', b'', tarfile.REGTYPE)])
                self.reject(data, kind)

    def test_raw_tar_reads_fit_remaining_expanded_budget(self):
        empty_member = tar_bytes([('a', b'', tarfile.REGTYPE)])
        tiny_member = tar_bytes([('a', b'x', tarfile.REGTYPE)])
        extension = pax('mtime', '1' * 65523)
        self.assertEqual(len(extension), 65536)
        extended = tar_bytes([('pax', extension, tarfile.XHDTYPE),
                              ('a', b'', tarfile.REGTYPE)])
        cases = (('first header', empty_member, 511),
                 ('next header', tar_bytes([('a', b'', tarfile.REGTYPE),
                                           ('b', b'', tarfile.REGTYPE)]), 513),
                 ('PAX body', extended, 513),
                 ('member padding', tiny_member, 514),
                 ('first terminal block', empty_member, 513),
                 ('second terminal block', empty_member, 1025),
                 ('record padding', empty_member, 1537),
                 ('trailing byte', empty_member + b'x', len(empty_member)))
        for name, data, limit in cases:
            with self.subTest(part=name):
                budget = archives.Budget(dataclasses.replace(archives.Limits(), expanded=limit))
                requests = []
                class Guard(io.BytesIO):
                    def read(stream, count=-1):
                        remaining = limit - budget.counts['expanded']
                        self.assertGreater(count, 0)
                        self.assertLessEqual(count, remaining, 'allocation exceeds remaining budget')
                        requests.append(count)
                        return super().read(count)
                with self.assertRaisesRegex(ValueError, 'expanded.*budget exceeded'):
                    archives.parse_tar(Guard(data), False, archives.Tree([]), IDENTITY, budget)
                self.assertTrue(requests)

    def test_raw_tar_exact_budget_and_short_reads(self):
        data = tar_bytes([('a', b'x', tarfile.REGTYPE)])
        for short in (False, True):
            with self.subTest(short=short):
                budget = archives.Budget(dataclasses.replace(archives.Limits(), expanded=len(data)))
                class Guard(io.BytesIO):
                    def read(stream, count=-1):
                        self.assertGreater(count, 0)
                        self.assertLessEqual(count, len(data) - budget.counts['expanded'])
                        return super().read(min(count, 7) if short else count)
                archives.parse_tar(Guard(data), False, archives.Tree([]), IDENTITY, budget)
                self.assertEqual(budget.counts['expanded'], len(data))

    def test_directory_tree_in_both_orders(self):
        cases = [([('a/b', b'', tarfile.REGTYPE), ('a', b'', tarfile.DIRTYPE)], True),
                 ([('a', b'', tarfile.DIRTYPE), ('a/b', b'', tarfile.REGTYPE)], True),
                 ([('a', b'', tarfile.REGTYPE), ('a/b', b'', tarfile.REGTYPE)], False),
                 ([('a/b', b'', tarfile.REGTYPE), ('a', b'', tarfile.REGTYPE)], False),
                 ([('A/b', b'', tarfile.REGTYPE), ('a/c', b'', tarfile.REGTYPE)], False),
                 ([('a', b'', tarfile.DIRTYPE), ('a', b'', tarfile.DIRTYPE)], False),
                 ([('a', b'x', tarfile.DIRTYPE)], False)]
        for members, valid in cases:
            for kind in ('tar', 'zip'):
                with self.subTest(kind=kind, members=members):
                    data = tar_bytes(members) if kind == 'tar' else zip_bytes([(n + ('/' if t == tarfile.DIRTYPE else ''), b) for n, b, t in members])
                    (self.parse if valid else self.reject)(data, kind)

    def test_tar_end_and_gzip_integrity(self):
        good = tar_bytes([('a', b'abc', tarfile.REGTYPE)])
        self.parse(good)
        for data in (good + good, good + b'\0' * 10240, good[:-1], good[:1024] + b'\0' * 512,
                     good[:-1] + b'x', b'x' + good[1:]):
            self.reject(data)
        compressed = gzip.compress(good)
        self.parse(compressed, 'tar.gz')
        for data in (compressed[:-1], compressed + b'x', compressed + compressed,
                     compressed[:-8] + b'\0' * 8):
            self.reject(data, 'tar.gz')

    def test_tar_rejects_other_types_and_pax_sequences(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                     tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE, tarfile.GNUTYPE_LONGNAME, tarfile.XGLTYPE, b'Z'):
            self.reject(tar_bytes([('a', b'', kind)]))
        extension = ('pax', pax('path', 'a'), tarfile.XHDTYPE)
        self.reject(tar_bytes([extension]))
        self.reject(tar_bytes([extension, extension, ('a', b'', tarfile.REGTYPE)]))

    def test_pax_allowed_keys_and_extension_budgets(self):
        for key, value in (('path', 'dir/a'), ('size', '1'), ('mtime', '1.123456789'),
                           ('uid', '0'), ('gid', '12'), ('uname', 'user'), ('gname', 'group')):
            body = pax(key, value)
            data = tar_bytes([('pax', body, tarfile.XHDTYPE), ('a', b'x', tarfile.REGTYPE)])
            self.parse(data, extension=len(body), structural=len(body) + 1024, members=2)
            self.reject(data, extension=len(body) - 1)
            self.reject(data, structural=len(body) + 1023)
            self.reject(data, members=1)
        for body in (pax('unknown', 'x'), pax('path', 'a') * 2, b'4 a=x\n', b'99 a=x\n',
                     pax('size', '01'), pax('uid', '-1'), pax('mtime', '1.1234567890'),
                     pax('mtime', 'NaN'), pax('path', '../escape'), pax('uname', 'x' * 241),
                     pax('gname', '\t'), pax('path', 'a\0b'), b'12 path=\xff\n'):
            self.reject(tar_bytes([('pax', body, tarfile.XHDTYPE), ('a', b'', tarfile.REGTYPE)]))

    def test_zip_header_crc_encryption_methods_overlap_and_truncation(self):
        good = zip_bytes([('a', b'payload'), ('b', b'body')])
        self.parse(good, 'zip')
        central = good.index(b'PK\1\2')
        controls = [good.replace(b'payload', b'PAYLOAD'), good[:-1]]
        for offset, fmt, value in ((6, '<H', 1), (8, '<H', 12), (18, '<I', 8),
                                   (central + 8, '<H', 1), (central + 10, '<H', 12),
                                   (central + 20, '<I', 8), (central + 42, '<I', 1)):
            changed = bytearray(good)
            struct.pack_into(fmt, changed, offset, value)
            controls.append(bytes(changed))
        controls.append(good[:30] + b'z' + good[31:])
        for data in controls:
            self.reject(data, 'zip')
        self.parse(zip_bytes([('a', b'x' * 1024)], zipfile.ZIP_DEFLATED), 'zip')
        # False EOCD count must not conceal real central entries.
        changed = bytearray(good)
        struct.pack_into('<HH', changed, len(changed) - 14, 1, 1)
        self.reject(bytes(changed), 'zip')

    def test_decoder_byte_call_and_deadline_budgets(self):
        raw = gzip.compress(tar_bytes([('a', b'x', tarfile.REGTYPE)]))
        for limit in ({'work': 1}, {'calls': 0}, {'seconds': 0}):
            self.reject(raw, 'tar.gz', **limit)
        budget = archives.Budget(dataclasses.replace(archives.Limits(), work=4, calls=1))
        decoder = zlib.decompressobj()
        # Charging precedes the actual decoder call.
        with self.assertRaises(ValueError):
            budget.decompress(decoder, b'abc', 2)
        class Stalled:
            unconsumed_tail = b'x'
            unused_data = b''
            eof = False
            def decompress(self, data, cap):
                return b''
        with self.assertRaises(ValueError):
            archives.Budget(archives.Limits()).decompress(Stalled(), b'x', 1)

    def test_reads_and_decoder_output_are_bounded(self):
        data = gzip.compress(tar_bytes([('a', b'x' * 200000, tarfile.REGTYPE)]))
        real_open = Path.open
        requests = []
        class Guard:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def read(self, count=-1):
                requests.append(count)
                if count < 0 or count > 65536:
                    raise AssertionError('unbounded read')
                return self.stream.read(count)
            def __getattr__(self, name): return getattr(self.stream, name)
        self.path.write_bytes(data)
        with patch.object(Path, 'open', lambda path, *args, **kw: Guard(real_open(path, *args, **kw))):
            archives.parse(self.path, 'tar.gz', [], IDENTITY)
        self.assertTrue(requests)
        self.assertLessEqual(max(requests), 65536)

    def test_extension_exact_65536_and_before_allocation(self):
        # mtime's grammar permits a large unsigned integer without conversion.
        body = pax('mtime', '1' * 65523)
        while len(body) != 65536:
            body = pax('mtime', '1' * (65523 + 65536 - len(body)))
        data = tar_bytes([('pax', body, tarfile.XHDTYPE), ('a', b'', tarfile.REGTYPE)])
        self.parse(data)
        self.reject(data, extension=65535)
        larger = pax('mtime', '1' * 65524)
        self.reject(tar_bytes([('pax', larger, tarfile.XHDTYPE), ('a', b'', tarfile.REGTYPE)]))
        self.path.write_bytes(data)
        original = archives.read_exact
        requests = []
        def guarded(stream, size, budget):
            requests.append(size)
            if size > 512:
                self.fail('oversized extension requested before rejection')
            return original(stream, size, budget)
        with patch.object(archives, 'read_exact', side_effect=guarded), self.assertRaises(ValueError):
            archives.parse(self.path, 'tar', [], IDENTITY,
                           dataclasses.replace(archives.Limits(), extension=65535))
        self.assertEqual(requests, [512])

    def test_work_calls_and_deadline_exact_boundaries(self):
        class Decoder:
            eof = True
            unconsumed_tail = b''
            unused_data = b''
            def decompress(self, data, cap): return b'x' * cap
        for field, value in (('work', 5), ('calls', 1)):
            limits = dataclasses.replace(archives.Limits(), **{field: value})
            self.assertEqual(archives.Budget(limits).decompress(Decoder(), b'abc', 2), b'xx')
            limits = dataclasses.replace(limits, **{field: value - 1})
            with self.assertRaises(ValueError):
                archives.Budget(limits).decompress(Decoder(), b'abc', 2)
        ticks = iter((0, 119.999, 120))
        budget = archives.Budget(archives.Limits(), clock=lambda: next(ticks))
        budget.deadline()
        with self.assertRaises(ValueError): budget.deadline()
        class OutputGuard(Decoder):
            eof = False
            def decompress(self, data, cap):
                if cap <= 0 or cap > 65536: raise AssertionError('unbounded decoder output')
                self.eof = True
                return b'x'
        archives.Budget(archives.Limits()).decompress(OutputGuard(), b'abc', 65536)

    def test_zip_preflight_counts_before_member_table_and_large_metadata_reads(self):
        data = zip_bytes([('a', b''), ('b', b'')])
        self.path.write_bytes(data)
        with patch.object(archives.Tree, 'admit', side_effect=AssertionError('member table created')):
            with self.assertRaises(ValueError):
                archives.parse(self.path, 'zip', [], IDENTITY,
                               dataclasses.replace(archives.Limits(), members=1))
        changed = bytearray(data)
        central = data.index(b'PK\1\2')
        struct.pack_into('<H', changed, central + 28, 65535)
        self.reject(bytes(changed), 'zip')

    def test_tar_effective_pax_size_and_directory_rules(self):
        self.reject(tar_bytes([('pax', pax('size', '2049'), tarfile.XHDTYPE),
                               ('a', b'', tarfile.REGTYPE)]), member=2048)
        self.reject(tar_bytes([('pax', pax('path', 'dir/'), tarfile.XHDTYPE),
                               ('a', b'', tarfile.REGTYPE)]))
        self.parse(tar_bytes([('pax', pax('path', 'dir/'), tarfile.XHDTYPE),
                              ('a', b'', tarfile.DIRTYPE)]))

    def test_zip64_local_headers_and_descriptors(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            with archive.open('a', 'w', force_zip64=True) as member:
                member.write(b'payload')
        self.parse(out.getvalue(), 'zip')
        class Unseekable(io.BytesIO):
            def seekable(self): return False
            def seek(self, *args): raise io.UnsupportedOperation('not seekable')
        out = Unseekable()
        with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('a', b'payload')
        self.parse(out.getvalue(), 'zip')
        changed = bytearray(out.getvalue())
        descriptor = changed.index(b'PK\7\10')
        changed[descriptor + 4] ^= 1
        self.reject(bytes(changed), 'zip')

    def test_metadata_casing_and_directory_even_when_unlisted(self):
        for kind in ('tar', 'zip'):
            for name in ('BUILD-INFO.JSON', 'dir/Identity.Json', 'identity.json/'):
                directory = name.endswith('/')
                data = zip_bytes([(name, b'')]) if kind == 'zip' else tar_bytes([(name, b'', tarfile.DIRTYPE if directory else tarfile.REGTYPE)])
                self.reject(data, kind)

    def test_tar_header_structural_budget_before_body(self):
        data = tar_bytes([('a', b'x' * 200000, tarfile.REGTYPE)])
        self.parse(data, structural=512)
        self.reject(data, structural=511)

    def test_metadata_name_cannot_be_implicit_directory(self):
        for name in ('identity.json/child', 'dir/BUILD-INFO.JSON/child'):
            for kind in ('tar', 'zip'):
                with self.subTest(kind=kind, name=name):
                    data = zip_bytes([(name, b'')]) if kind == 'zip' else tar_bytes([(name, b'', tarfile.REGTYPE)])
                    self.reject(data, kind)

    def test_zip_stored_compression_flags_and_dos_directory_disagreement(self):
        data = zip_bytes([('a', b'x')])
        central = data.index(b'PK\1\2')
        changed = bytearray(data)
        struct.pack_into('<H', changed, 6, 2)
        struct.pack_into('<H', changed, central + 8, 2)
        self.reject(bytes(changed), 'zip')
        changed = bytearray(data)
        struct.pack_into('<I', changed, central + 38, 0x10)
        self.reject(bytes(changed), 'zip')

    def test_gzip_expanded_stream_boundary(self):
        data = tar_bytes([('a', b'x' * 512, tarfile.REGTYPE)])
        self.parse(gzip.compress(data), 'tar.gz', expanded=len(data))
        self.reject(gzip.compress(data), 'tar.gz', expanded=len(data) - 1)

    def test_truncated_deflate_and_two_local_regions_overlap(self):
        original = zip_bytes([('a', b'x' * 1000)], zipfile.ZIP_DEFLATED)
        central = original.index(b'PK\1\2')
        stored = struct.unpack_from('<I', original, 18)[0]
        changed = bytearray(original[:central - 1] + original[central:])
        struct.pack_into('<I', changed, 18, stored - 1)
        struct.pack_into('<I', changed, central - 1 + 20, stored - 1)
        struct.pack_into('<I', changed, len(changed) - 6, central - 1)
        self.reject(bytes(changed), 'zip')
        original = zip_bytes([('a', b'a'), ('b', b'b')])
        first = original.index(b'PK\1\2')
        second = original.index(b'PK\1\2', first + 4)
        changed = bytearray(original)
        struct.pack_into('<I', changed, second + 42, 0)
        self.reject(bytes(changed), 'zip')

    def test_large_deflate_body_streamed_to_verified_end(self):
        for size in (65536, 65537, 200000):
            data = zip_bytes([('payload', b'x' * size)], zipfile.ZIP_DEFLATED)
            self.parse(data, 'zip', member=size)
            self.reject(data, 'zip', member=size - 1)

    def test_deflate_residual_output_keeps_size_crc_and_end_checks(self):
        data = zip_bytes([('payload', b'abc')], zipfile.ZIP_DEFLATED)

        class ResidualDecoder:
            unconsumed_tail = b''
            unused_data = b''
            eof = False

            def __init__(self, output, valid_end=True):
                self.output = output
                self.first = True
                self.valid_end = valid_end

            def decompress(self, compressed, cap):
                if self.first:
                    self.first = False
                    if not compressed:
                        raise AssertionError('first step needs compressed input')
                    output, self.output = self.output[:2], self.output[2:]
                    return output
                if compressed:
                    raise AssertionError('residual step must use empty input')
                output, self.output = self.output[:cap], self.output[cap:]
                self.eof = not self.output and self.valid_end
                return output

        for output, valid_end, accepted in ((b'abc', True, True),
                                            (b'abX', True, False),
                                            (b'abcd', True, False),
                                            (b'abc', False, False)):
            with self.subTest(output=output, valid_end=valid_end):
                with patch.object(archives.zlib, 'decompressobj',
                                  return_value=ResidualDecoder(output, valid_end)):
                    if accepted:
                        self.parse(data, 'zip')
                    else:
                        self.reject(data, 'zip')

    def test_deflate_one_byte_buffer_drains_real_decoder(self):
        data = zip_bytes([('payload', b'x' * 31)], zipfile.ZIP_DEFLATED)
        self.parse(data, 'zip', buffer=1)

    def test_gzip_reader_drains_residual_output_before_end(self):
        class ResidualDecoder:
            unconsumed_tail = b''
            unused_data = b''
            eof = False

            def __init__(self):
                self.first = True

            def decompress(self, data, cap):
                if self.first:
                    self.first = False
                    return b'a'
                self.eof = True
                return b'b'

        # A valid bounded decoder may retain output after consuming all input.
        compressed = gzip.compress(b'ab')
        for valid_end in (True, False):
            with self.subTest(valid_end=valid_end):
                decoder = ResidualDecoder()
                with patch.object(archives.zlib, 'decompressobj', return_value=decoder):
                    reader = archives.TarReader(io.BytesIO(compressed), True,
                                                archives.Budget(archives.Limits()))
                    self.assertEqual(reader.read(1), b'a')
                    if valid_end:
                        self.assertEqual(reader.read(1), b'b')
                        self.assertEqual(reader.read(1), b'')
                    else:
                        decoder.decompress = lambda data, cap: b''
                        with self.assertRaisesRegex(ValueError, 'no progress'):
                            reader.read(1)


if __name__ == '__main__':
    unittest.main()
