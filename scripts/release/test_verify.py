"""Verify real files against a separate expected identity and closed inventory."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).with_name('verify.py')
ROOT = SCRIPT.resolve().parents[2]


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ricevanta-verify-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.records = self.root / 'records'
        self.artifacts = self.root / 'artifacts'
        self.records.mkdir()
        self.artifacts.mkdir()
        self.identity = {'version': '0.1.0-alpha.1', 'commit': '1'*40,
                         'channel': 'prerelease', 'sourceEpoch': 1}
        self.expected = self.root / 'expected.json'
        self.expected.write_text(json.dumps(self.identity), encoding='utf-8', newline='\n')
        self.inventory = {'schemaVersion': 1, 'records': [{
            'name': 'console.json', 'target': 'web', 'image': False,
            'artifacts': [{'name': 'console.tar.gz', 'component': 'console',
                           'format': 'tar.gz', 'identityPaths': ['build-info.json']}]}],
            'evidence': ['evidence.tar.gz']}
        self.record = {'schemaVersion': 1, 'identity': copy.deepcopy(self.identity),
                       'target': 'web', 'signing': 'unsigned-development', 'artifacts': []}
        self.pack()
        self.save()

    def pack(self, identity=None, members=None, kind='tar.gz'):
        identity = self.identity if identity is None else identity
        members = [('build-info.json', json.dumps(identity).encode(), 'file')] if members is None else members
        output = io.BytesIO()
        if kind == 'zip':
            with zipfile.ZipFile(output, 'w') as archive:
                for name, data, filetype in members:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (0o120777 if filetype == 'link' else 0o100644) << 16
                    archive.writestr(info, data)
        else:
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                for name, data, filetype in members:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    if filetype == 'link':
                        info.type = tarfile.SYMTYPE
                        info.linkname = 'outside'
                        info.size = 0
                    archive.addfile(info, io.BytesIO(data))
        recipe = self.inventory['records'][0]['artifacts'][0]
        recipe['format'] = kind
        recipe['name'] = 'console.zip' if kind == 'zip' else 'console.tar.gz'
        for path in self.artifacts.iterdir():
            path.unlink()
        (self.artifacts / recipe['name']).write_bytes(output.getvalue())
        evidence = io.BytesIO()
        with tarfile.open(fileobj=evidence, mode='w:gz') as archive:
            info = tarfile.TarInfo('evidence.txt')
            info.size = 8
            archive.addfile(info, io.BytesIO(b'evidence'))
        (self.artifacts / 'evidence.tar.gz').write_bytes(evidence.getvalue())
        self.record['artifacts'] = [{'name': recipe['name'], 'component': 'console',
                                     'bytes': len(output.getvalue()),
                                     'sha256': hashlib.sha256(output.getvalue()).hexdigest()}]

    def save(self):
        self.inventory_path = self.root / 'inventory.json'
        self.inventory_path.write_text(json.dumps(self.inventory), encoding='utf-8', newline='\n')
        (self.records / 'console.json').write_text(json.dumps(self.record), encoding='utf-8', newline='\n')
        files = list(self.records.iterdir()) + [p for p in self.artifacts.iterdir() if p.name != 'SHA256SUMS']
        sums = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                       for p in sorted(files, key=lambda p: p.name) if p.is_file())
        (self.artifacts / 'SHA256SUMS').write_text(sums, encoding='utf-8', newline='\n')

    def run_verify(self):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), '--records', str(self.records),
                               '--artifacts', str(self.artifacts), '--inventory', str(self.inventory_path),
                               '--expected-identity', str(self.expected)], capture_output=True, text=True)

    def reject(self, item=None):
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if item:
            self.assertIn(item, result.stderr)

    def test_valid_tar_and_zip(self):
        for kind in ('tar.gz', 'zip'):
            self.pack(kind=kind)
            self.save()
            result = self.run_verify()
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_payload(self):
        with (self.artifacts / 'console.tar.gz').open('ab') as stream:
            stream.write(b'changed')
        self.reject('console.tar.gz')

    def test_record_each_identity_field(self):
        for field, value in (('version', '0.1.0-beta.1'), ('commit', '2'*40),
                             ('channel', 'pr'), ('sourceEpoch', 2)):
            with self.subTest(field=field):
                self.record['identity'] = dict(self.identity, **{field: value})
                self.save()
                self.reject('console.json')

    def test_embedded_each_identity_field(self):
        for field, value in (('version', '0.1.0-beta.1'), ('commit', '2'*40),
                             ('channel', 'pr'), ('sourceEpoch', 2)):
            with self.subTest(field=field):
                self.pack(dict(self.identity, **{field: value}))
                self.save()
                self.reject('build-info.json')

    def test_self_consistent_pr_set_cannot_replace_prerelease(self):
        candidate = dict(self.identity, version='0.1.0-dev.0+g' + '1'*40, channel='pr')
        self.pack(candidate)
        self.record['identity'] = candidate
        self.save()
        self.reject('console.json')

    def test_bad_digest_and_component(self):
        for field, value in (('sha256', 'A'*64), ('sha256', 'abc'), ('component', 'agent'), ('bytes', 1)):
            with self.subTest(field=field):
                old = self.record['artifacts'][0][field]
                self.record['artifacts'][0][field] = value
                self.save()
                self.reject('console')
                self.record['artifacts'][0][field] = old

    def test_duplicate_case_collision_and_traversal_names(self):
        original = copy.deepcopy(self.record['artifacts'][0])
        for name in ('console.tar.gz', 'CONSOLE.tar.gz', '../console.tar.gz'):
            with self.subTest(name=name):
                self.record['artifacts'] = [original, dict(original, name=name)]
                self.save()
                self.reject('console')

    def test_archive_links_traversal_duplicates_and_missing_identity(self):
        good = json.dumps(self.identity).encode()
        for kind in ('tar.gz', 'zip'):
            for members in ([('build-info.json', b'outside', 'link')],
                            [('../build-info.json', good, 'file')],
                            [('build-info.json', good, 'file'), ('BUILD-INFO.json', good, 'file')],
                            [('payload', b'no identity', 'file')],
                            [('build-info.json', b'{"version":1,"version":2}', 'file')]):
                with self.subTest(kind=kind, members=members):
                    self.pack(members=members, kind=kind)
                    self.save()
                    self.reject()

    def test_extra_missing_and_symlink_files(self):
        path = self.artifacts / 'extra'
        path.write_bytes(b'extra')
        self.reject('extra')
        path.unlink()
        path = self.artifacts / 'console.tar.gz'
        data = path.read_bytes()
        path.unlink()
        self.reject('console.tar.gz')
        outside = self.root / 'outside'
        outside.write_bytes(data)
        path.symlink_to(outside)
        self.reject('console.tar.gz')

    def test_extra_record_and_record_symlink(self):
        path = self.records / 'extra.json'
        path.write_text('{}', encoding='utf-8', newline='\n')
        self.reject('extra.json')
        path.unlink()
        original = self.records / 'console.json'
        outside = self.root / 'outside.json'
        outside.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(outside)
        self.reject('console.json')

    def test_closed_inventory_and_missing_recipe(self):
        for mutate in (lambda d: d.update(shell='echo hi'),
                       lambda d: d.update(schemaVersion=2),
                       lambda d: d.update(records=[]),
                       lambda d: d['records'][0].update(command='echo hi'),
                       lambda d: d['records'][0]['artifacts'][0].update(format='shell')):
            old = copy.deepcopy(self.inventory)
            mutate(self.inventory)
            self.save()
            self.reject('inventory')
            self.inventory = old

    def test_expected_identity_must_be_separate_and_schema_valid(self):
        self.expected.write_text(json.dumps(dict(self.identity, extra=True)), encoding='utf-8', newline='\n')
        self.reject('expected')
        self.expected = self.artifacts / 'expected.json'
        self.expected.write_text(json.dumps(self.identity), encoding='utf-8', newline='\n')
        self.reject('expected')

    def test_synthetic_fixture_cannot_pass_real_file_verification(self):
        self.record = json.loads((ROOT / 'schemas/build/v1/example.json').read_text())
        self.save()
        self.reject()

    def test_checksums_complete_sorted_lowercase_and_no_paths(self):
        path = self.artifacts / 'SHA256SUMS'
        original = path.read_text()
        for changed in (original.upper(), original.splitlines()[0] + '\n',
                        original + original.splitlines()[0] + '\n',
                        original.replace('console.json', '../console.json'),
                        '\n'.join(reversed(original.splitlines())) + '\n'):
            path.write_text(changed, encoding='utf-8', newline='\n')
            self.reject('SHA256SUMS')
        path.write_text(original, encoding='utf-8', newline='\n')

    def test_image_metadata_not_allowed_on_non_image_recipe(self):
        self.record['image'] = json.loads((ROOT / 'schemas/build/v1/example-image.json').read_text())['image']
        self.save()
        self.reject('console.json')

    def test_image_recipe_requires_metadata(self):
        self.inventory['records'][0].update(image=True, target='linux-x64')
        self.record['target'] = 'linux-x64'
        self.record['image'] = json.loads((ROOT / 'schemas/build/v1/example-image.json').read_text())['image']
        self.save()
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        del self.record['image']
        self.save()
        self.reject('console.json')

    def test_missing_record(self):
        # An absent expected record must fail before candidate identities are read.
        (self.records / 'console.json').unlink()
        self.reject('console.json')

    def test_unlisted_identity_inside_archive_checked(self):
        different = dict(self.identity, sourceEpoch=2)
        self.pack(members=[('build-info.json', json.dumps(self.identity).encode(), 'file'),
                           ('agent/build-info.json', json.dumps(different).encode(), 'file')])
        self.save()
        self.reject('agent/build-info.json')

    def test_expected_dev_identity_commit_mismatch(self):
        self.expected.write_text(json.dumps(dict(self.identity, channel='pr',
                                                version='0.1.0-dev.0+g' + '2'*40)), encoding='utf-8', newline='\n')
        self.reject('expected')

    def test_duplicate_json_inventory_and_unknown_artifact_field(self):
        self.inventory_path.write_text('{"schemaVersion":1,"schemaVersion":1,"records":[],"evidence":[]}', encoding='utf-8', newline='\n')
        self.reject('inventory')
        self.inventory['records'][0]['artifacts'][0]['command'] = 'echo unsafe'
        self.save()
        self.reject('inventory')

    def test_schema_valid_channel_substitutions(self):
        for channel, substitute in (('master', 'pr'), ('pr', 'master')):
            self.identity = dict(self.identity, version='0.1.0-dev.0+g' + '1'*40, channel=channel)
            self.expected.write_text(json.dumps(self.identity), encoding='utf-8', newline='\n')
            for location in ('record', 'embedded'):
                with self.subTest(channel=channel, location=location):
                    candidate = dict(self.identity, channel=substitute)
                    self.record['identity'] = candidate if location == 'record' else self.identity
                    self.pack(candidate if location == 'embedded' else self.identity)
                    self.save()
                    self.reject('channel differs')

    def test_oversized_identity_whitespace(self):
        good = json.dumps(self.identity).encode()
        for kind in ('tar.gz', 'zip'):
            for size in (65536, 65537):
                self.pack(members=[('build-info.json', b' ' * (size - len(good)) + good, 'file')], kind=kind)
                self.save()
                result = self.run_verify()
                self.assertEqual(result.returncode == 0, size == 65536, result.stderr)

    def test_path_tree_and_metadata_case(self):
        good = ('build-info.json', json.dumps(self.identity).encode(), 'file')
        for kind in ('tar.gz', 'zip'):
            for names in (('payload', 'payload/child'), ('payload/child', 'payload'),
                          ('Dir/a', 'dir/b'), ('agent/BUILD-INFO.JSON',)):
                with self.subTest(kind=kind, names=names):
                    self.pack(members=[good] + [(n, b'{}', 'file') for n in names], kind=kind)
                    self.save()
                    self.reject()

    def test_corrupt_nonidentity_zip_crc_with_updated_outer_hashes(self):
        self.pack(kind='zip', members=[('build-info.json', json.dumps(self.identity).encode(), 'file'),
                                      ('payload', b'unique-payload-bytes', 'file')])
        path = self.artifacts / 'console.zip'
        data = path.read_bytes().replace(b'unique-payload-bytes', b'changed-payload-byte')
        self.assertEqual(len(data), path.stat().st_size)
        path.write_bytes(data)
        self.record['artifacts'][0].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.save()
        self.reject()

    def test_evidence_requires_structurally_valid_archive(self):
        (self.artifacts / 'evidence.tar.gz').write_bytes(b'not an archive')
        self.save()
        self.reject('evidence')

    def test_inventory_trusted_version_expansion(self):
        original = self.inventory['records'][0]['artifacts'][0]
        for identity in (self.identity, dict(self.identity, channel='master', version='0.1.0-dev.0+g' + '1'*40)):
            self.identity = identity
            self.expected.write_text(json.dumps(identity), encoding='utf-8', newline='\n')
            self.record['identity'] = identity
            self.pack()
            old = self.artifacts / 'console.tar.gz'
            expanded = 'console_' + identity['version'] + '.tar.gz'
            old.rename(self.artifacts / expanded)
            self.inventory['records'][0]['artifacts'][0]['name'] = 'console_{version}.tar.gz'
            self.record['artifacts'][0]['name'] = expanded
            self.save()
            result = self.run_verify()
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_strict_json_control_inputs(self):
        original = self.expected.read_bytes()
        for raw in (b'\xef\xbb\xbf' + original, b'\xff', original + b'{}',
                    original.replace(b'"sourceEpoch": 1', b'"sourceEpoch": true'),
                    original.replace(b'"sourceEpoch": 1', b'"sourceEpoch": NaN'),
                    original.replace(b'"sourceEpoch": 1', b'"sourceEpoch": Infinity'),
                    original.replace(b'"commit":', b'"extra":"\\ud800","commit":')):
            with self.subTest(raw=raw):
                self.expected.write_bytes(raw)
                self.reject()
        self.expected.write_bytes(original)

    def test_inventory_invalid_shapes_placeholders_and_component_identity(self):
        from release_common import load
        import verify
        original = copy.deepcopy(self.inventory)
        changes = [lambda d: d.update(schemaVersion=True),
                   lambda d: d['records'][0].update(name='record_{version}.json'),
                   lambda d: d.update(evidence=['evidence_{version}.zip']),
                   lambda d: d['records'][0].update(image=True, target='web')]
        for name in ('console_{unknown}.tar.gz', 'console_{version}_{version}.tar.gz',
                     'a' * 230 + '{version}.tar.gz', 'console_{version}.tar.gz\n'):
            changes.append(lambda d, name=name: d['records'][0]['artifacts'][0].update(name=name))
        for paths in ([], [''], ['../identity.json'], ['a', 'A']):
            changes.append(lambda d, paths=paths: d['records'][0]['artifacts'][0].update(identityPaths=paths))
        changes.append(lambda d: d['records'][0]['artifacts'].append({
            'name': 'agent.spdx.json', 'component': 'agent', 'format': 'sbom', 'identityPaths': []}))
        for change in changes:
            self.inventory = copy.deepcopy(original)
            change(self.inventory)
            self.save()
            with self.assertRaises(ValueError): verify.inventory(self.inventory_path, self.identity)
        self.inventory = original

    def test_inventory_expansion_collisions_with_all_name_classes(self):
        import verify
        original = copy.deepcopy(self.inventory)
        for location in ('literal', 'evidence', 'record', 'reserved'):
            self.inventory = copy.deepcopy(original)
            artifact = self.inventory['records'][0]['artifacts'][0]
            artifact['name'] = 'artifact_{version}.zip'
            expanded = 'artifact_0.1.0-alpha.1.zip'
            if location == 'literal':
                self.inventory['records'][0]['artifacts'].append(dict(artifact, name=expanded))
            elif location == 'evidence': self.inventory['evidence'] = [expanded]
            elif location == 'record': self.inventory['records'][0]['name'] = expanded
            else: artifact['name'] = 'SHA256SUMS'
            self.save()
            with self.assertRaises(ValueError): verify.inventory(self.inventory_path, self.identity)
        self.inventory = original

    def test_candidate_cannot_select_expanded_version(self):
        self.inventory['records'][0]['artifacts'][0]['name'] = 'console_{version}.tar.gz'
        (self.artifacts / 'console.tar.gz').rename(self.artifacts / 'console_0.2.0-alpha.1.tar.gz')
        self.record['artifacts'][0]['name'] = 'console_0.2.0-alpha.1.tar.gz'
        self.save()
        self.reject()

    def test_nested_duplicate_keys_record_and_embedded(self):
        original = (self.records / 'console.json').read_bytes()
        (self.records / 'console.json').write_bytes(original.replace(b'"sourceEpoch": 1', b'"sourceEpoch": 1, "sourceEpoch": 1'))
        self.reject('duplicate JSON')
        (self.records / 'console.json').write_bytes(original)
        good = json.dumps(self.identity).encode()
        self.pack(members=[('build-info.json', good.replace(b'"sourceEpoch": 1', b'"sourceEpoch": 1, "sourceEpoch": 1'), 'file')])
        self.save()
        self.reject('duplicate JSON')

    def test_boolean_record_integer_rejected(self):
        self.record['artifacts'][0]['bytes'] = True
        self.save()
        self.reject()

    def test_linked_parents_hardlinks_and_special_files(self):
        import os
        original = self.artifacts / 'console.tar.gz'
        linked = self.root / 'link'
        linked.hardlink_to(original)
        self.reject()
        linked.unlink()
        real = self.artifacts
        self.artifacts = self.root / 'linked-parent'
        self.artifacts.symlink_to(real, target_is_directory=True)
        self.reject()
        self.artifacts = real
        if hasattr(os, 'mkfifo'):
            original.unlink()
            os.mkfifo(original)
            self.reject()

    def test_evidence_archive_structural_controls(self):
        import gzip
        from test_archives import tar_bytes, zip_bytes
        original = self.inventory['evidence']
        for kind in ('tar', 'tar.gz', 'zip'):
            name = 'evidence.' + kind
            self.inventory['evidence'] = [name]
            for paths in (('payload', 'payload/child'), ('dir/BUILD-INFO.JSON',), ('../escape',)):
                data = zip_bytes([(p, b'') for p in paths]) if kind == 'zip' else tar_bytes([(p, b'', tarfile.REGTYPE) for p in paths])
                if kind == 'tar.gz': data = gzip.compress(data)
                for path in self.artifacts.glob('evidence.*'): path.unlink()
                (self.artifacts / name).write_bytes(data)
                self.save()
                self.reject('evidence')
        self.inventory['evidence'] = original

    def test_float_record_integer_fields_rejected(self):
        for field in ('schemaVersion', 'bytes'):
            original = copy.deepcopy(self.record)
            if field == 'schemaVersion': self.record[field] = 1.0
            else: self.record['artifacts'][0][field] = float(self.record['artifacts'][0][field])
            self.save()
            self.reject()
            self.record = original


if __name__ == '__main__':
    unittest.main()
