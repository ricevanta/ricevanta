"""Regression checks for the schema-validation command."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


class ValidatorCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ricevanta-validator-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = Path(__file__).resolve().parents[3]
        self.directory = self.root / 'schemas/policy/v1alpha1'
        shutil.copytree(source / 'schemas/policy/v1alpha1', self.directory)
        self.spec = self.root / 'docs/specs/policy-envelope.md'
        self.spec.parent.mkdir(parents=True)
        shutil.copy(source / 'docs/specs/policy-envelope.md', self.spec)
        shutil.copy(source / 'docs/specs/mdm-resource-schemas.md', self.spec.parent)

    def run_validator(self):
        return subprocess.run([sys.executable, str(self.directory / 'validate.py')],
                              capture_output=True, text=True, check=False)

    def test_valid_contracts_and_examples_pass(self):
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_required_schema_fails(self):
        for filename in ('policy.schema.json', 'exception.schema.json'):
            with self.subTest(filename=filename):
                path = self.directory / filename
                content = path.read_text()
                path.unlink()
                result = self.run_validator()
                path.write_text(content)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'Missing required schema: {filename}', result.stderr)

    def test_unknown_resource_kind_fails(self):
        self.spec.write_text(self.spec.read_text().replace('kind: Exception', 'kind: Exeption'))
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unknown resource kind: Exeption', result.stderr)

    def test_resource_without_kind_fails(self):
        self.spec.write_text(self.spec.read_text().replace('kind: Exception\n', ''))
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Resource example requires apiVersion and kind', result.stderr)

    def test_each_resource_kind_requires_an_example(self):
        original = self.spec.read_text()
        for kind in ('Policy', 'Exception'):
            with self.subTest(kind=kind):
                self.spec.write_text(re.sub(rf'```yaml\napiVersion:[^`]*?kind: {kind}[^`]*?\n```',
                                            '', original))
                result = self.run_validator()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'No {kind} example validated', result.stderr)

    def test_invalid_exception_expiry_example_fails(self):
        self.spec.write_text(self.spec.read_text().replace('2027-01-31T00:00:00Z', 'not-a-date'))
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Exception example: 'not-a-date' is not a 'date-time'", result.stderr)


class MDMSchemaTests(unittest.TestCase):
    def test_required_mdm_schemas(self):
        import validate
        self.assertTrue(hasattr(validate, 'load_mdm_schemas'), 'MDM schema registry is required')
        schemas, registry = validate.load_mdm_schemas()
        self.assertEqual(len(schemas), 23)

    def test_structural_and_semantic_fixtures(self):
        import validate
        self.assertTrue(hasattr(validate, 'check_mdm_fixtures'), 'MDM fixture checks are required')
        failures, count = validate.check_mdm_fixtures()
        self.assertGreater(count, 100)
        self.assertEqual(failures, [])


class MDMSemanticTests(unittest.TestCase):
    def test_input_and_budget(self):
        import validate
        self.assertTrue(hasattr(validate, 'validate_mdm'), 'Full MDM validation is required')
        for value in (float('nan'), float('inf'), 9007199254740992, '\ud800'):
            with self.subTest(value=repr(value)):
                self.assertEqual(validate.validate_mdm({'x': value})[0]['sentinel'], 'ErrInput')
        cycle = {}
        cycle['cycle'] = cycle
        self.assertEqual(validate.validate_mdm(cycle)[0]['rule'], 'budget')


class MDMCommandTests(unittest.TestCase):
    setUp = ValidatorCommandTests.setUp
    run_validator = ValidatorCommandTests.run_validator

    def mutate_schema(self, name, mutate):
        import json
        path = self.directory / name
        schema = json.loads(path.read_text())
        mutate(schema)
        path.write_text(json.dumps(schema))

    def assert_command_fails(self, message):
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_missing_item_schema_fails(self):
        (self.directory / 'baseline/linux.file.json').unlink()
        self.assert_command_fails('Missing required schema: baseline/linux.file.json')

    def test_extra_schema_fails(self):
        (self.directory / 'extra.schema.json').write_text('{}')
        self.assert_command_fails('Schema inventory')

    def test_remote_ref_refused(self):
        self.mutate_schema('device-group.schema.json', lambda s: s.update({'$ref': 'https://example.invalid/schema'}))
        self.assert_command_fails('Off-tree schema reference')

    def test_missing_ref_fails(self):
        self.mutate_schema('device-group.schema.json', lambda s: s.update({'$ref': 'mdm-common.schema.json#/$defs/missing'}))
        self.assert_command_fails('Missing schema reference')

    def test_ref_cycle_fails(self):
        self.mutate_schema('device-group.schema.json', lambda s: s.update({'$ref': '#'}))
        self.assert_command_fails('Schema reference cycle')

    def test_native_same_instance_cycle_fails(self):
        self.mutate_schema('mdm-common.schema.json', lambda s: s['$defs']['nativeJSON'].update(
            {'allOf': [{'$ref': '#/$defs/nativeJSON'}]}))
        self.assert_command_fails('Schema reference cycle')

    def test_native_recursive_node_alias_fails(self):
        for suffix in ('4/items', '5/additionalProperties'):
            with self.subTest(suffix=suffix):
                self.mutate_schema('mdm-common.schema.json', lambda s: s['$defs']['nativeJSON'].update(
                    {'allOf': [{'$ref': '#/$defs/nativeJSON/oneOf/' + suffix}]}))
                self.assert_command_fails('Schema reference cycle')

    def test_noncanonical_array_ref_fails(self):
        import json
        path = self.directory / 'device-group.schema.json'
        original = path.read_text()
        for token in ('00', '-1', '+0'):
            with self.subTest(token=token):
                schema = json.loads(original)
                ref = '#/$defs/loop/allOf/' + token
                schema['$defs'] = {'loop': {'allOf': [{'$ref': ref}]}}
                schema['$ref'] = ref
                path.write_text(json.dumps(schema))
                self.assert_command_fails('Missing schema reference')
        path.write_text(original)

    def test_duplicate_schema_id_fails(self):
        self.mutate_schema('device-group.schema.json', lambda s: s.update({'$id': 'https://ricevanta.io/schemas/policy/v1alpha1/baseline.schema.json'}))
        self.assert_command_fails('must have its exact id')

    def test_wrong_effect_annotation_fails(self):
        self.mutate_schema('baseline/linux.file.json', lambda s: s.update({'x-ricevanta-protected-publication': False}))
        self.assert_command_fails('Wrong effect annotation')

    def test_invalid_mdm_manifest_fails(self):
        (self.directory / 'fixtures/mdm/manifest.json').write_text('[{"file":"../escape"}]')
        self.assert_command_fails('Invalid MDM manifest entry')

    def test_fixture_inventory_complete(self):
        (self.directory / 'fixtures/mdm/valid/mdm-unlisted.json').write_text('{}')
        self.assert_command_fails('MDM fixture inventory')

    def test_fixture_symlink_fails(self):
        path = next((self.directory / 'fixtures/mdm/valid').glob('*.json'))
        target = self.root / 'fixture.json'
        target.write_text(path.read_text())
        path.unlink()
        path.symlink_to(target)
        self.assert_command_fails('MDM fixture symlink refused')

    def test_fixture_parent_symlink_fails(self):
        path = self.directory / 'fixtures'
        target = self.root / 'external-fixtures'
        path.rename(target)
        path.symlink_to(target, target_is_directory=True)
        self.assert_command_fails('MDM fixture symlink refused')

    def test_manifest_symlink_fails(self):
        path = self.directory / 'fixtures/mdm/manifest.json'
        target = self.root / 'external-manifest.json'
        path.rename(target)
        path.symlink_to(target)
        self.assert_command_fails('MDM fixture symlink refused')

    def test_missing_mdm_example_fails(self):
        path = self.spec.parent / 'mdm-resource-schemas.md'
        path.write_text(re.sub(r'```yaml\napiVersion:[^`]*?kind: DeviceGroup[^`]*?\n```', '', path.read_text()))
        self.assert_command_fails('No DeviceGroup example validated')

    def test_invalid_mdm_example_fails(self):
        path = self.spec.parent / 'mdm-resource-schemas.md'
        path.write_text(path.read_text().replace('severity: high', 'severity: severe'))
        self.assert_command_fails('Baseline example:')

    def test_yaml_duplicate_key_fails(self):
        self.spec.write_text(self.spec.read_text().replace('kind: Exception', 'kind: Exception\nkind: Exception'))
        self.assert_command_fails('Duplicate or nonstring object key')

    def test_yaml_nonstring_key_fails(self):
        self.spec.write_text(self.spec.read_text() + '\n```yaml\napiVersion: x\nkind: Exception\n1: true\n```\n')
        self.assert_command_fails('Duplicate or nonstring object key')

    def test_yaml_alias_fails(self):
        self.spec.write_text(self.spec.read_text() + '\n```yaml\na: &x [1]\nb: *x\n```\n')
        self.assert_command_fails('YAML aliases are forbidden')

    def test_yaml_nonfinite_fails(self):
        self.spec.write_text(self.spec.read_text() + '\n```yaml\nx: .inf\n```\n')
        self.assert_command_fails('Nonfinite number')

    def test_json_exponent_overflow_fails(self):
        path = next((self.directory / 'fixtures/mdm/valid').glob('*.json'))
        path.write_text('{"kind": "Baseline", "value": 1e400}')
        self.assert_command_fails('Nonfinite number')

    def test_json_duplicate_key_fails(self):
        path = next((self.directory / 'fixtures/mdm/valid').glob('*.json'))
        path.write_text(path.read_text().replace('"kind":', '"kind": "Baseline", "kind":', 1))
        self.assert_command_fails('Duplicate or nonstring object key')


class MDMBoundaryTests(unittest.TestCase):
    @staticmethod
    def baseline(settings):
        return {'apiVersion': 'ricevanta.io/v1alpha1', 'kind': 'Baseline',
                'metadata': {'name': 'boundary'}, 'spec': {'os': 'macos', 'allowedGroups': ['fleet'],
                'items': [{'id': 'item', 'kind': 'apple.declaration', 'settings': settings,
                           'required': True, 'severity': 'high'}]}}

    @staticmethod
    def text_charge(value):
        # These generated trees contain no numbers. JSON escapes LF in two bytes;
        # the contract charges six, so add four per LF independently of the validator.
        import json
        encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        return len(encoded.encode('utf-8')) + 4 * encoded.count('\\n')

    @classmethod
    def settings(cls, target, char):
        settings = {'identifier': 'io.ricevanta.test', 'type': 'com.apple.configuration',
                    'payload': {str(i): '' for i in range(8)}}
        remaining = target - cls.text_charge(settings)
        unit = 6 if char == '\n' else len(char.encode('utf-8'))
        for key in settings['payload']:
            n = min(16384, remaining // unit)
            settings['payload'][key] = char * n
            remaining -= n * unit
            if not remaining:
                break
        if remaining:
            settings['payload']['7'] += 'a' * remaining
        assert cls.text_charge(settings) == target
        return settings

    def test_exact_budget_vectors(self):
        import validate
        for value, charge in (({}, 2), ({'a': 0}, 30), ({'x': 'é'}, 10), ({'x': '\n'}, 14)):
            self.assertEqual(validate._mdm_charge(value), charge)

    def test_settings_byte_boundaries(self):
        import validate
        for char in ('a', '😀', '\n'):
            for size in (65536, 65537):
                with self.subTest(char=repr(char), size=size):
                    resource = self.baseline(self.settings(size, char))
                    self.assertTrue(validate.mdm_validators()['Baseline'].is_valid(resource))
                    errors = validate.validate_mdm(resource)
                    self.assertEqual(errors, [] if size == 65536 else [
                        {'sentinel': 'ErrLimit', 'path': '/spec/items/0/settings', 'rule': 'bytes'}])

    def test_resource_byte_boundaries(self):
        import copy
        import validate
        for char in ('a', '😀', '\n'):
            for size in (1048576, 1048577):
                with self.subTest(char=repr(char), size=size):
                    resource = self.baseline(self.settings(60000, char))
                    first = resource['spec']['items'][0]
                    resource['spec']['items'] = [dict(copy.deepcopy(first), id=f'item-{i}') for i in range(17)]
                    empty = self.settings(500, 'a')
                    resource['spec']['items'].append(dict(copy.deepcopy(first), id='padding', settings=empty))
                    needed = size - self.text_charge(resource) + 500
                    resource['spec']['items'][-1]['settings'] = self.settings(needed, char)
                    self.assertEqual(self.text_charge(resource), size)
                    self.assertTrue(validate.mdm_validators()['Baseline'].is_valid(resource))
                    errors = validate.validate_mdm(resource)
                    self.assertEqual(errors, [] if size == 1048576 else [
                        {'sentinel': 'ErrLimit', 'path': '', 'rule': 'bytes'}])
                    if size > 1048576:
                        resource['kind'] = 'UnknownKind'
                        self.assertEqual(validate.validate_mdm(resource)[0]['rule'], 'bytes')

    def test_item_and_group_count_limits(self):
        import validate
        item = {'id': 'item', 'kind': 'check.query', 'settings': {'query': 'select 1', 'expect': 'true'},
                'required': False, 'severity': 'low'}
        resource = self.baseline({})
        resource['spec'] = {'os': 'linux', 'items': []}
        for count in (0, 1, 2000, 2001):
            resource['spec']['items'] = [dict(item, id=f'item-{i}') for i in range(count)]
            self.assertEqual(not validate.validate_mdm(resource), count in (1, 2000))
        group = {'apiVersion': 'ricevanta.io/v1alpha1', 'kind': 'DeviceGroup', 'metadata': {'name': 'fleet'}, 'spec': {}}
        for count in (0, 1, 20000, 20001):
            group['spec']['members'] = [f'device-{i}' for i in range(count)]
            self.assertEqual(not validate.validate_mdm(group), count in (1, 20000))

    def test_input_domain_and_precedence(self):
        import validate
        for value in (10**1000, -float('inf'), object(), {'x': (1,)}, {1: 'x'}):
            self.assertEqual(validate.validate_mdm(value)[0]['sentinel'], 'ErrInput')
        self.assertEqual(validate.validate_mdm(None)[0]['sentinel'], 'ErrEnvelope')
        resource = self.baseline(self.settings(500, 'a'))
        resource['spec']['items'][0]['grace'] = -0.0
        self.assertEqual(validate.validate_mdm(resource), [])
        resource['spec']['items'][0]['grace'] = False
        self.assertEqual(validate.validate_mdm(resource)[0]['sentinel'], 'ErrSchema')
        for value in ([None] * 100001, {'x': 'a' * 2097153}):
            self.assertEqual(validate.validate_mdm(value)[0]['rule'], 'budget')

    def test_no_mutation_and_repeatable_results(self):
        import copy
        import validate
        resource = self.baseline(self.settings(500, 'a'))
        original = copy.deepcopy(resource)
        for _ in range(2):
            self.assertEqual(validate.validate_mdm(resource), [])
            self.assertEqual(resource, original)


class MDMNamespaceVersionTests(unittest.TestCase):
    def test_version_scalar_boundaries(self):
        import validate
        schema = validate.read_json(Path(__file__).with_name('mdm-common.schema.json'))['$defs']['version']
        validator = validate.Draft202012Validator(schema)
        excluded = (set(range(0x21)) | {0x7f, 0x85, 0xa0, 0x1680, 0x2028, 0x2029,
                                      0x202f, 0x205f, 0x3000, 0xfeff} | set(range(0x2000, 0x200b)))
        probes = excluded | {cp + delta for cp in excluded for delta in (-1, 1) if cp + delta >= 0}
        probes.add(0x1f600)
        for cp in sorted(probes):
            for value in ('1' + chr(cp) + '0', '1' + chr(cp)):
                with self.subTest(cp=hex(cp), value=value):
                    self.assertEqual(validator.is_valid(value), cp not in excluded)
        for value, accepted in [('', False), ('a' * 128, True), ('a' * 129, False),
                                (chr(0x1f600) * 128, True), (chr(0x1f600) * 129, False)]:
            self.assertEqual(validator.is_valid(value), accepted)

    def test_version_fields_share_scalar_rules(self):
        import copy
        import validate
        directory = Path(__file__).with_name('fixtures') / 'mdm/valid'
        settings = ['spec', 'items', 0, 'settings']
        cases = [
            ('mdm-os-update-macos-populated.json', ['spec', 'minOsVersion']),
            ('mdm-os-update-macos-populated.json', settings + ['targetVersion']),
            ('mdm-os-update-macos-populated.json', settings + ['targetBuild']),
            ('mdm-os-update-windows-populated.json', settings + ['productVersion']),
            ('mdm-os-update-windows-populated.json', settings + ['targetRelease']),
        ]
        for name in ('mdm-package-macos-pkg-blob-developer-id-bundle.json',
                     'mdm-package-windows-msix-blob-msix-msix.json',
                     'mdm-package-windows-exe-blob-authenticode-uninstall.json',
                     'mdm-package-linux-deb-blob-none-package.json'):
            cases.extend((name, path) for path in (['spec', 'version'], ['spec', 'detection', 'version']))
        for name, path in cases:
            seed = validate.read_json(directory / name)
            for cp, accepted in ((0x85, False), (0xfeff, False), (0x200b, True)):
                doc = copy.deepcopy(seed)
                parent = doc
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = '1' + chr(cp) + '0'
                if accepted and doc['kind'] == 'SoftwarePackage':
                    doc['spec']['version'] = doc['spec']['detection']['version'] = parent[path[-1]]
                expected = [] if accepted else [{'sentinel': 'ErrSchema',
                    'path': '/' + '/'.join(map(str, path)), 'rule': 'schema'}]
                with self.subTest(name=name, path=path, cp=hex(cp)):
                    self.assertEqual(validate.validate_mdm(doc), expected)

    def test_csp_namespace_segments(self):
        import validate
        directory = Path(__file__).with_name('fixtures') / 'mdm/valid'
        doc = validate.read_json(directory / 'mdm-windows-csp-windows-minimum.json')
        settings = doc['spec']['items'][0]['settings']
        for scope in ('Device', 'User'):
            for fmt, value in (('int', 1), ('bool', True), ('chr', ''), ('xml', '<x/>'), ('b64', 'YQ==')):
                settings.update(format=fmt, value=value)
                for suffix, rule in (('Test/Setting', ''), ('./Test', 'target'), ('../Test', 'target'),
                                     ('Test/.', 'target'), ('Test/..', 'target'), ('', 'schema'),
                                     ('Test//Setting', 'schema'), ('Test/', 'schema'),
                                     ('%2e/Test', 'schema'), ('Test?q=1', 'schema'), ('Test#x', 'schema')):
                    settings['locUri'] = f'./{scope}/Vendor/MSFT/{suffix}'
                    expected = [] if not rule else [{'sentinel': 'ErrSchema' if rule == 'schema' else 'ErrSemantic',
                        'path': '/spec/items/0/settings/locUri', 'rule': rule}]
                    with self.subTest(scope=scope, fmt=fmt, suffix=suffix):
                        self.assertEqual(validate.validate_mdm(doc), expected)


class MDMCoverageTests(unittest.TestCase):
    def test_all_item_kinds_and_platforms(self):
        import validate
        directory = Path(__file__).resolve().parent / 'fixtures/mdm'
        manifest = validate.read_json(directory / 'manifest.json')
        coverage = {}
        for record in manifest:
            if record['accepted']:
                doc = validate.read_json(directory / record['file'])
                if doc['kind'] == 'Baseline':
                    for item in doc['spec']['items']:
                        key = item['kind'], doc['spec']['os']
                        coverage[key] = coverage.get(key, 0) + 1
        for kind in validate.MDM_KINDS:
            oses = ('macos',) if kind.startswith('apple.') else ('windows',) if kind.startswith('windows.') else ('linux',) if kind.startswith('linux.') else ('macos', 'windows', 'linux')
            for os in oses:
                self.assertGreaterEqual(coverage.get((kind, os), 0), 2, (kind, os))

    def test_package_matrix_and_group_operators(self):
        import validate
        directory = Path(__file__).resolve().parent / 'fixtures/mdm'
        rows, operators = set(), set()
        for record in validate.read_json(directory / 'manifest.json'):
            if not record['accepted']:
                continue
            doc = validate.read_json(directory / record['file']); spec = doc['spec']
            if doc['kind'] == 'SoftwarePackage':
                rows.add((spec['os'], spec['format'], spec['source'].get('manager', 'blob'), spec['signature']['type'], spec['detection']['type']))
            if doc['kind'] == 'DeviceGroup':
                operators.update(x['operator'] for x in spec.get('selector', {}).get('matchExpressions', []))
        expected = [
            ('macos', 'pkg', 'blob', 'developer-id', 'bundle'),
            ('macos', 'homebrew-formula', 'homebrew', 'checksum', 'package'),
            ('macos', 'homebrew-cask', 'homebrew', 'checksum', 'bundle'),
            ('windows', 'msi', 'blob', 'authenticode', 'msi'),
            ('windows', 'msix', 'blob', 'msix', 'msix'),
            ('windows', 'exe', 'blob', 'authenticode', 'uninstall'),
            ('windows', 'winget', 'winget', 'authenticode', 'uninstall'),
            ('windows', 'winget', 'winget', 'msix', 'msix'),
            ('linux', 'deb', 'blob', 'none', 'package'),
            ('linux', 'deb', 'apt', 'openpgp', 'package'),
            ('linux', 'rpm', 'blob', 'openpgp', 'package'),
            ('linux', 'rpm', 'dnf', 'openpgp', 'package'),
            ('linux', 'rpm', 'zypper', 'openpgp', 'package'),
            ('linux', 'flatpak', 'flatpak', 'openpgp', 'package'),
        ]
        for os, fmt, source, signature, detection in expected:
            self.assertIn((os, fmt, source, signature, detection), rows)
            self.assertIn((os, fmt, source, 'none', detection), rows)
        self.assertEqual(operators, {'In', 'NotIn', 'Exists', 'DoesNotExist'})


if __name__ == '__main__':
    unittest.main()
