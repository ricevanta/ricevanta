"""Exercise the export runner with isolated repository-shaped inputs."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from validate import validate

ROOT = Path(__file__).resolve().parents[3]
CANARY = 'synthetic-private-canary'


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='export-runner-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'schemas/export/v1alpha1'
        self.directory.mkdir(parents=True)
        for name in ('export-destination.json', 'fixtures.schema.json', 'fixtures.json'):
            shutil.copy(ROOT / 'schemas/export/v1alpha1' / name, self.directory / name)
        specs = self.root / 'docs/specs'
        specs.mkdir(parents=True)
        for name in ('export-destination-schema.md', 'event-export.md', 'ocsf-profile.md'):
            shutil.copy(ROOT / 'docs/specs' / name, specs / name)

    def edit(self, name, change):
        path = self.directory / name
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def rejected(self):
        failures = validate(self.root)
        self.assertTrue(failures)
        self.assertNotIn(CANARY, '\n'.join(failures))

    def test_checked_in(self):
        self.assertEqual(validate(ROOT), [])

    def test_missing_exact_filename(self):
        (self.directory / 'export-destination.json').rename(self.directory / 'other.schema.json')
        self.rejected()

    def test_broken_unused_local_reference(self):
        self.edit('export-destination.json', lambda s: s['$defs'].update(unused={'$ref': '#/$defs/' + CANARY}))
        self.rejected()

    def test_external_reference(self):
        self.edit('export-destination.json', lambda s: s['$defs'].update(unused={'$ref': 'https://example.invalid/' + CANARY}))
        self.rejected()

    def test_dynamic_references(self):
        for reference in ('#/$defs/' + CANARY, 'https://example.invalid/' + CANARY):
            with self.subTest(reference=reference):
                self.edit('export-destination.json', lambda s: s['$defs'].update(unused={'$dynamicRef': reference}))
                self.rejected()

    def test_duplicate_id(self):
        self.edit('fixtures.json', lambda f: f['cases'].append(f['cases'][0]))
        self.rejected()

    def test_empty_manifest(self):
        self.edit('fixtures.json', lambda f: f.update(cases=[]))
        self.rejected()

    def test_missing_adapter_positive(self):
        for adapter in ('elasticsearch', 'opensearch', 'splunk_hec', 'syslog', 'otlp', 'loki', 'sentinel', 'kafka', 's3', 'connector'):
            with self.subTest(adapter=adapter):
                original = (self.directory / 'fixtures.json').read_text()
                self.edit('fixtures.json', lambda f: f.update(cases=[c for c in f['cases'] if not (c['valid'] and c['resource']['spec']['type'] == adapter)]))
                self.rejected()
                (self.directory / 'fixtures.json').write_text(original)

    def test_flipped_expectations(self):
        for valid in (True, False):
            with self.subTest(valid=valid):
                original = (self.directory / 'fixtures.json').read_text()
                def flip(f):
                    c = next(c for c in f['cases'] if c['valid'] == valid)
                    c['valid'] = not valid
                    if valid:
                        c['error'] = 'ErrResource'
                    else:
                        del c['error']
                self.edit('fixtures.json', flip)
                self.rejected()
                (self.directory / 'fixtures.json').write_text(original)

    def test_missing_negative_sentinel(self):
        self.edit('fixtures.json', lambda f: next(c for c in f['cases'] if not c['valid']).pop('error'))
        self.rejected()

    def test_unknown_sentinel(self):
        self.edit('fixtures.json', lambda f: next(c for c in f['cases'] if not c['valid']).update(error=CANARY))
        self.rejected()

    def test_bad_example(self):
        path = self.root / 'docs/specs/event-export.md'
        with path.open('a') as stream:
            stream.write('\n```yaml\napiVersion: ricevanta.io/v1alpha1\nkind: ExportDestination\nmetadata: {name: ' + CANARY + '}\nspec: {}\n```\n')
        self.rejected()

    def test_unknown_example_kind(self):
        path = self.root / 'docs/specs/event-export.md'
        with path.open('a') as stream:
            stream.write('\n```json\n{"apiVersion":"ricevanta.io/v1alpha1","kind":"' + CANARY + '","metadata":{},"spec":{}}\n```\n')
        self.rejected()

    def test_missing_example(self):
        (self.root / 'docs/specs/export-destination-schema.md').write_text('No examples\n')
        self.rejected()

    def test_class_drift(self):
        self.edit('export-destination.json', lambda s: s['$defs']['class']['enum'].append(CANARY))
        self.rejected()

    def test_all_classes_fixture_drift(self):
        self.edit('fixtures.json', lambda f: next(c for c in f['cases'] if c['id'] == 'valid-selection')['resource']['spec']['filter']['classes'].pop())
        self.rejected()


if __name__ == '__main__':
    unittest.main()
