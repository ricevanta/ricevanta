#!/usr/bin/env python3
"""Report contract regressions. Acceptance supplies no authority."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
import validate as v

def base(source='dlp.findings'):
    return {'apiVersion': 'ricevanta.io/v1alpha1', 'kind': 'ReportTemplate', 'metadata': {'name': 'sample'}, 'spec': {'title': {'en': 'Report', 'vi': 'Báo cáo'}, 'datasets': [{'name': 'data', 'source': source, 'filter': {}, 'measures': [{'name': 'rows', 'fn': 'count'}]}], 'layout': [{'type': 'table', 'dataset': 'data', 'columns': ['rows']}]}}

class Contract(unittest.TestCase):

    def test_schema_inventory(self):
        v.load_contracts()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                v.load_contracts(Path(d))
            for p in v.HERE.glob('*.json'):
                Path(d, p.name).write_bytes(p.read_bytes())
            Path(d, 'extra.json').write_text('{}')
            with self.assertRaises(ValueError):
                v.load_contracts(Path(d))

    def test_fixture_contract(self):
        fixtures = v.load_fixtures()
        self.assertEqual(len(fixtures), 83)
        self.assertEqual(sum((f['accepted'] for f in fixtures)), 33)
        for f in fixtures:
            with self.subTest(f=f['id']):
                self.assertEqual(v.TEMPLATE.is_valid(f['document']), f['structural'])
                self.assertEqual(v.validate_template(f['document']), [] if f['accepted'] else [{k: f[k] for k in ('sentinel', 'path', 'rule')}])
        with self.assertRaises(ValueError):
            v.check_fixtures(fixtures + [fixtures[0]])
        for raw in ('{"a":1,"a":2}', '[NaN]', '[Infinity]'):
            with self.assertRaises(ValueError):
                v.strict_loads(raw)

    def test_catalogue_integrity(self):
        self.assertEqual(v.check_catalogue(v.CATALOGUE), [])
        for mutate in (lambda c: c['sources'].reverse(), lambda c: c['sources'][0].update(owner='mdm'), lambda c: c['sources'].pop(), lambda c: c['sources'][0]['fields'][0].update(type='boolean'), lambda c: next((s for s in c['sources'] if s['id'] == 'pki.certificates')).update(conditional_reads=[])):
            c = copy.deepcopy(v.CATALOGUE)
            mutate(c)
            self.assertTrue(v.check_catalogue(c))

    def test_permission_bindings(self):
        expected = {'devices': ('devices', 'mdm.devices.read', 'devices'), 'devices.software': ('mdm', 'mdm.inventory.read', 'devices'), 'mdm.compliance': ('mdm', 'mdm.compliance.read', 'devices'), 'edr.alerts': ('detection', 'edr.alerts.read', 'devices'), 'edr.response_actions': ('detection', 'edr.response.read', 'devices'), 'dlp.findings': ('dlp', 'dlp.findings.read', 'devices'), 'lineage.edges': ('lineage', 'lineage.edges.read', 'lineage_endpoints'), 'pki.certificates': ('pki', 'pki.certificates.read', 'certificate_profile'), 'radius.authentications': ('radius', 'radius.authentications.read', 'radius_attribution'), 'agents.versions': ('devices', 'mdm.versions.read', 'devices'), 'agents.health': ('events', 'events.health.read', 'devices'), 'audit.events': ('audit', 'audit.events.read', 'organization')}
        self.assertEqual(v.BINDINGS, expected)
        self.assertEqual(v.check_permissions(v.CATALOGUE), [])

    def test_same_owner_scope_permission_substitution(self):
        c = copy.deepcopy(v.CATALOGUE)
        source = next(s for s in c['sources'] if s['id'] == 'edr.alerts')
        source['read_permission'] = 'edr.response.read'
        self.assertTrue(v.CATALOGUE_SCHEMA.is_valid(c))
        self.assertEqual(v.check_permissions(c), [])
        self.assertEqual(v.check_catalogue(c), ['source binding'])

    def test_reference_registry(self):
        schemas = copy.deepcopy(v.SCHEMAS)
        schemas[0]['properties']['spec'] = {'$ref': schemas[1]['$id']}
        v.registry(schemas)
        for ref in ('https://invalid.test/a', '#/$defs/absent'):
            schemas = copy.deepcopy(v.SCHEMAS)
            schemas[0]['properties']['spec'] = {'$ref': ref}
            with self.assertRaises(ValueError):
                v.registry(schemas)
        schemas = copy.deepcopy(v.SCHEMAS)
        schemas[0]['$defs']['loop'] = {'$ref': '#/$defs/loop'}
        with self.assertRaises(ValueError):
            v.registry(schemas)
        schemas = copy.deepcopy(v.SCHEMAS)
        schemas[0]['$defs']['bad'] = {'$id': 'nested'}
        with self.assertRaises(ValueError):
            v.registry(schemas)

    def test_precedence(self):
        d = base()
        d['apiVersion'] = 'bad'
        d['spec']['title'].pop('vi')
        self.assertEqual(v.validate_template(d)[0]['path'], '/apiVersion')
        d = base()
        d['spec']['datasets'][0]['filter'] = {'channel': {'eq': {}, 'param': 3}}
        self.assertEqual(v.validate_template(d)[0]['path'], '/spec/datasets/0/filter/channel/eq')

    def test_bounds(self):
        for value, n in ((None, 4), (True, 4), (0, 24), ({}, 2), ('', 2), ('ế', 5), ([0], 26), ({'a': 0}, 30), ('"\\\n', 12)):
            self.assertEqual(v.charge(value), n)
        for n in (65536, 65537):
            d = base()
            d['spec']['layout'] = [{'type': 'text', 'text': {'en': 'a', 'vi': 'a'}} for _ in range(9)]
            remaining = n - v.charge(d)
            for b in d['spec']['layout']:
                for lang in ('en', 'vi'):
                    take = min(4095, remaining)
                    b['text'][lang] += 'a' * take
                    remaining -= take
            self.assertEqual(remaining, 0)
            self.assertTrue(v.TEMPLATE.is_valid(d))
            self.assertEqual(bool(v.validate_template(d)), n > 65536)

    def test_calendar(self):
        for date, ok in (('2024-02-29', True), ('2023-02-29', False), ('0000-01-01', False), ('2024-04-31', False)):
            d = base()
            d['spec']['datasets'][0]['filter']['time'] = {'start': date + 'T00:00:00Z', 'end': '2025-01-01T00:00:00Z'}
            self.assertEqual(not v.validate_template(d), ok)

    def test_capability_matrix(self):
        counts = [0, 0, 0]
        for s in v.CATALOGUE['sources']:
            for f in s['fields']:
                counts[0] += 1
                value = {'string': 'x', 'enum': f.get('values', ['x'])[0], 'boolean': True, 'integer': 1, 'number': 1.5, 'timestamp': '2024-01-01T00:00:00Z'}[f['type']]
                for op in ('eq', 'in', 'not_in', 'gte', 'lte', 'between', 'prefix', 'exists'):
                    d = base(s['id'])
                    operand = [value, value] if op == 'between' else [value] if op in ('in', 'not_in') else True if op == 'exists' else value
                    d['spec']['datasets'][0]['filter'][f['name']] = {op: operand}
                    result = v.validate_template(d)
                    self.assertEqual(not result, op in f['operators'], (s['id'], f['name'], op, result))
                    if op in f['operators']:
                        counts[1] += 1
                for fn in ('count_distinct', 'sum', 'min', 'max', 'avg', 'p50', 'p95'):
                    d = base(s['id'])
                    d['spec']['datasets'][0]['measures'] = [{'name': 'measure', 'fn': fn, 'field': f['name']}]
                    d['spec']['layout'][0]['columns'] = ['measure']
                    self.assertEqual(not v.validate_template(d), fn in f['aggregations'])
                    if fn in f['aggregations']:
                        counts[2] += 1
        self.assertEqual(counts, [88, 422, 106])
        print('Capability coverage: fields/operators/aggregations', counts)

class Drift(unittest.TestCase):

    def test_null_measure_discriminator(self):
        d = base()
        d['spec']['datasets'][0]['measures'][0]['fn'] = None
        self.assertEqual(v.validate_template(d), [{'sentinel': 'ErrSchema', 'path': '/spec/datasets/0/measures/0/fn', 'rule': 'schema'}])

    def test_nested_boolean_number_uniqueness(self):
        for values in ([{'a': False}, {'a': 0}], [[False], [0]],
                       [{'a': [True]}, {'a': [1]}], [[{'a': False}], [{'a': 0}]]):
            with self.subTest(values=values):
                self.assertEqual(v.shape(values, {'type': 'array', 'uniqueItems': True}), [])
                d = base()
                d['spec']['datasets'][0]['filter']['device_uid'] = {'in': values}
                self.assertEqual(v.validate_template(d), [{'sentinel': 'ErrSchema', 'path': '/spec/datasets/0/filter/device_uid/in/0', 'rule': 'schema'}])
        for values in ([{'a': False}, {'a': False}], [[False], [False]],
                       [{'a': [1]}, {'a': [1.0]}], [[{'a': 0}], [{'a': 0.0}]],
                       [{'a': 1, 'b': 2}, {'b': 2, 'a': 1}], [1, 1.0]):
            with self.subTest(values=values):
                self.assertEqual(v.shape(values, {'type': 'array', 'uniqueItems': True}), [()])

    def test_strict_numbers(self):
        for raw in ('[1e999]', '[-1e999]'):
            with self.assertRaises(ValueError):
                v.strict_loads(raw)
        self.assertEqual(v.validate_template({'x': 10 ** 1000})[0]['rule'], 'input')

    def test_example_inventory(self):
        fixtures = v.load_fixtures()
        sources = {d['source'] for f in fixtures if f['accepted'] for d in f['document']['spec']['datasets']}
        self.assertEqual(sources, set(v.BINDINGS))
        parameters = {p['type'] for f in fixtures if f['accepted'] for p in f['document']['spec'].get('parameters', [])}
        self.assertEqual(parameters, {'time_range', 'device_groups', 'enum_list', 'string'})
        blocks = {b['type'] for f in fixtures if f['accepted'] for b in f['document']['spec']['layout']}
        self.assertEqual(blocks, {'heading', 'text', 'kpi', 'table', 'chart'})
        charts = {b['chart'] for f in fixtures if f['accepted'] for b in f['document']['spec']['layout'] if b['type'] == 'chart'}
        self.assertEqual(charts, {'bar', 'stacked_bar', 'line', 'area', 'pie', 'heatmap'})

    def test_chart_branches(self):
        for chart in ('stacked_bar', 'heatmap', 'pie'):
            d = base()
            d['spec']['datasets'][0]['group_by'] = ['severity']
            d['spec']['layout'] = [{'type': 'chart', 'chart': chart, 'dataset': 'data', 'x': 'severity', 'y': 'rows'}]
            if chart == 'pie':
                d['spec']['layout'][0]['series'] = 'severity'
            self.assertFalse(v.TEMPLATE.is_valid(d))
            self.assertEqual(v.validate_template(d), [{'sentinel': 'ErrSchema', 'path': '/spec/layout/0/series', 'rule': 'schema'}])

class Generated(unittest.TestCase):

    def test_parameters(self):
        for kind, default, field, site, op, source in (('string', 'x', None, 'component', 'prefix', 'agents.health'), ('enum_list', ['high'], 'dlp.findings/severity', 'severity', 'in', 'dlp.findings'), ('time_range', {'start': '2024-02-29T00:00:00Z', 'end': '2024-03-01T00:00:00Z'}, None, 'occurred_at', 'between', 'dlp.findings'), ('device_groups', ['group-a'], None, 'device_groups', None, 'dlp.findings')):
            for explicit in (False, True):
                d = base(source)
                p = {'name': 'p', 'type': kind}
                if field:
                    p['field'] = field
                if explicit:
                    p['default'] = default
                d['spec']['parameters'] = [p]
                ref = {'param': 'p'}
                d['spec']['datasets'][0]['filter'][site] = {op: ref} if op else ref
                self.assertEqual(v.validate_template(d), [])
                if kind == 'enum_list':
                    p['field'] = 'edr.alerts/severity'
                    self.assertEqual(v.validate_template(d), [{'sentinel': 'ErrSemantic', 'path': '/spec/datasets/0/filter/severity/in', 'rule': 'compatibility'}])
                if kind == 'time_range':
                    d['spec']['datasets'][0]['filter'] = {'time': ref}
                    self.assertEqual(v.validate_template(d), [])

    def test_closed_objects(self):

        def walk(value, path=()):
            if isinstance(value, dict):
                yield (path, value)
                for k, x in value.items():
                    yield from walk(x, path + (k,))
            elif isinstance(value, list):
                for i, x in enumerate(value):
                    yield from walk(x, path + (i,))
        checked = 0
        for f in v.load_fixtures():
            if not f['accepted']:
                continue
            original = f['document']
            self.assertEqual(v.validate_template(original), [])
            for path, obj in walk(original):
                for key in list(obj) + ['zz_unknown']:
                    d = copy.deepcopy(original)
                    target = d
                    for part in path:
                        target = target[part]
                    if key in target:
                        del target[key]
                    else:
                        target[key] = True
                    if not v.TEMPLATE.is_valid(d):
                        self.assertIn(v.validate_template(d)[0]['sentinel'], ('ErrEnvelope', 'ErrSchema'))
                        checked += 1
        self.assertGreater(checked, 300)
        print('Closed-object mutations:', checked)

    def test_caps(self):
        for count in (0, 1, 16, 17):
            d = base()
            d['spec']['parameters'] = [{'name': 'p' + str(i), 'type': 'string'} for i in range(count)]
            self.assertEqual(not v.validate_template(d), count <= 16)
        for count in (0, 1, 10, 11):
            d = base()
            dataset = d['spec']['datasets'][0]
            d['spec']['datasets'] = [dict(copy.deepcopy(dataset), name='d' + str(i)) for i in range(count)]
            d['spec']['layout'] = [{'type': 'text', 'text': {'en': 'a', 'vi': 'a'}}]
            self.assertEqual(not v.validate_template(d), 1 <= count <= 10)
        for count in (0, 1, 64, 65):
            d = base()
            d['spec']['layout'] = [{'type': 'text', 'text': {'en': 'a', 'vi': 'a'}} for _ in range(count)]
            self.assertEqual(not v.validate_template(d), 1 <= count <= 64)
        for n in (16, 17):
            d = {}
            target = d
            for _ in range(n - 1):
                target['a'] = {}
                target = target['a']
            self.assertEqual(bool(v.preflight(d)), n > 16)
        for n in (131071, 131072):
            self.assertEqual(bool(v.preflight({'a': 'x' * n})), n > 131071)

class Fields(unittest.TestCase):

    def test_enum_declarations_and_groups(self):
        for source in v.CATALOGUE['sources']:
            for field in source['fields']:
                for explicit in (False, True):
                    d = base(source['id'])
                    p = {'name': 'values', 'type': 'enum_list', 'field': source['id'] + '/' + field['name']}
                    if explicit:
                        p['default'] = [field.get('values', ['x'])[0]]
                    d['spec']['parameters'] = [p]
                    expected = [] if field['type'] == 'enum' else [{'sentinel': 'ErrSemantic', 'path': '/spec/parameters/0/field', 'rule': 'compatibility'}]
                    self.assertEqual(v.validate_template(d), expected)
                d = base(source['id'])
                d['spec']['datasets'][0]['group_by'] = [field['name']]
                self.assertEqual(not v.validate_template(d), field['groupable'])

class ShapeCaps(unittest.TestCase):

    def test_array_and_string_caps(self):
        for key, minimum, cap in (('measures', 1, 8), ('group_by', 1, 3), ('order_by', 1, 11), ('columns', 1, 11), ('filter', 0, 32), ('groups', 1, 64), ('enum', 1, 64), ('in', 1, 64), ('between', 2, 2)):
            for n in (0, 1, cap, cap + 1):
                d = base()
                ds = d['spec']['datasets'][0]
                names = ['v' + str(i) for i in range(n)]
                if key == 'measures':
                    ds[key] = [{'name': name, 'fn': 'count'} for name in names]
                elif key == 'group_by':
                    ds[key] = names
                elif key == 'order_by':
                    ds[key] = [{'field': name} for name in names]
                elif key == 'columns':
                    d['spec']['layout'][0][key] = names
                elif key == 'filter':
                    ds[key] = {name: True for name in names}
                elif key == 'groups':
                    ds['filter']['device_groups'] = names
                elif key == 'enum':
                    d['spec']['parameters'] = [{'name': 'p', 'type': 'enum_list', 'field': 'dlp.findings/severity', 'default': names}]
                else:
                    ds['filter']['channel'] = {key: names}
                expected = minimum <= n <= cap
                self.assertEqual(v.TEMPLATE.is_valid(d), expected, (key, n))
                self.assertEqual(not v.shape(d['spec'], v.SCHEMAS[0]['properties']['spec'], ('spec',)), expected, (key, n))
        for key, minimum, cap in (('name', 1, 63), ('description', 0, 1024), ('title', 1, 256), ('text', 1, 4096), ('scalar', 0, 256), ('identifier', 1, 32)):
            for n in (0, 1, cap, cap + 1):
                d = base()
                value = 'a' * n
                if key in ('name', 'description'):
                    d['metadata'][key] = value
                elif key == 'title':
                    d['spec']['title']['en'] = value
                elif key == 'text':
                    d['spec']['layout'] = [{'type': 'text', 'text': {'en': value, 'vi': 'a'}}]
                elif key == 'scalar':
                    d['spec']['datasets'][0]['filter']['channel'] = value
                else:
                    d['spec']['datasets'][0]['name'] = value
                self.assertEqual(v.TEMPLATE.is_valid(d), minimum <= n <= cap, (key, n))
                self.assertEqual(not v.shape(d, v.SCHEMAS[0]), minimum <= n <= cap, (key, n))

class CompatibilityPairs(unittest.TestCase):

    def test_literals(self):
        for source in v.CATALOGUE['sources']:
            for field in source['fields']:
                value = {'string': 'x', 'enum': field.get('values', ['x'])[0], 'boolean': True, 'integer': 0, 'number': 0.5, 'timestamp': '2024-02-29T00:00:00Z'}[field['type']]
                for op in field['operators']:
                    d = base(source['id'])
                    filter = d['spec']['datasets'][0]['filter']
                    operand = [value, value] if op == 'between' else [value] if op in ('in', 'not_in') else True if op == 'exists' else value
                    filter[field['name']] = {op: operand}
                    self.assertEqual(v.validate_template(d), [])
                    wrong = 1 if field['type'] == 'boolean' else False
                    path = '/spec/datasets/0/filter/' + field['name'] + '/' + op
                    if op in ('in', 'not_in'):
                        wrong = [wrong]
                        path += '/0'
                    if op == 'between':
                        wrong = [wrong, value]
                        path += '/0'
                    if op == 'exists':
                        wrong = 1
                    filter[field['name']] = {op: wrong}
                    self.assertEqual(v.validate_template(d), [{'sentinel': 'ErrSchema' if op == 'exists' else 'ErrSemantic', 'path': path, 'rule': 'schema' if op == 'exists' else 'compatibility'}])
if __name__ == '__main__':
    unittest.main()
