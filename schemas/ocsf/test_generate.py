"""Offline source-pin tests; profile compilation awaits its source-binding gate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


class TestVendor(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'generate.py'
        self.assertTrue(path.is_file(), 'generator interfaces are absent')
        spec = importlib.util.spec_from_file_location('ocsf_generate', path)
        self.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.generator)
        self.assertTrue(callable(getattr(self.generator, 'verify_vendor', None)),
                        'verify_vendor interface is absent')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'ocsf'
        shutil.copytree(ROOT / 'upstream', self.root / 'upstream')
        shutil.copyfile(ROOT / 'upstream.lock.json', self.root / 'upstream.lock.json')

    def lock(self):
        return json.loads((self.root / 'upstream.lock.json').read_bytes())

    def write_lock(self, lock):
        (self.root / 'upstream.lock.json').write_text(json.dumps(lock))

    def test_vendor_pin(self):
        self.generator.verify_vendor(self.root)
        for entry in self.lock()['files']:
            data = (self.root / 'upstream' / '1.9.0' / entry['path']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])
            self.assertEqual(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(), entry['git_blob'])
        path = self.root / 'upstream/1.9.0/version.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            self.generator.verify_vendor(self.root)

    def test_vendor_inventory(self):
        vendor = self.root / 'upstream/1.9.0'
        for mutation in ('missing_notice', 'extra', 'symlink', 'traversal', 'duplicate', 'wrong_pin'):
            with self.subTest(mutation=mutation):
                lock_bytes = (self.root / 'upstream.lock.json').read_bytes()
                notice = (vendor / 'NOTICE').read_bytes()
                try:
                    lock = self.lock()
                    if mutation == 'missing_notice':
                        (vendor / 'NOTICE').unlink()
                    elif mutation == 'extra':
                        (vendor / 'extra.json').write_bytes(b'{}')
                    elif mutation == 'symlink':
                        (vendor / 'NOTICE').unlink()
                        (vendor / 'NOTICE').symlink_to(vendor / 'LICENSE')
                    elif mutation == 'traversal':
                        lock['files'][0]['path'] = '../LICENSE'
                        self.write_lock(lock)
                    elif mutation == 'duplicate':
                        lock['files'].append(lock['files'][0])
                        self.write_lock(lock)
                    else:
                        lock['tree'] = '0' * 40
                        self.write_lock(lock)
                    with self.assertRaises(ValueError):
                        self.generator.verify_vendor(self.root)
                finally:
                    if (vendor / 'NOTICE').is_symlink():
                        (vendor / 'NOTICE').unlink()
                    (vendor / 'NOTICE').write_bytes(notice)
                    (vendor / 'extra.json').unlink(missing_ok=True)
                    (self.root / 'upstream.lock.json').write_bytes(lock_bytes)

class TestCompilation(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('ocsf_generate', ROOT / 'generate.py')
        self.g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.g)
        self.assertTrue(callable(getattr(self.g, 'compile_profile', None)), 'compile_profile interface is absent')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'schemas/ocsf'
        shutil.copytree(ROOT, self.root)

    def profile(self):
        return json.loads((self.root / 'profile.json').read_bytes())

    def reject(self, mutate):
        p = self.profile()
        mutate(p)
        (self.root / 'profile.json').write_text(json.dumps(p))
        with self.assertRaises(ValueError):
            self.g.compile_profile(self.root)

    def test_source_bindings(self):
        self.g.compile_profile(self.root)
        self.reject(lambda p: p['objects']['certificate']['required'].remove('issuer'))

    def test_pinned_host_profile(self):
        r = self.g.SourceResolver(self.root)
        base = r.resolve('upstream/1.9.0/events/base_event.json')
        self.assertEqual(base['attributes']['device']['requirement'], 'recommended')
        self.assertEqual(base['attributes']['actor']['requirement'], 'optional')
        host = json.loads((ROOT / 'upstream/1.9.0/profiles/host.json').read_bytes())
        self.assertEqual(host['meta'], 'profile')
        self.assertEqual(host['annotations'], {'group': 'primary'})
        for bad in ({'annotations': {'groop': 'primary'}}, {'meta': 1}, {'metaa': 'profile'}):
            v = dict(host, **bad)
            with self.assertRaises(ValueError):
                self.g.check_source(v, 'profile')

    def test_bytes_unsigned_overrides(self):
        outputs = self.g.compile_profile(self.root)
        s = json.loads(outputs['compiled/99901003.schema.json'])
        self.assertEqual(s['properties']['bytes']['x-integer'], 'uint64')
        self.assertEqual(s['$defs']['spool_sample']['properties']['bytes']['x-integer'], 'uint64')
        self.reject(lambda p: p['classes'][0]['schema']['properties']['type_uid'].update({'x-integer': 'uint64', 'maximum': 18446744073709551615}))

    def test_unknown_construct(self):
        self.reject(lambda p: p['classes'][0]['schema'].update({'unknown': True}))

    def test_inheritance(self):
        r = self.g.SourceResolver(self.root)
        base = r.resolve('extensions/ricevanta/events/policy_activity.json')
        self.assertEqual(base['attributes']['metadata']['requirement'], 'required')
        self.reject(lambda p: p['classes'][0]['schema']['required'].remove('time'))

    def test_compiled_grammar(self):
        for bad in ({'type': 'null'}, {'$ref': 'https://example.com'}, {'additionalProperties': True}, {'x-rule': ['unknown']}, {'pattern': '(a+)+', 'x-maxBytes': 10}):
            with self.assertRaises(ValueError):
                self.g.check_schema(bad)

    def test_determinism(self):
        self.assertEqual(self.g.compile_profile(self.root), self.g.compile_profile(self.root))

    def test_embed_drift(self):
        outputs = self.g.compile_profile(ROOT)
        self.g.check_outputs(ROOT, outputs)
        name = next(k for k in outputs if k.startswith('server/'))
        path = ROOT.parents[1] / name
        original = path.read_bytes()
        try:
            path.write_bytes(original + b' ')
            with self.assertRaises(ValueError):
                self.g.check_outputs(ROOT, outputs)
        finally:
            path.write_bytes(original)

class TestSourceDefects(TestCompilation):
    def test_dependency_defects(self):
        path = self.root / 'extensions/ricevanta/objects/policy_bundle.json'
        original = path.read_bytes()
        cases = [dict(extends='missing'), dict(extends='policy_bundle'), dict(typo=True), dict(attributes={'sequence': {'type': 'string_t'}}), dict(attributes={'sequence': {'type': 'integer_t', 'is_array': True}})]
        for patch in cases:
            with self.subTest(patch=patch):
                v = json.loads(original)
                v.update(patch)
                path.write_text(json.dumps(v))
                with self.assertRaises((ValueError, OSError)):
                    self.g.compile_profile(self.root)
                path.write_bytes(original)
        path.write_bytes(b'{"name":"policy_bundle","name":"policy_bundle","attributes":{}}')
        with self.assertRaises(ValueError):
            self.g.compile_profile(self.root)

    def test_reference_cycle(self):
        self.reject(lambda p: p['objects']['policy_bundle']['properties']['bundle_uid'].update({'$ref':'#/$defs/policy_bundle'}))

    def test_unselected_class(self):
        self.reject(lambda p: p['classes'][0].update({'class_uid':6003}))

    def test_enum_conflict(self):
        self.reject(lambda p: p['objects']['os']['properties']['type_id'].update({'enum':[999]}))

class TestClosedInputs(TestCompilation):
    def test_missing_binding(self):
        self.reject(lambda p: p['classes'][0]['schema']['properties']['time'].pop('x-source'))

    def test_missing_rule(self):
        self.reject(lambda p: p['classes'][0]['schema']['x-rule'].remove('coverage'))

    def test_changed_limits(self):
        path=self.root/'limits.yaml'
        path.write_text(path.read_text().replace('device.labels: 32','device.labels: 31'))
        with self.assertRaises(ValueError):self.g.compile_profile(self.root)

    def test_source_required_removal(self):
        path=self.root/'extensions/ricevanta/events/policy_activity.json'
        v=json.loads(path.read_bytes());v['attributes']['time']=None;path.write_text(json.dumps(v))
        with self.assertRaises(ValueError):self.g.compile_profile(self.root)

    def test_nested_definitions(self):
        with self.assertRaises(ValueError):self.g.check_schema({'properties':{'x':{'$defs':{'a':{'unknown':True}}}}})

class TestBindingPaths(TestCompilation):
    def test_dictionary_path(self):
        self.reject(lambda p: p['classes'][0]['schema']['properties']['time'].update({'x-source':'elsewhere/dictionary.json#/attributes/time'}))

    def test_missing_native_type(self):
        path=self.root/'extensions/ricevanta/dictionary.json'
        v=json.loads(path.read_bytes());v['attributes']['processes']['type']='missing';path.write_text(json.dumps(v))
        with self.assertRaises(ValueError):self.g.compile_profile(self.root)

    def test_wrong_object_binding(self):
        self.reject(lambda p: p['objects']['device']['properties']['os'].update({'$ref':'#/$defs/group'}))

class TestSourceBranches(TestCompilation):
    def test_source_override(self):
        self.reject(lambda p: p['classes'][3].update({'source_kinds':['agent','server']}))

    def test_branch_inventory(self):
        self.reject(lambda p: p['classes'][0]['schema']['anyOf'].append({'x-sourceKind':'server'}))

class TestLiteralGrammar(TestCompilation):
    def test_null_literal(self):
        with self.assertRaises(ValueError):self.g.check_schema({'const':None})
        with self.assertRaises(ValueError):self.g.check_schema({'enum':[None]})


class TestReviewFindings(TestCompilation):
    def test_reference_type_siblings_at_every_binding(self):
        original = self.profile()
        paths = []
        def walk(node, path):
            if '$ref' in node and 'x-source' in node:
                paths.append(path)
            for key, value in node.items():
                if isinstance(value, dict):
                    walk(value, path + [key])
                elif isinstance(value, list):
                    for index, child in enumerate(value):
                        if isinstance(child, dict):
                            walk(child, path + [key, index])
        walk(original, [])
        self.assertEqual(len(paths), 21)
        from jsonschema import Draft202012Validator
        schema = json.loads((ROOT / 'profile.schema.json').read_bytes())
        validator = Draft202012Validator({'$defs': schema['$defs'], '$ref': '#/$defs/attribute'})
        for path in paths:
            with self.subTest(path=path):
                p = json.loads(json.dumps(original))
                node = p
                for key in path:
                    node = node[key]
                node['type'] = 'string'
                (self.root / 'profile.json').write_text(json.dumps(p))
                with self.assertRaisesRegex(ValueError, r'^schema\.grammar\.reference:type$'):
                    self.g.compile_profile(self.root)
                self.assertFalse(validator.is_valid(node))

    def test_closed_node_keyword_matrix(self):
        from jsonschema import Draft202012Validator
        # Include all Draft 2020-12 vocabulary keywords and legacy schema keywords.
        keywords = set("""$schema $id $vocabulary $anchor $dynamicAnchor $ref $dynamicRef
            $defs $comment type enum const multipleOf maximum exclusiveMaximum
            minimum exclusiveMinimum maxLength minLength pattern maxItems minItems
            uniqueItems maxContains minContains maxProperties minProperties required
            dependentRequired format contentEncoding contentMediaType contentSchema
            prefixItems items contains additionalProperties properties patternProperties
            dependentSchemas propertyNames if then else allOf anyOf oneOf not
            unevaluatedItems unevaluatedProperties title description default deprecated
            readOnly writeOnly definitions dependencies additionalItems id $recursiveRef
            $recursiveAnchor x-source x-restriction x-maxBytes x-integer x-sourceKind
            x-rule unknown x-unknown""".split())
        composition = set('allOf anyOf oneOf not if then else'.split())
        annotations = {'x-source', 'x-restriction'}
        scalar = {'type', 'const', 'enum'} | composition | annotations
        cases = [
            ('reference', {'$ref': '#/$defs/os'}, {'$ref', 'x-source'}),
            ('string', {'type': 'string'}, scalar | {'minLength', 'maxLength', 'pattern', 'x-maxBytes'}),
            ('integer', {'type': 'integer'}, scalar | {'minimum', 'maximum', 'x-integer'}),
            ('number', {'type': 'number'}, scalar | {'minimum', 'maximum'}),
            ('boolean', {'type': 'boolean'}, scalar),
            ('array', {'type': 'array', 'items': {'type': 'string'}},
             {'type', 'items', 'minItems', 'maxItems'} | composition | annotations),
            ('fragment', {'const': 1}, {'type', 'const', 'enum', 'minimum', 'maximum', 'x-integer',
                                     'minLength', 'maxLength', 'pattern', 'x-maxBytes'} | composition),
            ('object_fragment', {'required': ['name']}, {'properties', 'required'} | composition | {'x-sourceKind'}),
            ('string_fragment', {'pattern': '^[0-9a-f]{64}$'},
             {'type', 'const', 'enum', 'pattern', 'minLength', 'maxLength', 'x-maxBytes'} | composition),
            ('number_fragment', {'minimum': 0}, {'type', 'const', 'enum', 'minimum', 'maximum', 'x-integer'} | composition),
            ('array_fragment', {'minItems': 0}, {'type', 'items', 'minItems', 'maxItems'} | composition),
        ]
        root_keys = {'type', 'properties', 'required', 'additionalProperties', 'x-source',
                     'title', 'description'} | composition
        cases += [('definition', self.profile()['objects']['os'], root_keys),
                  ('class', self.profile()['classes'][0]['schema'], root_keys | {'x-rule'})]
        samples = {
            '$ref': '#/$defs/os', 'type': 'string', 'properties': {}, 'required': [],
            'additionalProperties': False, 'items': {'type': 'string'},
            'const': 1, 'enum': [1], 'pattern': '^[0-9a-f]{64}$',
            'x-integer': 'int64', 'x-sourceKind': 'agent', 'x-rule': [],
            'x-source': 'extensions/ricevanta/objects/os.json#',
            'x-restriction': 'review case', 'title': 'review case', 'description': 'review case',
            '$id': 'https://ricevanta.io/review',
            '$schema': 'https://json-schema.org/draft/2020-12/schema', '$defs': {},
        }
        samples.update({k: 1 for k in ('minimum', 'maximum', 'minLength', 'maxLength',
                                       'minItems', 'maxItems', 'x-maxBytes')})
        samples.update({k: [{}] for k in ('allOf', 'anyOf', 'oneOf')})
        samples.update({k: {} for k in ('not', 'if', 'then', 'else')})
        schema = json.loads((ROOT / 'profile.schema.json').read_bytes())
        for kind, node, allowed in cases:
            contexts = ([kind] if kind in ('class', 'definition') else
                        ['fragment', 'attribute', 'item'] if kind in
                        ('reference', 'string', 'integer', 'number', 'boolean', 'array') else ['fragment'])
            for context in contexts:
                validator = Draft202012Validator({'$defs': schema['$defs'],
                                                  '$ref': '#/$defs/' + context})
                baseline = json.loads(json.dumps(node))
                if context == 'attribute':
                    baseline['x-source'] = 'extensions/ricevanta/objects/os.json#/attributes/name'
                self.assertTrue(validator.is_valid(baseline), (kind, context))
                self.g.check_schema(baseline, root_kind=context,
                                    definitions=self.profile()['objects'], compiled=False)
                for keyword in sorted(keywords - allowed):
                    with self.subTest(kind=kind, context=context, keyword=keyword):
                        bad = dict(baseline, **{keyword: samples.get(keyword, True)})
                        with self.assertRaisesRegex(ValueError, r'^schema\.grammar\.'):
                            self.g.check_schema(bad, root_kind=context,
                                                definitions=self.profile()['objects'], compiled=False)
                        self.assertFalse(validator.is_valid(bad))

    def test_fragment_keywords_and_literals_check_native_type(self):
        resolver = self.g.SourceResolver(self.root)
        cases = [
            ('string_t', {'minimum': 0}, 'binding.type'),
            ('integer_t', {'minLength': 1}, 'binding.type'),
            ('boolean_t', {'maximum': 1}, 'binding.type'),
            ('string_t', {'const': 1}, 'binding.literal_type'),
            ('integer_t', {'enum': ['1']}, 'binding.literal_type'),
            ('boolean_t', {'const': 1}, 'binding.literal_type'),
        ]
        for native_type, node, error in cases:
            with self.subTest(native_type=native_type, node=node):
                with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                    self.g._bind(self.root, resolver, node, {}, 'test.value',
                                 native_attribute={'type': native_type}, fragment=True)

    def test_definition_fragments_check_native_object_type(self):
        original = self.profile()
        for fragment in ({'type': 'string'}, {'minimum': 0}, {'const': 'os'}):
            with self.subTest(fragment=fragment):
                p = json.loads(json.dumps(original))
                p['objects']['os']['allOf'].append(fragment)
                (self.root / 'profile.json').write_text(json.dumps(p))
                with self.assertRaisesRegex(ValueError, r'^binding\.(type|literal_type)$'):
                    self.g.compile_profile(self.root)

    def test_signed_width_reviewer_inputs(self):
        original = self.profile()
        for name in ('time', 'type_uid'):
            with self.subTest(field=name):
                p = json.loads(json.dumps(original))
                field = p['classes'][0]['schema']['properties'][name]
                if name == 'time':
                    field['x-integer'] = 'uint64'
                else:
                    field.pop('x-integer')
                field['maximum'] = 18446744073709551615
                (self.root / 'profile.json').write_text(json.dumps(p))
                with self.assertRaisesRegex(ValueError, '^binding.integer_range$'):
                    self.g.compile_profile(self.root)

    def test_native_integer_ranges(self):
        resolver = self.g.SourceResolver(self.root)
        types = resolver.dictionary['types']['attributes']
        # Exercise every pinned integer type with a defined width or range.
        cases = {'long_t': (-2**63, 2**63 - 1),
                 'timestamp_t': (-2**63, 2**63 - 1),
                 'port_t': (0, 65535)}
        self.assertEqual({name for name, node in types.items()
                          if name == 'long_t' or node.get('type') == 'long_t'
                          or (node.get('type') == 'integer_t' and 'range' in node)},
                         set(cases))
        for native_type, (low, high) in cases.items():
            for annotation in (None, 'int64', 'uint64'):
                node = {'type': 'integer', 'minimum': low, 'maximum': high}
                if annotation is not None:
                    node['x-integer'] = annotation
                for patch in ({'minimum': low - 1}, {'maximum': high + 1},
                              {'minimum': high + 1}, {'maximum': low - 1},
                              {'minimum': None}, {'maximum': None}):
                    with self.subTest(native_type=native_type, annotation=annotation,
                                      patch=patch):
                        bad = dict(node, **patch)
                        bad = {k: v for k, v in bad.items() if v is not None}
                        with self.assertRaisesRegex(ValueError, '^binding.integer_range$'):
                            self.g._bind(self.root, resolver, bad, {}, 'test.value',
                                         native_attribute={'type': native_type})
                with self.subTest(native_type=native_type, annotation=annotation):
                    if native_type != 'port_t' and annotation == 'uint64':
                        with self.assertRaisesRegex(ValueError, '^binding.unsigned$'):
                            self.g._bind(self.root, resolver, node, {}, 'test.value',
                                         native_attribute={'type': native_type})
                    else:
                        self.g._bind(self.root, resolver, node, {}, 'test.value',
                                     native_attribute={'type': native_type})

    def test_native_integer_fragment_ranges(self):
        resolver = self.g.SourceResolver(self.root)
        for native_type, low, high in (('long_t', -2**63, 2**63 - 1),
                                      ('timestamp_t', -2**63, 2**63 - 1),
                                      ('port_t', 0, 65535)):
            for node in ({'minimum': low}, {'maximum': high}, {'const': low}):
                self.g._bind(self.root, resolver, node, {}, 'test.value',
                             native_attribute={'type': native_type}, fragment=True)
            for node in ({'minimum': low - 1}, {'maximum': high + 1},
                         {'const': high + 1}, {'enum': [low - 1]}):
                with self.subTest(native_type=native_type, node=node):
                    with self.assertRaisesRegex(ValueError, '^binding.integer_range$'):
                        self.g._bind(self.root, resolver, node, {}, 'test.value',
                                     native_attribute={'type': native_type}, fragment=True)

    def edit_source(self, relative, mutate):
        path = self.root / relative
        value = json.loads(path.read_bytes())
        mutate(value)
        path.write_text(json.dumps(value))

    def add_os_shadow(self, p):
        path = self.root / 'extensions/ricevanta/objects/os_shadow.json'
        path.write_text(json.dumps({
            'name': 'os_shadow', 'caption': 'OS shadow',
            'description': 'Review case.', 'extends': 'os',
            'attributes': {'name': {'type': 'string_t'}},
        }))
        p['objects']['os_shadow'] = json.loads(json.dumps(p['objects']['os']))
        p['objects']['os_shadow']['x-source'] = 'extensions/ricevanta/objects/os_shadow.json#'

    def test_definition_ref_cannot_hide_native_type_change(self):
        p = self.profile()
        self.add_os_shadow(p)
        self.edit_source('extensions/ricevanta/objects/os.json',
                         lambda v: v['attributes'].update({'name': {'type': 'integer_t'}}))
        p['objects']['os']['$ref'] = '#/$defs/os_shadow'
        (self.root / 'profile.json').write_text(json.dumps(p))
        with self.assertRaisesRegex(ValueError, r'^schema\.grammar\.definition:\$ref$'):
            self.g.compile_profile(self.root)

    def test_definition_aliases(self):
        original = self.profile()
        self.add_os_shadow(original)
        for keyword in ('$ref', 'allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else'):
            with self.subTest(keyword=keyword):
                p = json.loads(json.dumps(original))
                ref = {'$ref': '#/$defs/os_shadow'}
                p['objects']['os'][keyword] = (ref['$ref'] if keyword == '$ref' else
                    [ref] if keyword in ('allOf', 'anyOf', 'oneOf') else ref)
                (self.root / 'profile.json').write_text(json.dumps(p))
                error = r'^schema\.grammar\.definition:\$ref$' if keyword == '$ref' else '^binding.definition_reference$'
                with self.assertRaisesRegex(ValueError, error):
                    self.g.compile_profile(self.root)

    def test_every_definition_checks_own_native_object(self):
        original = self.profile()
        for name, node in original['objects'].items():
            with self.subTest(definition=name):
                p = json.loads(json.dumps(original))
                path = self.root / ('extensions/ricevanta/objects/' + name + '.json')
                saved = path.read_bytes() if path.exists() else None
                native = json.loads(saved) if saved is not None else {
                    'name': name, 'caption': name, 'description': 'Native binding test.',
                    'extends': name, 'attributes': {},
                }
                field, schema = next(iter(node['properties'].items()))
                native['attributes'][field] = {
                    'type': 'integer_t' if schema.get('type') == 'string' else 'string_t',
                }
                path.write_text(json.dumps(native))
                p['objects'][name]['x-source'] = path.relative_to(self.root).as_posix() + '#'
                (self.root / 'profile.json').write_text(json.dumps(p))
                try:
                    with self.assertRaisesRegex(ValueError, r'^binding\.(attribute|array|type|object)$'):
                        self.g.compile_profile(self.root)
                finally:
                    if saved is None:
                        path.unlink()
                    else:
                        path.write_bytes(saved)

    def test_inline_os_required_native_field(self):
        self.edit_source('extensions/ricevanta/objects/os.json',
                         lambda v: v['attributes'].update({'cpu_bits': {'type': 'integer_t', 'requirement': 'required'}}))
        p = self.profile()
        field = p['objects']['device']['properties']['os']
        inline = p['objects'].pop('os')
        inline['x-source'] = field['x-source']
        p['objects']['device']['properties']['os'] = inline
        (self.root / 'profile.json').write_text(json.dumps(p))
        with self.assertRaisesRegex(ValueError, '^schema\\.grammar\\.attribute:type$'):
            self.g.compile_profile(self.root)

    def test_inline_process_item_native_type(self):
        self.edit_source('extensions/ricevanta/objects/process_sample.json',
                         lambda v: v['attributes']['name'].update({'type': 'integer_t'}))
        p = self.profile()
        inline = p['objects'].pop('process_sample')
        inline.pop('x-source')
        inline['properties']['name'].pop('x-source')
        p['classes'][0]['schema']['properties']['processes']['items'] = inline
        (self.root / 'profile.json').write_text(json.dumps(p))
        with self.assertRaisesRegex(ValueError, '^schema\\.grammar\\.item:type$'):
            self.g.compile_profile(self.root)

    def test_nested_object_projection_branches(self):
        original = self.profile()
        for keyword in ('not', 'if', 'then', 'else', 'allOf', 'anyOf', 'oneOf'):
            with self.subTest(keyword=keyword):
                p = json.loads(json.dumps(original))
                inline = json.loads(json.dumps(p['objects']['os']))
                inline.pop('x-source')
                field = p['objects']['device']['properties']['os']
                field[keyword] = [inline] if keyword in ('allOf', 'anyOf', 'oneOf') else inline
                (self.root / 'profile.json').write_text(json.dumps(p))
                with self.assertRaisesRegex(ValueError, r'^schema\.grammar\.reference:' + keyword + '$'):
                    self.g.compile_profile(self.root)

    def test_nested_native_attribute_context(self):
        original = self.profile()
        for keyword in ('not', 'if', 'then', 'else', 'allOf', 'anyOf', 'oneOf'):
            with self.subTest(keyword=keyword):
                p = json.loads(json.dumps(original))
                field = p['objects']['process_sample']
                fragment = {'properties': {'name': {'type': 'integer'}}}
                field[keyword] = [fragment] if keyword in ('allOf', 'anyOf', 'oneOf') else fragment
                (self.root / 'profile.json').write_text(json.dumps(p))
                with self.assertRaisesRegex(ValueError, '^binding.type$'):
                    self.g.compile_profile(self.root)

    def test_nested_native_constraints_remain_valid(self):
        p = self.profile()
        item = p['objects']['process_sample']
        item['if'] = {'properties': {'name': {'const': 'collector'}}}
        item['then'] = {'properties': {'name': {'type': 'string', 'minLength': 1}}}
        (self.root / 'profile.json').write_text(json.dumps(p))
        self.g.compile_profile(self.root)

    def test_untyped_inline_object_item(self):
        p = self.profile()
        inline = p['objects'].pop('process_sample')
        inline.pop('type')
        inline.pop('x-source')
        p['classes'][0]['schema']['properties']['processes']['items'] = inline
        (self.root / 'profile.json').write_text(json.dumps(p))
        with self.assertRaisesRegex(ValueError, '^schema\\.grammar\\.item:type$'):
            self.g.compile_profile(self.root)

    def test_property_binding_identity(self):
        self.reject(lambda p: p['classes'][1]['schema']['properties']['command_uid'].update(
            {'x-source': 'extensions/ricevanta/events/policy_activity.json#/attributes/rule_uid'}))

    def test_command_native_type(self):
        self.edit_source('extensions/ricevanta/events/policy_activity.json',
                         lambda v: v['attributes']['command_uid'].update({'type': 'integer_t'}))
        with self.assertRaises(ValueError):
            self.g.compile_profile(self.root)

    def test_required_attribute_bindings(self):
        original = self.profile()
        cases = [
            (None, 'binding.missing'),
            ('', 'binding.empty'),
            ('extensions/ricevanta/events/policy_activity.json#', 'binding.kind'),
            ('extensions/ricevanta/events/policy_activity.json#/attributes/rule_uid', 'binding.attribute'),
            ('upstream/1.9.0/profiles/host.json#/attributes/command_uid', 'binding.kind'),
        ]
        for source, error in cases:
            with self.subTest(source=source):
                p = json.loads(json.dumps(original))
                field = p['classes'][1]['schema']['properties']['command_uid']
                if source is None:
                    field.pop('x-source')
                else:
                    field['x-source'] = source
                (self.root / 'profile.json').write_text(json.dumps(p))
                with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                    self.g.compile_profile(self.root)

    def test_required_root_bindings(self):
        original = self.profile()
        for kind in ('object', 'class'):
            path = ('extensions/ricevanta/objects/os.json' if kind == 'object'
                    else 'extensions/ricevanta/events/policy_activity.json')
            cases = [
                (None, 'binding.missing'),
                ('', 'binding.empty'),
                (path, 'binding.path'),
                ('upstream/1.9.0/dictionary.json#/attributes/os', 'binding.kind'),
                (path + '#/attributes/type_id', 'binding.kind'),
                ('extensions/ricevanta/objects/device.json#', 'binding.root' if kind == 'object' else 'binding.kind'),
                ('extensions/ricevanta/events/agent_health_activity.json#', 'binding.kind' if kind == 'object' else 'binding.root'),
            ]
            for source, error in cases:
                with self.subTest(kind=kind, source=source):
                    p = json.loads(json.dumps(original))
                    node = p['objects']['os'] if kind == 'object' else p['classes'][1]['schema']
                    if source is None:
                        node.pop('x-source')
                    else:
                        node['x-source'] = source
                    (self.root / 'profile.json').write_text(json.dumps(p))
                    with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                        self.g.compile_profile(self.root)

    def test_empty_command_binding_with_native_type_change(self):
        self.edit_source('extensions/ricevanta/events/policy_activity.json',
                         lambda v: v['attributes']['command_uid'].update({'type': 'integer_t'}))
        p = self.profile()
        p['classes'][1]['schema']['properties']['command_uid']['x-source'] = ''
        (self.root / 'profile.json').write_text(json.dumps(p))
        with self.assertRaisesRegex(ValueError, '^binding.empty$'):
            self.g.compile_profile(self.root)

    def test_invalid_os_binding_with_required_native_field(self):
        self.edit_source('extensions/ricevanta/objects/os.json',
                         lambda v: v['attributes'].update({'cpu_bits': {'type': 'integer_t', 'requirement': 'required'}}))
        original = self.profile()
        for source, error in [('', 'binding.empty'),
                              ('upstream/1.9.0/dictionary.json#/attributes/os', 'binding.kind')]:
            with self.subTest(source=source):
                p = json.loads(json.dumps(original))
                p['objects']['os']['x-source'] = source
                (self.root / 'profile.json').write_text(json.dumps(p))
                with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                    self.g.compile_profile(self.root)

    def test_augmented_root_binding(self):
        self.reject(lambda p: p['objects']['os'].update({'x-source': 'upstream/1.9.0/objects/os.json#'}))

    def test_augmented_required_field(self):
        self.edit_source('extensions/ricevanta/objects/os.json',
                         lambda v: v['attributes'].update({'cpu_bits': {'type': 'integer_t', 'requirement': 'required'}}))
        with self.assertRaises(ValueError):
            self.g.compile_profile(self.root)

    def test_inherited_required_downgrade(self):
        self.edit_source('extensions/ricevanta/events/policy_activity.json',
                         lambda v: v['attributes'].update({'time': {'requirement': 'optional'}}))
        self.reject(lambda p: (p['classes'][1]['schema']['required'].remove('time'),
                               p['classes'][1]['schema']['properties'].pop('time')))

    def test_native_enum_requires_domain(self):
        self.reject(lambda p: p['objects']['os']['properties']['type_id'].pop('enum'))

    def test_data_object_requires_closure(self):
        with self.assertRaises(ValueError):
            self.g.check_schema({'$defs': {'device': {'type': 'object', 'properties': {}}}})

    def test_distribution_notice(self):
        notice = (ROOT / 'upstream/1.9.0/NOTICE').read_text()
        self.assertIn(notice, (ROOT.parents[1] / 'NOTICE').read_text())


# Independent allowlist for contract-fields.md sections 1 through 6 and
# ocsf-profile.md section 4. Changes require a reviewed catalogue rule.
# Each entry names exact field, presence, bound and conditional restrictions.
CATALOGUE_RULES = json.loads(r'''{
  "object/budget_sample": {
    "additionalProperties": false,
    "properties": {
      "cpu_limit_pct": {"allOf": [{"maximum": 100, "minimum": 0, "type": "number"}, {"not": {"const": 0}}], "type": "number"},
      "cpu_pct": {"maximum": 100, "minimum": 0, "type": "number"},
      "memory_bytes": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "memory_limit_bytes": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "state": {"enum": ["normal", "throttled", "disabled"], "maxLength": 9, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 9},
      "unit": {"allOf": [{"pattern": "^[a-z][a-z0-9_.-]*$"}], "maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "window_ms": {"maximum": 3600000, "minimum": 1, "type": "integer", "x-integer": "uint64"}
    },
    "required": ["cpu_limit_pct", "memory_limit_bytes", "state", "unit", "window_ms"],
    "type": "object"
  },
  "object/certificate": {
    "additionalProperties": false,
    "properties": {
      "created_time": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "expiration_time": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "fingerprints": {"items": {"$ref": "#/$defs/fingerprint"}, "maxItems": 1, "minItems": 1, "type": "array"},
      "issuer": {"maxLength": 2048, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 2048},
      "serial_number": {"allOf": [{"pattern": "^([0-9a-f]{2}){1,20}$"}], "maxLength": 40, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 40},
      "subject": {"maxLength": 2048, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 2048},
      "uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256}
    },
    "required": ["created_time", "expiration_time", "fingerprints", "issuer", "serial_number", "uid"],
    "type": "object"
  },
  "object/coverage_entry": {
    "additionalProperties": false,
    "properties": {
      "path": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "reason": {"enum": ["not_applicable", "not_observed", "sensor_unavailable", "permission_denied", "collection_failed", "privacy_filtered"], "maxLength": 18, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 18}
    },
    "required": ["path", "reason"],
    "type": "object"
  },
  "object/device": {
    "additionalProperties": false,
    "properties": {
      "groups": {"items": {"$ref": "#/$defs/group"}, "maxItems": 64, "minItems": 0, "type": "array"},
      "hostname": {"maxLength": 253, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 253},
      "labels": {"items": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128}, "maxItems": 32, "minItems": 0, "type": "array"},
      "os": {"$ref": "#/$defs/os"},
      "type_id": {"enum": [0, 1, 2, 3], "maximum": 3, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256}
    },
    "required": ["hostname", "os", "type_id", "uid"],
    "type": "object"
  },
  "object/event_rate": {
    "additionalProperties": false,
    "properties": {
      "count": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "source": {"allOf": [{"pattern": "^[a-z][a-z0-9_.-]*$"}], "maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128}
    },
    "required": ["count", "source"],
    "type": "object"
  },
  "object/extension": {
    "additionalProperties": false,
    "properties": {
      "name": {"const": "ricevanta", "maxLength": 9, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 9},
      "uid": {"const": "999", "maxLength": 3, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 3},
      "version": {"const": "1.9.0", "maxLength": 5, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 5}
    },
    "required": ["name", "uid", "version"],
    "type": "object"
  },
  "object/extension_origin": {
    "additionalProperties": false,
    "properties": {
      "component": {"allOf": [{"pattern": "^[a-z][a-z0-9_.-]*$"}], "maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "component_digest": {"allOf": [{"pattern": "^[0-9a-f]{64}$"}], "maxLength": 64, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 64},
      "grant_generation": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "id": {"allOf": [{"pattern": "^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$"}], "maxLength": 253, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 253},
      "package_digest": {"allOf": [{"pattern": "^[0-9a-f]{64}$"}], "maxLength": 64, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 64},
      "recovery_epoch": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "version": {"allOf": [{"pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$"}], "maxLength": 64, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 64}
    },
    "required": ["component", "component_digest", "grant_generation", "id", "package_digest", "recovery_epoch", "version"],
    "type": "object"
  },
  "object/fingerprint": {
    "additionalProperties": false,
    "properties": {
      "algorithm_id": {"const": 3, "maximum": 3, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "value": {"allOf": [{"pattern": "^[0-9a-f]{64}$"}], "maxLength": 64, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 64}
    },
    "required": ["algorithm_id", "value"],
    "type": "object"
  },
  "object/group": {
    "additionalProperties": false,
    "properties": {
      "name": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256}
    },
    "required": ["name"],
    "type": "object"
  },
  "object/metadata": {
    "additionalProperties": false,
    "properties": {
      "bundle_state": {"enum": ["absent", "installed"], "maxLength": 9, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 9},
      "correlation_uid": {"maxLength": 36, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 36},
      "coverage": {"items": {"$ref": "#/$defs/coverage_entry"}, "maxItems": 512, "minItems": 1, "type": "array"},
      "extension_origin": {"$ref": "#/$defs/extension_origin"},
      "extensions": {"items": {"$ref": "#/$defs/extension"}, "maxItems": 1, "minItems": 1, "type": "array"},
      "is_truncated": {"const": true, "type": "boolean"},
      "original_time": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "policy_bundle": {"$ref": "#/$defs/policy_bundle"},
      "product": {"$ref": "#/$defs/product"},
      "profiles": {"items": {"maxLength": 4, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 4}, "maxItems": 1, "minItems": 0, "type": "array"},
      "sequence": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "truncation": {"$ref": "#/$defs/truncation"},
      "uid": {"maxLength": 36, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 36},
      "untruncated_size": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "version": {"const": "1.9.0", "maxLength": 5, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 5}
    },
    "required": ["correlation_uid", "extensions", "product", "profiles", "sequence", "uid", "version"],
    "type": "object"
  },
  "object/os": {
    "additionalProperties": false,
    "allOf": [{"else": {"properties": {"cpu_architecture": {"const": "x64"}}}, "if": {"properties": {"type_id": {"const": 300}}, "required": ["type_id"]}, "then": {"properties": {"cpu_architecture": {"const": "arm64"}}}}],
    "properties": {
      "cpu_architecture": {"enum": ["arm64", "x64"], "maxLength": 5, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 5},
      "name": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "type_id": {"enum": [100, 200, 300], "maximum": 300, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "version": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128}
    },
    "required": ["cpu_architecture", "name", "type_id"],
    "type": "object"
  },
  "object/policy": {
    "additionalProperties": false,
    "properties": {
      "uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "version": {"allOf": [{"pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$"}], "maxLength": 64, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 64}
    },
    "required": ["uid", "version"],
    "type": "object"
  },
  "object/policy_bundle": {
    "additionalProperties": false,
    "properties": {
      "bundle_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "recovery_epoch": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "scope_id": {"allOf": [{"pattern": "^[0-9a-f]{64}$"}], "maxLength": 64, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 64},
      "sequence": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"}
    },
    "required": ["bundle_uid", "recovery_epoch", "scope_id", "sequence"],
    "type": "object"
  },
  "object/process_sample": {
    "additionalProperties": false,
    "properties": {
      "cpu_pct": {"maximum": 100, "minimum": 0, "type": "number"},
      "event_rates": {"items": {"$ref": "#/$defs/event_rate"}, "maxItems": 128, "minItems": 0, "type": "array"},
      "fd_count": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "footprint_bytes": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "footprint_metric": {"enum": ["phys_footprint", "private_working_set", "pss"], "maxLength": 19, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 19},
      "handle_count": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "name": {"allOf": [{"pattern": "^[a-z][a-z0-9_.-]*$"}], "maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "pid": {"maximum": 4294967295, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256}
    },
    "required": ["event_rates", "footprint_metric", "name", "pid", "uid"],
    "type": "object"
  },
  "object/product": {
    "additionalProperties": false,
    "properties": {
      "name": {"const": "Ricevanta", "maxLength": 9, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 9},
      "vendor_name": {"const": "Ricevanta", "maxLength": 9, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 9},
      "version": {"allOf": [{"pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$"}], "maxLength": 64, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 64}
    },
    "required": ["name", "vendor_name", "version"],
    "type": "object"
  },
  "object/requester": {
    "additionalProperties": false,
    "properties": {
      "kind": {"enum": ["device", "user", "service"], "maxLength": 7, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 7},
      "uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256}
    },
    "required": ["kind", "uid"],
    "type": "object"
  },
  "object/sequence_range": {
    "additionalProperties": false,
    "properties": {
      "first": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "last": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"}
    },
    "required": ["first", "last"],
    "type": "object"
  },
  "object/spool_sample": {
    "additionalProperties": false,
    "properties": {
      "bytes": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64", "x-restriction": "Explicit unsigned byte counter at this use site."},
      "dropped_bytes": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "dropped_records": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "dropped_segments": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "last_ack_sequence": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "oldest_unsent_ms": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "spool_class": {"enum": ["raw", "context", "lineage", "findings", "audit"], "maxLength": 8, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 8},
      "stream_epoch": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "upload_errors": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"}
    },
    "required": ["bytes", "dropped_bytes", "dropped_records", "dropped_segments", "spool_class", "stream_epoch", "upload_errors"],
    "type": "object"
  },
  "object/truncation": {
    "additionalProperties": false,
    "properties": {
      "omitted_entries": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "original_event_bytes": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "original_unmapped_bytes": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"}
    },
    "required": ["omitted_entries", "original_event_bytes", "original_unmapped_bytes"],
    "type": "object"
  },
  "object/unmapped": {
    "additionalProperties": false,
    "properties": {
      "entries": {"items": {"$ref": "#/$defs/unmapped_entry"}, "maxItems": 128, "minItems": 1, "type": "array"}
    },
    "required": ["entries"],
    "type": "object"
  },
  "object/unmapped_entry": {
    "additionalProperties": false,
    "properties": {
      "field": {"enum": ["os_error_code", "sampler_backend", "native_event_code"], "maxLength": 17, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 17},
      "index": {"maximum": 127, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "reason": {"enum": ["field_unmapped", "value_unmapped"], "maxLength": 14, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 14},
      "value": {"allOf": [{"pattern": "^[A-Za-z0-9_.:-]+$"}], "maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256}
    },
    "required": ["field", "index", "reason", "value"],
    "type": "object"
  },
  "class/99901001": {
    "additionalProperties": false,
    "allOf": [{"if": {"properties": {"activity_id": {"const": 1}}, "required": ["activity_id"]}, "then": {"properties": {"status_id": {"const": 1}}, "required": []}}, {"properties": {"metadata": {"not": {"required": ["extension_origin"]}}}}, {"if": {"properties": {"activity_id": {"not": {"const": 1}}}}, "then": {"properties": {"metadata": {"not": {"anyOf": [{"required": ["is_truncated"]}, {"required": ["untruncated_size"]}, {"required": ["truncation"]}]}}}}}],
    "anyOf": [{"properties": {"metadata": {"properties": {"profiles": {"minItems": 1, "maxItems": 1, "items": {"const": "host", "type": "string"}}}, "required": ["bundle_state"]}}, "required": ["device"], "x-sourceKind": "agent"}],
    "properties": {
      "activity_id": {"enum": [1], "maximum": 1, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "budgets": {"items": {"$ref": "#/$defs/budget_sample"}, "maxItems": 128, "minItems": 0, "type": "array"},
      "category_uid": {"const": 1, "maximum": 1, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "class_uid": {"const": 99901001, "maximum": 99901001, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "device": {"$ref": "#/$defs/device"},
      "interval_ms": {"maximum": 3600000, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "kernel_bytes": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "message": {"maxLength": 1024, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 1024},
      "metadata": {"$ref": "#/$defs/metadata"},
      "processes": {"items": {"$ref": "#/$defs/process_sample"}, "maxItems": 64, "minItems": 1, "type": "array"},
      "severity_id": {"const": 1, "maximum": 1, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "spools": {"items": {"$ref": "#/$defs/spool_sample"}, "maxItems": 5, "minItems": 5, "type": "array"},
      "status_id": {"enum": [0, 1, 2], "maximum": 2, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "time": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "type_uid": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "unmapped": {"$ref": "#/$defs/unmapped"}
    },
    "required": ["activity_id", "budgets", "category_uid", "class_uid", "interval_ms", "metadata", "processes", "severity_id", "spools", "status_id", "time", "type_uid"],
    "type": "object",
    "x-rule": ["type_uid", "bundle_state", "coverage", "health_identity", "unmapped", "truncation"]
  },
  "class/99901002": {
    "additionalProperties": false,
    "allOf": [{"if": {"properties": {"activity_id": {"const": 1}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["rule_uid"]}, {"required": ["unit"]}]}, "properties": {"reason": {"enum": ["completed"]}, "status_id": {"const": 1}}, "required": ["policy", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 2}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["rule_uid"]}]}, "properties": {"reason": {"enum": ["evaluation_failed", "measurement_failed", "query_failed"]}, "status_id": {"const": 2}}, "required": ["reason"]}}, {"if": {"properties": {"activity_id": {"const": 3}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["rule_uid"]}, {"required": ["unit"]}]}, "properties": {"reason": {"enum": ["exception_active"]}, "status_id": {"const": 1}}, "required": ["exception_uid", "policy", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 4}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["rule_uid"]}]}, "properties": {"reason": {"enum": ["timeout", "resource_limit", "sensor_unavailable"]}, "status_id": {"const": 2}}, "required": ["policy", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 5}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["rule_uid"]}]}, "properties": {"reason": {"enum": ["timeout", "resource_limit", "sensor_unavailable"]}, "status_id": {"const": 2}}, "required": ["policy", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 6}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["exception_uid"]}, {"required": ["rule_uid"]}, {"required": ["unit"]}]}, "properties": {"reason": {"enum": ["invalid_signature", "expired", "stale_epoch", "scope_mismatch", "replay", "unsupported"]}, "status_id": {"const": 2}}, "required": ["command_uid", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 7}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["policy"]}, {"required": ["rule_uid"]}, {"required": ["unit"]}]}, "properties": {"reason": {"enum": ["installed"]}, "status_id": {"const": 1}}, "required": ["candidate_bundle_uid", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 8}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["policy"]}, {"required": ["rule_uid"]}, {"required": ["unit"]}]}, "properties": {"reason": {"enum": ["invalid_signature", "stale_epoch", "scope_mismatch", "replay", "unsupported"]}, "status_id": {"const": 2}}, "required": ["candidate_bundle_uid", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 9}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["unit"]}]}, "properties": {"reason": {"enum": ["unsupported"]}, "status_id": {"const": 2}}, "required": ["rule_uid", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 10}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["rule_uid"]}]}, "properties": {"reason": {"enum": ["resource_limit"]}, "status_id": {"const": 2}}, "required": ["unit", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 11}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["candidate_bundle_uid"]}, {"required": ["command_uid"]}, {"required": ["exception_uid"]}, {"required": ["rule_uid"]}]}, "properties": {"reason": {"enum": ["resource_limit", "repeated_failure"]}, "status_id": {"const": 2}}, "required": ["unit", "reason"]}}, {"properties": {"metadata": {"not": {"required": ["coverage"]}}}}, {"if": {"properties": {"activity_id": {"not": {"const": 2}}}}, "then": {"not": {"required": ["unmapped"]}}}, {"if": {"properties": {"activity_id": {"not": {"const": 2}}}}, "then": {"properties": {"metadata": {"not": {"anyOf": [{"required": ["is_truncated"]}, {"required": ["untruncated_size"]}, {"required": ["truncation"]}]}}}}}],
    "anyOf": [{"properties": {"metadata": {"properties": {"profiles": {"minItems": 1, "maxItems": 1, "items": {"const": "host", "type": "string"}}}, "required": ["bundle_state"]}}, "required": ["device"], "x-sourceKind": "agent"}, {"not": {"required": ["device"]}, "properties": {"activity_id": {"not": {"const": 7}}, "metadata": {"not": {"anyOf": [{"required": ["bundle_state"]}, {"required": ["policy_bundle"]}]}, "properties": {"profiles": {"maxItems": 0}}}}, "x-sourceKind": "server"}],
    "properties": {
      "activity_id": {"enum": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], "maximum": 11, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "candidate_bundle_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "category_uid": {"const": 1, "maximum": 1, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "class_uid": {"const": 99901002, "maximum": 99901002, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "command_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "device": {"$ref": "#/$defs/device"},
      "exception_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "message": {"maxLength": 1024, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 1024},
      "metadata": {"$ref": "#/$defs/metadata"},
      "policy": {"$ref": "#/$defs/policy"},
      "reason": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "rule_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "severity_id": {"maximum": 6, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "status_id": {"enum": [0, 1, 2], "maximum": 2, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "time": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "type_uid": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "unit": {"allOf": [{"pattern": "^[a-z][a-z0-9_.-]*$"}], "maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "unmapped": {"$ref": "#/$defs/unmapped"}
    },
    "required": ["activity_id", "category_uid", "class_uid", "metadata", "severity_id", "status_id", "time", "type_uid"],
    "type": "object",
    "x-rule": ["type_uid", "bundle_state", "policy_activity", "unmapped", "truncation"]
  },
  "class/99901003": {
    "additionalProperties": false,
    "allOf": [{"if": {"properties": {"activity_id": {"const": 1}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["affected_device_uid"]}, {"required": ["archive_uid"]}, {"required": ["destination"]}, {"required": ["destination_state"]}, {"required": ["event_uid"]}, {"required": ["quarantine_uid"]}]}, "properties": {"reason": {"enum": ["corrupt", "capacity", "rejected", "lookback_overrun"]}, "status_id": {"const": 2}}, "required": ["bytes", "count", "spool_class", "stream_epoch", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 2}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["archive_uid"]}, {"required": ["bytes"]}, {"required": ["destination"]}, {"required": ["destination_state"]}, {"required": ["event_uid"]}, {"required": ["quarantine_uid"]}]}, "properties": {"reason": {"enum": ["sequence_gap"]}, "status_id": {"const": 0}}, "required": ["affected_device_uid", "count", "sequence_range", "spool_class", "stream_epoch", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 3}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["archive_uid"]}, {"required": ["bytes"]}, {"required": ["destination"]}, {"required": ["destination_state"]}, {"required": ["sequence_range"]}, {"required": ["spool_class"]}, {"required": ["stream_epoch"]}]}, "properties": {"reason": {"enum": ["schema_invalid", "device_binding", "extension_binding", "event_id", "sequence", "json"]}, "status_id": {"const": 2}}, "required": ["affected_device_uid", "count", "quarantine_uid", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 4}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["affected_device_uid"]}, {"required": ["archive_uid"]}, {"required": ["bytes"]}, {"required": ["count"]}, {"required": ["event_uid"]}, {"required": ["quarantine_uid"]}, {"required": ["sequence_range"]}, {"required": ["spool_class"]}, {"required": ["stream_epoch"]}]}, "properties": {"reason": {"enum": ["recovered", "retrying", "dead_letter", "paused", "lag"]}}, "required": ["destination", "destination_state", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 5}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["affected_device_uid"]}, {"required": ["destination_state"]}, {"required": ["event_uid"]}, {"required": ["quarantine_uid"]}, {"required": ["sequence_range"]}, {"required": ["spool_class"]}, {"required": ["stream_epoch"]}]}, "properties": {"reason": {"enum": ["completed", "failed"]}}, "required": ["archive_uid", "bytes", "count", "destination", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 6}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["affected_device_uid"]}, {"required": ["archive_uid"]}, {"required": ["destination"]}, {"required": ["destination_state"]}, {"required": ["event_uid"]}, {"required": ["quarantine_uid"]}, {"required": ["sequence_range"]}, {"required": ["spool_class"]}, {"required": ["stream_epoch"]}]}, "properties": {"reason": {"enum": ["lookback_overrun"]}, "status_id": {"const": 2}}, "required": ["bytes", "count", "reason"]}}, {"properties": {"metadata": {"not": {"required": ["coverage"]}}}}, {"properties": {"metadata": {"not": {"required": ["extension_origin"]}}}}, {"not": {"required": ["unmapped"]}}, {"else": {"if": {"properties": {"activity_id": {"const": 4}}}, "then": {"properties": {"status_id": {"const": 2}}}}, "if": {"properties": {"activity_id": {"const": 4}, "destination_state": {"const": "healthy"}}, "required": ["destination_state"]}, "then": {"properties": {"status_id": {"const": 1}}}}, {"else": {"if": {"properties": {"activity_id": {"const": 5}}}, "then": {"properties": {"status_id": {"const": 2}}}}, "if": {"properties": {"activity_id": {"const": 5}, "reason": {"const": "completed"}}, "required": ["reason"]}, "then": {"properties": {"status_id": {"const": 1}}}}, {"properties": {"metadata": {"not": {"anyOf": [{"required": ["is_truncated"]}, {"required": ["untruncated_size"]}, {"required": ["truncation"]}]}}}}],
    "anyOf": [{"properties": {"activity_id": {"enum": [1, 6]}, "metadata": {"properties": {"profiles": {"minItems": 1, "maxItems": 1, "items": {"const": "host", "type": "string"}}}, "required": ["bundle_state"]}}, "required": ["device"], "x-sourceKind": "agent"}, {"not": {"required": ["device"]}, "properties": {"activity_id": {"enum": [2, 3, 4, 5]}, "metadata": {"not": {"anyOf": [{"required": ["bundle_state"]}, {"required": ["policy_bundle"]}]}, "properties": {"profiles": {"maxItems": 0}}}}, "x-sourceKind": "server"}],
    "properties": {
      "activity_id": {"enum": [1, 2, 3, 4, 5, 6], "maximum": 6, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "affected_device_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "archive_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "bytes": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer", "x-integer": "uint64", "x-restriction": "Explicit unsigned byte counter at this use site."},
      "category_uid": {"const": 1, "maximum": 1, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "class_uid": {"const": 99901003, "maximum": 99901003, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "count": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "destination": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "destination_state": {"enum": ["healthy", "degraded", "failed", "lagging"], "maxLength": 8, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 8},
      "device": {"$ref": "#/$defs/device"},
      "event_uid": {"maxLength": 36, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 36},
      "message": {"maxLength": 1024, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 1024},
      "metadata": {"$ref": "#/$defs/metadata"},
      "quarantine_uid": {"maxLength": 36, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 36},
      "reason": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "sequence_range": {"$ref": "#/$defs/sequence_range"},
      "severity_id": {"maximum": 6, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "spool_class": {"enum": ["raw", "context", "lineage", "findings", "audit"], "maxLength": 8, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 8},
      "status_id": {"enum": [0, 1, 2], "maximum": 2, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "stream_epoch": {"maximum": 18446744073709551615, "minimum": 1, "type": "integer", "x-integer": "uint64"},
      "time": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "type_uid": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "unmapped": {"$ref": "#/$defs/unmapped"}
    },
    "required": ["activity_id", "category_uid", "class_uid", "metadata", "severity_id", "status_id", "time", "type_uid"],
    "type": "object",
    "x-rule": ["type_uid", "bundle_state", "sequence_range", "pipeline_activity", "unmapped", "truncation"]
  },
  "class/99903001": {
    "additionalProperties": false,
    "allOf": [{"if": {"properties": {"activity_id": {"const": 1}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["prior_certificate_uid"]}]}, "properties": {"reason": {"enum": ["issued"]}, "status_id": {"const": 1}}, "required": ["reason"]}}, {"if": {"properties": {"activity_id": {"const": 2}}, "required": ["activity_id"]}, "then": {"properties": {"reason": {"enum": ["renewed"]}, "status_id": {"const": 1}}, "required": ["prior_certificate_uid", "reason"]}}, {"if": {"properties": {"activity_id": {"const": 3}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["prior_certificate_uid"]}]}, "properties": {"reason": {"enum": ["revoked"]}, "status_id": {"const": 1}}, "required": ["reason"]}}, {"if": {"properties": {"activity_id": {"const": 4}}, "required": ["activity_id"]}, "then": {"not": {"anyOf": [{"required": ["prior_certificate_uid"]}]}, "properties": {"reason": {"enum": ["expired"]}, "status_id": {"const": 1}}, "required": ["reason"]}}, {"properties": {"metadata": {"not": {"required": ["coverage"]}}}}, {"properties": {"metadata": {"not": {"required": ["extension_origin"]}}}}, {"not": {"required": ["unmapped"]}}, {"properties": {"metadata": {"not": {"anyOf": [{"required": ["is_truncated"]}, {"required": ["untruncated_size"]}, {"required": ["truncation"]}]}}}}],
    "anyOf": [{"not": {"required": ["device"]}, "properties": {"metadata": {"not": {"anyOf": [{"required": ["bundle_state"]}, {"required": ["policy_bundle"]}]}, "properties": {"profiles": {"maxItems": 0}}}}, "x-sourceKind": "server"}],
    "properties": {
      "activity_id": {"enum": [1, 2, 3, 4], "maximum": 4, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "ca_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "category_uid": {"const": 3, "maximum": 3, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "certificate": {"$ref": "#/$defs/certificate"},
      "class_uid": {"const": 99903001, "maximum": 99903001, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "device": {"$ref": "#/$defs/device"},
      "message": {"maxLength": 1024, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 1024},
      "metadata": {"$ref": "#/$defs/metadata"},
      "prior_certificate_uid": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 256},
      "profile": {"allOf": [{"pattern": "^[a-z][a-z0-9_.-]*$"}], "maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "reason": {"maxLength": 128, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 128},
      "request_uid": {"maxLength": 36, "minLength": 1, "pattern": "^[^\\x00-\\x1f\\x7f]+$", "type": "string", "x-maxBytes": 36},
      "requester": {"$ref": "#/$defs/requester"},
      "severity_id": {"maximum": 6, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "status_id": {"enum": [0, 1, 2], "maximum": 2, "minimum": 0, "type": "integer", "x-integer": "uint64"},
      "time": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "type_uid": {"maximum": 9223372036854775807, "minimum": 0, "type": "integer", "x-integer": "int64"},
      "unmapped": {"$ref": "#/$defs/unmapped"}
    },
    "required": ["activity_id", "ca_uid", "category_uid", "certificate", "class_uid", "metadata", "profile", "request_uid", "requester", "severity_id", "status_id", "time", "type_uid"],
    "type": "object",
    "x-rule": ["type_uid", "bundle_state", "certificate_activity", "unmapped", "truncation"]
  }
}''')


def catalogue_string_boundaries(rule):
    """Return valid extrema of the documented string domains, including enums."""
    from jsonschema import Draft202012Validator

    if 'const' in rule or 'enum' in rule:
        candidates = [rule['const']] if 'const' in rule else rule['enum']
    else:
        domains = {
            r'^[^\x00-\x1f\x7f]+$': (1, None, 1, lambda n: 'x' * n),
            r'^[a-z][a-z0-9_.-]*$': (1, None, 1, lambda n: 'a' * n),
            r'^[0-9a-f]{64}$': (64, 64, 1, lambda n: '0' * n),
            r'^([0-9a-f]{2}){1,20}$': (2, 40, 2, lambda n: '0' * n),
            r'^[A-Za-z0-9_.:-]+$': (1, None, 1, lambda n: 'a' * n),
            r'^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$':
                (3, None, 1, lambda n: 'a.' + 'b' * (n - 2)),
            r'^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$':
                (5, None, 1, lambda n: '1.2.' + '3' * (n - 4)),
        }
        patterns = [rule['pattern']] if 'pattern' in rule else []
        patterns += [node['pattern'] for node in rule.get('allOf', []) if 'pattern' in node]
        low = max(1, rule.get('minLength', 1))
        high = min(rule.get('maxLength', 256), rule.get('x-maxBytes', 256))
        candidates = []
        for pattern in patterns:
            domain_low, domain_high, step, build = domains[pattern]
            first = max(low, domain_low)
            first += (domain_low - first) % step
            last = min(high, domain_high if domain_high is not None else high)
            last -= (last - domain_low) % step
            if first <= last:
                candidates += [build(first), build(last)]
    check = Draft202012Validator(rule)
    accepted = [v for v in candidates if isinstance(v, str) and check.is_valid(v)
                and len(v.encode('utf-8')) <= rule.get('x-maxBytes', 2**63)]
    if not accepted:
        return []
    lengths = {min(map(len, accepted)), max(map(len, accepted))}
    return [v for v in accepted if len(v) in lengths]


class TestNativeCompatibility(TestCompilation):
    @staticmethod
    def reviewer_mutations():
        return {
            'A-08': lambda p: p['objects']['os']['properties']['type_id'].update(const=123),
            'A-09': lambda p: p['classes'][0]['schema']['properties']['processes'].update(
                allOf=[{'if': {}, 'then': {'const': 'wrong'}}]),
            'A-10': lambda p: p['classes'][0]['schema']['allOf'].append({
                'properties': {'unmapped': {'properties': {
                    'entries': {'items': {'type': 'string'}}}}}}),
        }

    def test_reviewer_native_compatibility_inputs(self):
        original = (self.root / 'profile.json').read_bytes()
        for name, mutate in self.reviewer_mutations().items():
            with self.subTest(finding=name):
                try:
                    p = json.loads(original)
                    mutate(p)
                    (self.root / 'profile.json').write_text(json.dumps(p))
                    with self.assertRaisesRegex(ValueError,
                            r'^binding\.(enum|literal_type|object_reference)$'):
                        self.g.compile_profile(self.root)
                finally:
                    (self.root / 'profile.json').write_bytes(original)

    def test_native_literals_at_every_composition_depth(self):
        original = (self.root / 'profile.json').read_bytes()
        for keyword in ('allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else'):
            for literal in ({'const': 'wrong'}, {'enum': ['wrong']},
                            {'const': [{'name': 'wrong'}]}):
                with self.subTest(keyword=keyword, literal=literal):
                    p = json.loads(original)
                    child = {'if': {}, 'then': literal}
                    node = p['classes'][0]['schema']['properties']['processes']
                    node[keyword] = [child] if keyword in ('allOf', 'anyOf', 'oneOf') else child
                    (self.root / 'profile.json').write_text(json.dumps(p))
                    try:
                        with self.assertRaisesRegex(ValueError, '^binding.literal_type$'):
                            self.g.compile_profile(self.root)
                    finally:
                        (self.root / 'profile.json').write_bytes(original)
        p = json.loads(original)
        p['objects']['os']['allOf'].append({'if': {}, 'then': {
            'properties': {'type_id': {'enum': [100], 'const': 123}}}})
        (self.root / 'profile.json').write_text(json.dumps(p))
        try:
            with self.assertRaisesRegex(ValueError, '^binding.enum$'):
                self.g.compile_profile(self.root)
        finally:
            (self.root / 'profile.json').write_bytes(original)

    def assert_native_property(self, root):
        """Compare each emitted position with native types and reviewed catalogue rules.

        The oracle does not call _bind, primitive or integer_bounds. Catalogue
        constraints come from an independent literal allowlist, never the input profile.
        Fragments are evaluated with their selected data field, because an untyped
        JSON Schema fragment alone deliberately accepts unrelated JSON types.
        """
        from jsonschema import Draft202012Validator, validators

        def byte_limit(validator, cap, value, schema):
            from jsonschema.exceptions import ValidationError
            if isinstance(value, str) and len(value.encode('utf-8')) > cap:
                yield ValidationError('byte limit')
        Validator = validators.extend(Draft202012Validator, {'x-maxBytes': byte_limit})
        outputs = self.g.compile_profile(root)
        source_profile = json.loads((root / 'profile.json').read_bytes())

        def restrictions(value):
            if isinstance(value, dict):
                return {k: restrictions(v) for k, v in value.items()
                        if k not in ('x-source', 'title', 'description')}
            if isinstance(value, list):
                return [restrictions(v) for v in value]
            return value

        catalogue = {'objects': {}, 'classes': []}
        for name, source in source_profile['objects'].items():
            rule = CATALOGUE_RULES.get('object/' + name)
            self.assertEqual(restrictions(source), rule,
                             'unlisted catalogue restriction: object/' + name)
            catalogue['objects'][name] = dict(rule, **{'x-source': source['x-source']})
        for entry in source_profile['classes']:
            name = 'class/' + str(entry['class_uid'])
            rule = CATALOGUE_RULES.get(name)
            self.assertEqual(restrictions(entry['schema']), rule,
                             'unlisted catalogue restriction: ' + name)
            catalogue['classes'].append(dict(entry, schema=dict(
                rule, **{'x-source': entry['schema']['x-source']})))
        resolver = self.g.SourceResolver(root)
        objects = catalogue['objects']
        native_defs = {}

        def attribute_schema(attribute, selected, item=False):
            if attribute.get('is_array') and not item:
                return {'type': 'array', 'items': attribute_schema(
                    attribute, selected.get('items', {}), True)}
            name = attribute['type']
            chain = []
            while name in resolver.dictionary['types']['attributes']:
                definition = resolver.dictionary['types']['attributes'][name]
                chain.append((name, definition))
                if 'type' not in definition:
                    break
                name = definition['type']
            primitives = {'string_t': 'string', 'integer_t': 'integer',
                          'long_t': 'integer', 'float_t': 'number',
                          'boolean_t': 'boolean', 'object': 'object'}
            typ = primitives.get(name, 'object')
            node = {'type': typ}
            if typ == 'object':
                if '$ref' in selected:
                    return {'$ref': selected['$ref']}
                if name != 'object':
                    return {'$ref': '#/$defs/' + name}
            ranges = [d['range'] for _, d in chain if 'range' in d]
            if any(n == 'long_t' for n, _ in chain):
                ranges.append([-2**63, 2**63 - 1])
            if ranges:
                node.update(minimum=max(r[0] for r in ranges),
                            maximum=min(r[1] for r in ranges))
            # The reviewed x-restriction explicitly changes these native counters
            # to unsigned. Keep that authorization out of the mutated profile.
            if selected.get('x-restriction') and selected.get('x-integer') == 'uint64':
                node.update(minimum=0, maximum=2**64 - 1)
            if attribute.get('enum'):
                node['enum'] = [int(v) for v in attribute['enum']]
            return node

        def object_schema(native, selected):
            properties = {k: attribute_schema(native['attributes'][k], v)
                          for k, v in selected.get('properties', {}).items()}
            node = {'type': 'object', 'properties': properties,
                    'required': sorted(native['required_attributes'])}
            if native['groups']:
                node['allOf'] = [{'anyOf': [{'required': [k]} for k in group]}
                                 for group in native['groups']]
            return node

        for name, selected in objects.items():
            native_defs[name] = object_schema(
                resolver.resolve(selected['x-source'].split('#')[0]), selected)

        # Literal fixture subtrees supply valid object seeds for conditional
        # branches, independently of schema validation and sample construction.
        seeds = []
        for path in sorted((ROOT / 'fixtures').rglob('*.json')):
            def collect(value):
                if isinstance(value, dict):
                    seeds.append(value)
                    for child in value.values():
                        collect(child)
                elif isinstance(value, list):
                    seeds.append(value)
                    for child in value:
                        collect(child)
            fixture = json.loads(path.read_bytes())
            if isinstance(fixture, dict):
                for event in fixture.get('events', []):
                    collect(json.loads(event['event_json']))
                collect(fixture)

        def deref(node, defs):
            return defs[node['$ref'][8:]] if '$ref' in node else node

        validator_cache = {}
        definition_keys = {}
        expanded_references = {}

        def expand(node, defs):
            if '$ref' in node:
                key = (id(defs), node['$ref'])
                if key not in expanded_references:
                    expanded_references[key] = expand(defs[node['$ref'][8:]], defs)
                return expanded_references[key]
            result = {k: v for k, v in node.items()
                      if k not in ('$defs', '$id', '$schema')}
            if 'properties' in result:
                result['properties'] = {k: expand(v, defs)
                                        for k, v in result['properties'].items()}
            for key in ('items', 'not', 'if', 'then', 'else'):
                if key in result:
                    result[key] = expand(result[key], defs)
            for key in ('allOf', 'anyOf', 'oneOf'):
                if key in result:
                    result[key] = [expand(v, defs) for v in result[key]]
            return result

        class CachedValidator:
            def __init__(self, node):
                self.validator = Validator(node)
                self.results = {}

            def is_valid(self, value):
                key = id(value)
                if key not in self.results:
                    self.results[key] = (value, self.validator.is_valid(value))
                return self.results[key][1]

        def validator(node, defs):
            definition_keys[id(defs)] = defs
            # Inline the already checked acyclic local references once.
            expanded = expand(node, defs)
            key = json.dumps(expanded, sort_keys=True)
            if key not in validator_cache:
                validator_cache[key] = CachedValidator(expanded)
            return validator_cache[key]

        sample_cache = {}

        def samples(native, rules):
            native = deref(native, native_defs)
            rules = deref(rules, objects)
            cache_key = (id(native), id(rules))
            if cache_key in sample_cache:
                return sample_cache[cache_key][2]
            values = [None, False, True, -1, 0, 1, 0.5, '', 'x', [], {}]
            values += native.get('enum', []) + rules.get('enum', [])
            if 'const' in rules:
                values.append(rules['const'])
            for node in (native, rules):
                for key in ('minimum', 'maximum'):
                    if key in node:
                        bound = node[key]
                        values += [bound - 1, bound, bound + 1]
            typ = native.get('type')
            if typ == 'string':
                values += ['0102']
                for key in ('minLength', 'maxLength', 'x-maxBytes'):
                    bound = rules.get(key, 1)
                    for size in {max(0, bound - 1), bound, bound + 1}:
                        # Pattern-valid candidates exercise each permitted length boundary.
                        # Unsupported formats fail the positive-witness assertion.
                        values += ['x' * size, 'é' * size, '0' * size,
                                   'a.b' + 'a' * max(0, size - 3),
                                   '1.2.' + '3' * max(0, size - 4)]
                values += catalogue_string_boundaries(rules)
                values += ['\x00', 'host', 'a' * 64,
                           '018f1f4a-7b00-7000-8000-000000000001']
            if typ == 'array':
                child_rules = rules.get('items', {})
                child_values = samples(native['items'], child_rules)
                values += [[v] for v in child_values]
                accepted = next((v for v in child_values
                                 if validator(child_rules, objects).is_valid(v)
                                 and validator(native['items'], native_defs).is_valid(v)), '')
                for key in ('minItems', 'maxItems'):
                    bound = rules.get(key, 1)
                    values += [[accepted] * size for size in
                               {max(0, bound - 1), bound, bound + 1}]
            if typ == 'object':
                baseline = {}
                branches = []
                for key, child in native.get('properties', {}).items():
                    child_rules = rules.get('properties', {}).get(key, {})
                    candidates = samples(child, child_rules)
                    valid = next((v for v in candidates
                                  if validator(child_rules, objects).is_valid(v)
                                  and validator(child, native_defs).is_valid(v)), None)
                    if valid is not None:
                        baseline[key] = valid
                    # Scalar boundaries are checked at the child position.
                    # Probe object presence and type here without a Cartesian product.
                    branches += [(key, valid), (key, None)]
                values += [baseline, {k: v for k, v in baseline.items()
                                      if k in native.get('required', [])}]
                values += [dict(baseline, **{k: v}) for k, v in branches]
                matching = [v for v in seeds if isinstance(v, dict)
                            and set(v) <= set(native.get('properties', {}))]
                unique = {json.dumps(v, sort_keys=True): v for v in matching}
                values += list(unique.values())
            sample_cache[cache_key] = (native, rules, values)
            return values

        positions = 0
        probes = 0
        for entry in catalogue['classes']:
            compiled = json.loads(outputs[f"compiled/{entry['class_uid']}.schema.json"])
            defs = compiled['$defs']
            native_root = object_schema(resolver.resolve(
                entry['schema']['x-source'].split('#')[0]), entry['schema'])

            def walk(node, rules, native, base, rule_base, path, fragment=False):
                nonlocal positions, probes
                positions += 1
                selected = deref(base, defs)
                reviewed = deref(rule_base, objects)
                native_node = deref(native, native_defs)
                for key, child in node.get('properties', {}).items():
                    walk(child, rules.get('properties', {}).get(key, {}),
                         native_node['properties'][key],
                         selected.get('properties', {}).get(key, child),
                         reviewed.get('properties', {}).get(key, {}),
                         path + '/properties/' + key, fragment)
                if 'items' in node:
                    walk(node['items'], rules.get('items', {}), native_node['items'],
                         selected.get('items', node['items']), reviewed.get('items', {}),
                         path + '/items', fragment)
                for key in ('not', 'if', 'then', 'else'):
                    if key in node:
                        walk(node[key], rules.get(key, {}), native, base, rule_base,
                             path + '/' + key, True)
                for key in ('allOf', 'anyOf', 'oneOf'):
                    for index, child in enumerate(node.get(key, [])):
                        rule_children = rules.get(key, [])
                        child_rule = rule_children[index] if index < len(rule_children) else {}
                        walk(child, child_rule, native, base, rule_base,
                             f'{path}/{key}/{index}', True)
                # Check children first so scalar boundary failures name the
                # field instead of a containing event or object seed.
                actual = {'allOf': [base, node]} if fragment else node
                allowed = {'allOf': [rule_base, rules]} if fragment else rules
                actual_validator = validator(actual, defs)
                allowed_validator = validator(allowed, objects)
                native_validator = validator(native, native_defs)
                positive = 0
                branch_validator = validator(rules, objects)
                candidates = samples(native, rule_base)
                if fragment:
                    candidates = candidates + samples(native, rules)
                for value in candidates:
                    probes += 1
                    native_accepts = native_validator.is_valid(value)
                    compiled_accepts = actual_validator.is_valid(value)
                    narrowed_accepts = allowed_validator.is_valid(value)
                    # A not operand can be intentionally disjoint from its
                    # enclosing field (for example the excluded CPU value zero).
                    # Witness operands in their native domain; compare narrowing
                    # in the enclosing selected field as before.
                    witness_accepts = (branch_validator.is_valid(value)
                                       if fragment else narrowed_accepts)
                    if native_accepts and witness_accepts:
                        positive += 1
                    message = f"{entry['class_uid']} {path}: {repr(value)[:160]}"

                    self.assertFalse(compiled_accepts and not native_accepts,
                                     'native widening: ' + message)
                    self.assertFalse(native_accepts and narrowed_accepts
                                     and not compiled_accepts,
                                     'undocumented narrowing: ' + message)
                self.assertGreater(positive, 0,
                                   f"no positive witness: {entry['class_uid']} {path}")

            walk(compiled, entry['schema'], native_root, compiled, entry['schema'], '')
            for name, node in defs.items():
                walk(node, objects[name], native_defs[name], node, objects[name],
                     '/$defs/' + name)
            # Probes demonstrate acceptance differences. Exact rule comparison
            # also rejects restrictions whose rejected values lie between probes.
            emitted_root = {k: v for k, v in compiled.items()
                            if k not in ('$id', '$schema', '$defs')}
            self.assertEqual(restrictions(emitted_root),
                             CATALOGUE_RULES['class/' + str(entry['class_uid'])],
                             'unlisted compiled restriction: class/' + str(entry['class_uid']))
            self.assertEqual(set(defs), set(objects),
                             'unlisted compiled restriction: definitions')
            for name, node in defs.items():
                self.assertEqual(restrictions(node), CATALOGUE_RULES['object/' + name],
                                 'unlisted compiled restriction: object/' + name)
        self.assertGreater(positions, 1000)
        self.assertGreater(probes, positions * 10)
        self.property_counts = positions, probes

    def test_pattern_valid_length_boundaries(self):
        probe_builder = globals().get('catalogue_string_boundaries')
        self.assertTrue(callable(probe_builder), 'pattern boundary builder is absent')
        cases = [
            ('certificate', 'serial_number', {2, 40}),
            ('product', 'version', {5, 64}),
            ('extension_origin', 'id', {3, 253}),
            ('fingerprint', 'value', {64}),
            ('os', 'cpu_architecture', {3, 5}),
        ]
        for obj, field, lengths in cases:
            with self.subTest(object=obj, field=field):
                rule = CATALOGUE_RULES['object/' + obj]['properties'][field]
                from jsonschema import Draft202012Validator
                probes = probe_builder(rule)
                self.assertEqual({len(v) for v in probes}, lengths)
                self.assertTrue(all(Draft202012Validator(rule).is_valid(v) for v in probes))
        serial = dict(CATALOGUE_RULES['object/certificate']['properties']['serial_number'],
                      minLength=3, maxLength=39)
        self.assertEqual({len(v) for v in probe_builder(serial)}, {4, 38})

    def test_serial_boundary_reviewer_input(self):
        original_compile = self.g.compile_profile

        def narrowed(root):
            outputs = original_compile(root)
            for name, data in list(outputs.items()):
                if name.startswith('compiled/') and name.endswith('.schema.json'):
                    schema = json.loads(data)
                    schema['$defs']['certificate']['properties']['serial_number']['maxLength'] = 2
                    outputs[name] = json.dumps(schema).encode()
            return outputs

        self.g.compile_profile = narrowed
        with self.assertRaisesRegex(AssertionError, "undocumented narrowing.*serial_number.*: '0102'"):
            self.assert_native_property(self.root)

    def test_unlisted_compiled_restriction_between_probes(self):
        original_compile = self.g.compile_profile

        def narrowed(root):
            outputs = original_compile(root)
            for name, data in list(outputs.items()):
                if name.startswith('compiled/') and name.endswith('.schema.json'):
                    schema = json.loads(data)
                    schema['$defs']['certificate']['properties']['serial_number']['allOf'].append(
                        {'pattern': '^[^b]*$'})
                    outputs[name] = json.dumps(schema).encode()
            return outputs

        self.g.compile_profile = narrowed
        with self.assertRaisesRegex(AssertionError, 'unlisted compiled restriction'):
            self.assert_native_property(self.root)

    def test_unlisted_catalogue_reviewer_inputs(self):
        original = (self.root / 'profile.json').read_bytes()
        mutations = {
            'count const zero': lambda p: p['objects']['event_rate']['properties']['count'].update(const=0),
            'reject every event': lambda p: [entry['schema']['allOf'].append({'not': {}})
                                           for entry in p['classes']],
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                try:
                    profile = json.loads(original)
                    mutate(profile)
                    (self.root / 'profile.json').write_text(json.dumps(profile))
                    with patch.dict(self.assert_native_property.__globals__, ROOT=self.root):
                        with self.assertRaisesRegex(AssertionError, 'unlisted catalogue restriction'):
                            self.assert_native_property(self.root)
                finally:
                    (self.root / 'profile.json').write_bytes(original)

    def test_differential_native_contract(self):
        self.assert_native_property(self.root)

    def test_differential_reviewer_profiles(self):
        original = (self.root / 'profile.json').read_bytes()
        for name, mutate in self.reviewer_mutations().items():
            with self.subTest(finding=name):
                try:
                    profile = json.loads(original)
                    mutate(profile)
                    (self.root / 'profile.json').write_text(json.dumps(profile))
                    with self.assertRaises((ValueError, AssertionError)):
                        self.assert_native_property(self.root)
                finally:
                    (self.root / 'profile.json').write_bytes(original)


if __name__ == '__main__':
    unittest.main()


class TestTruncationSchema(unittest.TestCase):
    def test_compiled_presence_restrictions(self):
        from jsonschema import Draft202012Validator
        spec = importlib.util.spec_from_file_location('ocsf_generate', ROOT / 'generate.py')
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        outputs = generator.compile_profile(ROOT)
        fixtures = json.loads((ROOT / 'fixtures/events.json').read_text())
        for f in fixtures['events']:
            if not f['name'].startswith('regression-truncation-'):
                continue
            with self.subTest(name=f['name']):
                event = json.loads(f['event_json'])
                schema = json.loads(outputs['compiled/' + str(event['class_uid']) + '.schema.json'])
                self.assertEqual(Draft202012Validator(schema).is_valid(event), f['expected_error'] is None)
