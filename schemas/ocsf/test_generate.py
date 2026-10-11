"""Offline source-pin tests; profile compilation awaits its source-binding gate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
