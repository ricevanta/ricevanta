"""Independent fixture and boundary expectations for emitted OCSF events."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


class ValidationCase(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'validate.py').is_file(), 'decoded validation interface is absent')
        spec = importlib.util.spec_from_file_location('ocsf_validate', ROOT / 'validate.py')
        self.v = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.v)

    def example(self, name):
        return self.v.load_event((ROOT / 'examples' / (name+'.json')).read_text())

    def check(self, e, want=None, source='agent'):
        self.assertEqual(self.v.validate_event(e, source), want)


class TestExamples(ValidationCase):
    def test_examples(self):
        for name in ['health','policy','pipeline','certificate']:
            with self.subTest(name=name):
                self.check(self.example(name), source='server' if name=='certificate' else 'agent')

    def test_shared_vectors(self):
        for f in self.v.load_fixtures(ROOT / 'examples/vectors.json')['events']:
            with self.subTest(name=f['name']):
                self.check(self.v.load_event(f['event_json']), f['expected_error'], f['source'])


class TestEveryActivity(ValidationCase):
    def test_emitted_fixtures(self):
        cases = self.v.load_fixtures()['events']
        for f in cases:
            with self.subTest(name=f['name']):
                self.check(self.v.load_event(f['event_json']), f['expected_error'], f['source'])
        activities = {(int(self.v.load_event(f['event_json'])['class_uid'].text),int(self.v.load_event(f['event_json'])['activity_id'].text)) for f in cases if f['expected_error'] is None}
        self.assertEqual(len(activities),22)


class TestPlatformCoverage(ValidationCase):
    def test_present_measurement_cannot_be_covered(self):
        e=self.example('health');e['processes'][0]['cpu_pct']=self.v.Number('0')
        self.check(e,'ErrConstraint')

    def test_wrong_platform_descriptor(self):
        e=self.example('health');e['processes'][0]['handle_count']=self.v.Number('0')
        self.check(e,'ErrConstraint')


class TestNumericTokens(ValidationCase):
    def test_uint64_and_lexical(self):
        for token,want in [('18446744073709551614',None),('18446744073709551615',None),('18446744073709551616','ErrShape'),('1.0','ErrShape'),('1e0','ErrShape'),('-0','ErrShape')]:
            e=self.example('policy');e['metadata']['sequence']=self.v.Number(token);self.check(e,want)

    def test_number_budget(self):
        for n,want in [(63,'ErrShape'),(64,'ErrShape'),(65,'ErrBudget')]:
            for version in ['1.9.0','2.0.0']:
                e=self.example('policy');e['metadata']['sequence']=self.v.Number('1'+'0'*(n-1));e['metadata']['version']=version
                self.check(e,'ErrVersion' if version!='1.9.0' and n<=64 else want)


class TestByteLimits(ValidationCase):
    def test_message_bytes(self):
        for n,want in [(1023,None),(1024,None),(1025,'ErrShape')]:
            e=self.example('policy');e['message']='a'*n;self.check(e,want)
        e=self.example('policy');e['message']='é'*513;self.check(e,'ErrShape')

    def test_global_string(self):
        for n,want in [(32767,'ErrShape'),(32768,'ErrShape'),(32769,'ErrBudget')]:
            e=self.example('policy');e['message']='a'*n;self.check(e,want)


class TestCrossFieldRules(ValidationCase):
    def test_type_uid(self):
        e=self.example('pipeline');e['type_uid']=self.v.Number('9990100302');self.check(e,'ErrConstraint')

    def test_parser(self):
        for raw in ['{"a":1,"a":2}','{"a":"\\ud800"}','{"a":NaN}','{"a":01}','{} {}']:
            with self.assertRaises(ValueError):self.v.load_event(raw)


class TestPrecedence(ValidationCase):
    def test_source_then_preflight(self):
        e={};e['self']=e;self.check(e,'ErrSource','invalid');self.check(e,'ErrBudget')

    def test_version_then_class(self):
        e=self.example('policy');e['metadata']['version']='2.0.0';e['class_uid']=self.v.Number('1');self.check(e,'ErrVersion')
        e['metadata']['version']='1.9.0';e['unknown']=None;self.check(e,'ErrClass')


class TestNoNetwork(ValidationCase):
    def test_external_resolver_rejected(self):
        with patch('socket.socket',side_effect=AssertionError('network access')):
            self.check(self.example('policy'))
            with self.assertRaises(ValueError):self.v.no_retrieve('https://example.com/schema')

class TestResourceBoundaries(ValidationCase):
    def test_exact_node_budget_with_keys(self):
        # Root + 16 arrays + 16,367 scalar visits = exactly 16,384 nodes.
        e={str(i):[None]*(1024 if i<15 else 1007) for i in range(16)}
        self.check(e,'ErrShape')
        e['15'].append(None);self.check(e,'ErrBudget')

    def test_list_bounds(self):
        for n,want in [(31,None),(32,None),(33,'ErrShape')]:
            e=self.example('policy');e['device']['labels']=['tag']*n;self.check(e,want)
        for n,want in [(63,None),(64,None),(65,'ErrShape')]:
            e=self.example('policy');e['device']['groups']=[{'name':'group'}]*n;self.check(e,want)

    def test_percent_boundaries(self):
        for tok,want in [('0',None),('0.000001',None),('99.999999',None),('100',None),('100.000001','ErrShape'),('0.0000001','ErrShape'),('1e0','ErrShape')]:
            e=self.example('health');e['processes'][0]['cpu_pct']=self.v.Number(tok)
            e['metadata']['coverage']=[x for x in e['metadata']['coverage'] if x['path']!='/processes/0/cpu_pct']
            self.check(e,want)

class TestFixtureLoading(ValidationCase):
    def test_event_text_budget_is_separate_from_source_budget(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events.json'
            raw='"'+'a'*(2097152-3)+'"'
            f={'format':1,'events':[dict(name='large',source='agent',event_json=raw,expected_error='ErrBudget')],'parser':[]}
            path.write_text(json.dumps(f))
            self.assertEqual(len(self.v.load_fixtures(path)['events']),1)

    def test_event_text_byte_cap(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events.json'
            raw='"'+'é'*(1048576)+'"'
            f={'format':1,'events':[dict(name='large',source='agent',event_json=raw,expected_error='ErrBudget')],'parser':[]}
            path.write_text(json.dumps(f,ensure_ascii=False))
            with self.assertRaises(ValueError):self.v.load_fixtures(path)

class TestOrderedKeys(ValidationCase):
    def test_key_does_not_count_as_node(self):
        e=[[None]*1024 for _ in range(15)]+[[None]*1006+[{'\ud800':None}]]
        self.check(e,'ErrDecoded')
