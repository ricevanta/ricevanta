#!/usr/bin/env python3
"""Offline emitted-event checks. Acceptance supplies no identity or authority."""
import json
from fractions import Fraction
from pathlib import Path
import re
from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
import generate

ROOT = Path(__file__).resolve().parent
JSON_NUMBER = re.compile(r'-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?\Z')
INTEGER = re.compile(r'(0|-?[1-9][0-9]*)\Z')
UNSIGNED = re.compile(r'(0|[1-9][0-9]*)\Z')
DECIMAL = re.compile(r'(0|[1-9][0-9]*)(\.[0-9]{1,6})?\Z')
UUID7 = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')


class Number:
    """Keep spelling without converting an exponent or a large integer to float."""
    def __init__(self, text):
        self.text = text

    def rational(self):
        if len(self.text) > 64 or DECIMAL.fullmatch(self.text) is None and INTEGER.fullmatch(self.text) is None:
            raise ValueError('number.lexical')
        return Fraction(self.text)

    def __eq__(self, other):
        if isinstance(other, Number):
            other = other.rational()
        if type(other) not in (int, Fraction):
            return False
        try:
            return self.rational() == other
        except ValueError:
            return False

    def __lt__(self, other):
        return self.rational() < other

    def __gt__(self, other):
        return self.rational() > other

    def __int__(self):
        return int(self.text)


def load_event(text: str) -> object:
    """Reject duplicate keys and invalid source/decoded Unicode before validation."""
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError('parse.invalid')
            result[k] = v
        return result
    def constant(_):
        raise ValueError('parse.invalid')
    try:
        text.encode('utf-8')
        value = json.loads(text, object_pairs_hook=pairs, parse_int=Number, parse_float=Number, parse_constant=constant)
        stack = [value]
        while stack:
            v = stack.pop()
            if type(v) is str:
                v.encode('utf-8')
            elif type(v) is dict:
                stack.extend(v.keys())
                stack.extend(v.values())
            elif type(v) is list:
                stack.extend(v)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('parse.invalid') from None


def preflight(root):
    stack, nodes, remaining = [(root, 0)], 0, 1048576
    while stack:
        v, depth = stack.pop()
        if type(v) is _Key:
            try:
                v.text.encode('utf-8')
            except UnicodeError:
                return 'ErrDecoded'
            continue
        nodes += 1
        if nodes > 16384:
            return 'ErrBudget'
        typ = type(v)
        size = 0
        if typ in (dict, list):
            depth += 1
            if depth > 32 or len(v) > (128 if typ is dict else 1024):
                return 'ErrBudget'
            size = 2
            if typ is dict:
                for k in v:
                    if type(k) is not str:
                        return 'ErrDecoded'
                    n = len(k.encode('utf-8', errors='surrogatepass'))
                    if n > 32768:
                        return 'ErrBudget'
                    size += n
                    if size > remaining:
                        return 'ErrBudget'
                for k in sorted(v, reverse=True):
                    # Check keys in the same ordered traversal as Go, without counting a key as a node.
                    stack.append((v[k], depth))
                    stack.append((_Key(k), depth))
            else:
                stack.extend((x, depth) for x in reversed(v))
        elif typ is str:
            size = len(v.encode('utf-8', errors='surrogatepass'))
            if size > 32768 or size > remaining:
                return 'ErrBudget'
            try:
                v.encode('utf-8')
            except UnicodeError:
                return 'ErrDecoded'
        elif typ is Number:
            size = len(v.text)
            if size > 64 or size > remaining:
                return 'ErrBudget'
            if JSON_NUMBER.fullmatch(v.text) is None:
                return 'ErrDecoded'
        elif typ is bool or v is None:
            size = 1
        else:
            return 'ErrDecoded'
        if size > remaining:
            return 'ErrBudget'
        remaining -= size
    return None


class _Key:
    def __init__(self, text):
        self.text = text


def no_retrieve(_):
    raise ValueError('schema.external_reference')


def registry_for(schemas):
    registry = Registry(retrieve=no_retrieve)
    for s in schemas:
        Draft202012Validator.check_schema(s)
        registry = registry.with_resource(s['$id'], Resource.from_contents(s))
    return registry


def _number(_, v):
    return type(v) is Number and (DECIMAL.fullmatch(v.text) is not None or INTEGER.fullmatch(v.text) is not None)


def _integer(_, v):
    return type(v) is Number and INTEGER.fullmatch(v.text) is not None


def _bytes(validator, cap, value, schema):
    if type(value) is str and len(value.encode('utf-8')) > cap:
        yield ValidationError('schema.bytes')


def _width(validator, width, value, schema):
    if type(value) is Number:
        pattern = UNSIGNED if width == 'uint64' else INTEGER
        if pattern.fullmatch(value.text) is None:
            yield ValidationError('schema.integer')
        else:
            n = int(value.text)
            if not (0 <= n <= 18446744073709551615 if width == 'uint64' else -9223372036854775808 <= n <= 9223372036854775807):
                yield ValidationError('schema.integer')


def _type(validator, kinds, value, schema):
    yield from Draft202012Validator.VALIDATORS['type'](validator, kinds, value, schema)
    if kinds == 'number' and type(value) is Number and DECIMAL.fullmatch(value.text) is None:
        yield ValidationError('schema.number')


def validator_for(schema, source):
    def source_kind(validator, kind, value, node):
        if kind != source:
            yield ValidationError('schema.source')
    checker = Draft202012Validator.TYPE_CHECKER.redefine('number', _number).redefine('integer', _integer)
    cls = validators.extend(Draft202012Validator, {'type': _type, 'x-maxBytes': _bytes, 'x-integer': _width, 'x-sourceKind': source_kind}, type_checker=checker)
    return cls(schema, registry=REGISTRY)


SCHEMAS = {}
for path in sorted((ROOT / 'compiled').glob('*.schema.json')):
    s = generate._json(generate._read(path))
    generate.check_schema(s)
    SCHEMAS[int(path.name.split('.')[0])] = s
REGISTRY = registry_for(list(SCHEMAS.values()))
VALIDATORS = {(cid, source): validator_for(s, source) for cid, s in SCHEMAS.items() for source in ('agent', 'server')}


def _unique(items, key):
    values = [x[key] for x in items]
    return len(values) == len(set(values))


def type_uid(e, source):
    if int(e['type_uid']) != int(e['class_uid']) * 100 + int(e['activity_id']):
        return False
    m = e['metadata']
    ids = [m['uid'], m['correlation_uid']]
    ids += [e[k] for k in ('quarantine_uid', 'event_uid', 'request_uid') if k in e]
    return all(UUID7.fullmatch(v) for v in ids)


def bundle_state(e, source):
    m = e['metadata']
    installed = m.get('bundle_state') == 'installed'
    if source == 'agent' and installed != ('policy_bundle' in m):
        return False
    origin = m.get('extension_origin')
    return not origin or source == 'server' or installed and origin['recovery_epoch'] == m['policy_bundle']['recovery_epoch']


def coverage(e, source):
    sampler = {'sensor_unavailable', 'permission_denied', 'collection_failed'}
    expected = {}
    def absent(parent, field, path, reasons):
        if field not in parent:
            expected[path] = reasons
    osid = int(e['device']['os']['type_id'])
    for i, p in enumerate(e['processes']):
        for k in ('cpu_pct', 'footprint_bytes', 'handle_count' if osid == 100 else 'fd_count'):
            absent(p, k, '/processes/'+str(i)+'/'+k, sampler)
    for i, b in enumerate(e['budgets']):
        for k in ('memory_bytes', 'cpu_pct'):
            absent(b, k, '/budgets/'+str(i)+'/'+k, sampler)
    for i, s in enumerate(e['spools']):
        if int(s['bytes']) == 0 and 'oldest_unsent_ms' in s:
            return False
        absent(s, 'oldest_unsent_ms', '/spools/'+str(i)+'/oldest_unsent_ms', {'not_applicable'} if int(s['bytes']) == 0 else sampler)
        absent(s, 'last_ack_sequence', '/spools/'+str(i)+'/last_ack_sequence', sampler | {'not_observed'})
    absent(e, 'kernel_bytes', '/kernel_bytes', sampler | {'not_applicable', 'privacy_filtered'})
    actual = e['metadata'].get('coverage', [])
    return len(actual) == len(expected) and len({x['path'] for x in actual}) == len(actual) and all(x['path'] in expected and x['reason'] in expected[x['path']] for x in actual)


def sequence_range(e, source):
    if 'sequence_range' not in e:
        return True
    r = e['sequence_range'];first, last = int(r['first']), int(r['last'])
    return first <= last and last-first < 18446744073709551615 and int(e['count']) == last-first+1


def health_identity(e, source):
    osid = int(e['device']['os']['type_id'])
    metric = {100:'private_working_set',200:'pss',300:'phys_footprint'}[osid]
    forbidden = 'fd_count' if osid == 100 else 'handle_count'
    return _unique(e['processes'], 'uid') and _unique(e['budgets'], 'unit') and _unique(e['spools'], 'spool_class') and all(p['footprint_metric'] == metric and forbidden not in p and _unique(p['event_rates'],'source') for p in e['processes'])


def pipeline_activity(e, source):
    a = int(e['activity_id'])
    if a == 3:
        return int(e['count']) == 1
    if a == 4:
        return e['reason'] in {'healthy':['recovered'],'degraded':['retrying','dead_letter'],'failed':['paused','retrying'],'lagging':['lag']}[e['destination_state']]
    return True


def policy_activity(e, source):
    if int(e['activity_id']) != 7:
        return True
    m = e['metadata']
    return source == 'agent' and m.get('bundle_state') == 'installed' and e['candidate_bundle_uid'] == m['policy_bundle']['bundle_uid']


def certificate_activity(e, source):
    c = e['certificate']
    return int(c['created_time']) < int(c['expiration_time']) and (int(e['activity_id']) != 2 or e['prior_certificate_uid'] != c['uid'])


def compact(v):
    """Encode only bounded schema-admitted diagnostic data, preserving numbers."""
    if type(v) is Number:
        return v.text
    if type(v) is dict:
        return '{'+','.join(json.dumps(k,ensure_ascii=True)+':'+compact(v[k]) for k in sorted(v))+'}'
    if type(v) is list:
        return '['+','.join(compact(x) for x in v)+']'
    return json.dumps(v, ensure_ascii=True, separators=(',',':'))


def unmapped(e, source):
    u = e.get('unmapped')
    if u is None:
        return True
    pairs = [(x['field'], int(x['index'])) for x in u['entries']]
    return len(set(pairs)) == len(pairs) and len(compact(u)) <= 32768


def truncation(e, source):
    m = e['metadata'];keys = ['is_truncated', 'untruncated_size', 'truncation']
    present = sum(k in m for k in keys)
    if present == 0:
        return True
    if present != 3:
        return False
    t = m['truncation'];original, unmapped_bytes = int(t['original_event_bytes']), int(t['original_unmapped_bytes'])
    return unmapped_bytes > 32768 and original >= unmapped_bytes and int(m['untruncated_size']) == (original+999)//1000


SEMANTICS = {name: globals()[name] for name in generate.RULES}


def validate_event(event: object, source: str) -> str | None:
    if source not in ('agent', 'server'):
        return 'ErrSource'
    error = preflight(event)
    if error:
        return error
    if type(event) is not dict or type(event.get('metadata')) is not dict or type(event['metadata'].get('version')) is not str or type(event.get('class_uid')) is not Number:
        return 'ErrShape'
    if event['metadata']['version'] != '1.9.0':
        return 'ErrVersion'
    token = event['class_uid'].text
    if UNSIGNED.fullmatch(token) is None or int(token) > 18446744073709551615:
        return 'ErrShape'
    cid = int(token)
    if cid not in SCHEMAS:
        return 'ErrClass'
    if not VALIDATORS[cid, source].is_valid(event):
        return 'ErrShape'
    for rule in SCHEMAS[cid]['x-rule']:
        if not SEMANTICS[rule](event, source):
            return 'ErrConstraint'
    return None


def load_fixtures(path=None):
    path = path or ROOT / 'fixtures/events.json'
    container = generate._json(path.read_bytes())
    schema = generate._json(generate._read(ROOT / 'fixture.schema.json'))
    Draft202012Validator.check_schema(schema)
    if not Draft202012Validator(schema, registry=Registry(retrieve=no_retrieve)).is_valid(container):
        raise ValueError('fixture.shape')
    names = set()
    for kind in ('events', 'parser'):
        for f in container[kind]:
            if len(f['event_json'].encode('utf-8', errors='surrogatepass')) > 2097152:
                raise ValueError('fixture.bytes')
            if f['name'] in names:
                raise ValueError('fixture.name')
            names.add(f['name'])
            try:
                load_event(f['event_json'])
            except ValueError:
                if kind != 'parser':
                    raise ValueError('fixture.parse') from None
            else:
                if kind == 'parser':
                    raise ValueError('fixture.parser_expected_failure')
    return container


def check_native():
    """Validate native declarations only with the pinned local metaschemas."""
    files = sorted((ROOT / 'upstream/1.9.0/metaschema').glob('*.json'))
    schemas = [generate._json(generate._read(p)) for p in files]
    registry = Registry(retrieve=no_retrieve)
    for p, s in zip(files, schemas):
        Draft202012Validator.check_schema(s)
        resource = Resource.from_contents(s)
        registry = registry.with_resource('https://schema.ocsf.io/'+p.name, resource)
        if '$id' in s:
            registry = registry.with_resource(s['$id'], resource)
    for p in sorted((ROOT / 'extensions/ricevanta').rglob('*.json')):
        name = 'event' if p.parent.name == 'events' else 'object' if p.parent.name == 'objects' else 'dictionary' if p.name == 'dictionary.json' else 'extension'
        schema = generate._json(generate._read(ROOT / 'upstream/1.9.0/metaschema' / (name+'.schema.json')))
        Draft202012Validator(schema, registry=registry).validate(generate._json(generate._read(p)))
    profile_schema = generate._json(generate._read(ROOT / 'profile.schema.json'))
    Draft202012Validator.check_schema(profile_schema)
    Draft202012Validator(profile_schema, registry=Registry(retrieve=no_retrieve)).validate(generate._json(generate._read(ROOT / 'profile.json')))


def main():
    generate.check_outputs(ROOT, generate.compile_profile(ROOT))
    check_native()
    count = 0
    for path in [ROOT / 'examples/vectors.json', ROOT / 'fixtures/events.json']:
        f = load_fixtures(path)
        for case in f['events']:
            if validate_event(load_event(case['event_json']), case['source']) != case['expected_error']:
                raise ValueError('fixture.outcome:'+case['name'])
            count += 1
    print('OCSF native sources, profile and '+str(count)+' event vectors verified offline')


if __name__ == '__main__':
    main()
