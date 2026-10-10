#!/usr/bin/env python3
"""Offline ReportTemplate checks. Validity grants no read or execution rights."""
import datetime
import json
import math
import re
from pathlib import Path
from urllib.parse import urldefrag
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
HERE = Path(__file__).resolve().parent
BINDINGS = {'devices': ('devices', 'mdm.devices.read', 'devices'), 'devices.software': ('mdm', 'mdm.inventory.read', 'devices'), 'mdm.compliance': ('mdm', 'mdm.compliance.read', 'devices'), 'edr.alerts': ('detection', 'edr.alerts.read', 'devices'), 'edr.response_actions': ('detection', 'edr.response.read', 'devices'), 'dlp.findings': ('dlp', 'dlp.findings.read', 'devices'), 'lineage.edges': ('lineage', 'lineage.edges.read', 'lineage_endpoints'), 'pki.certificates': ('pki', 'pki.certificates.read', 'certificate_profile'), 'radius.authentications': ('radius', 'radius.authentications.read', 'radius_attribution'), 'agents.versions': ('devices', 'mdm.versions.read', 'devices'), 'agents.health': ('events', 'events.health.read', 'devices'), 'audit.events': ('audit', 'audit.events.read', 'organization')}
CONDITIONAL = [{'condition': 'infrastructure_certificate', 'permission': 'pki.infrastructure.read', 'scope': 'organization'}]

def strict_loads(raw):

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError('duplicate key')
            out[k] = v
        return out

    def constant(_):
        raise ValueError('nonfinite number')

    def number(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError('nonfinite number')
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)

def read(path):
    return strict_loads(path.read_text(encoding='utf-8'))

def registry(schemas):
    """Resolve only the two bundled schemas and refuse retrieval."""
    ids = {s['$id']: s for s in schemas}
    expected = {'https://ricevanta.io/schemas/report/v1alpha1/' + n for n in ('report-template.json', 'catalogue.schema.json')}
    if len(ids) != 2 or set(ids) != expected:
        raise ValueError('schema ids')

    def target(ref, root):
        uri, frag = urldefrag(ref)
        if uri and uri not in ids:
            raise ValueError('external ref')
        obj = ids[uri] if uri else root
        if frag:
            if not frag.startswith('/'):
                raise ValueError('fragment')
            for k in frag[1:].split('/'):
                k = k.replace('~1', '/').replace('~0', '~')
                if not isinstance(obj, dict) or k not in obj:
                    raise ValueError('unresolved fragment')
                obj = obj[k]
        return (obj, ids[uri] if uri else root)

    def walk(obj, root, stack, nested=False):
        if isinstance(obj, dict):
            if nested and '$id' in obj:
                raise ValueError('nested id')
            if id(obj) in stack:
                raise ValueError('reference cycle')
            stack = stack | {id(obj)}
            if '$ref' in obj:
                node, base = target(obj['$ref'], root)
                walk(node, base, stack, node is not base)
            for k, v in obj.items():
                if k not in ('$ref',):
                    walk(v, root, stack, True)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, root, stack, True)
    for s in schemas:
        Draft202012Validator.check_schema(s)
        walk(s, s, set())

    def refuse(_):
        raise ValueError('retrieval forbidden')
    return Registry(retrieve=refuse).with_resources(((k, Resource.from_contents(s)) for k, s in ids.items()))

def load_contracts(directory=HERE):
    if {p.name for p in directory.glob('*.json')} != {'report-template.json', 'catalogue.schema.json', 'catalogue.json'}:
        raise ValueError('file inventory')
    schemas = [read(directory / n) for n in ('report-template.json', 'catalogue.schema.json')]
    return (schemas, registry(schemas))
SCHEMAS, REGISTRY = load_contracts()
TEMPLATE = Draft202012Validator(SCHEMAS[0], registry=REGISTRY)
CATALOGUE_SCHEMA = Draft202012Validator(SCHEMAS[1], registry=REGISTRY)
CATALOGUE = read(HERE / 'catalogue.json')
SOURCES = {s['id']: s for s in CATALOGUE['sources']}
FIELDS = {s['id']: {f['name']: f for f in s['fields']} for s in CATALOGUE['sources']}

def check_permissions(c):
    permissions = {p['name']: p for p in read(HERE.parents[1] / 'permissions/v1/catalogue.json')['permissions']}
    errors = []
    for s in c['sources']:
        for name, scope in [(s['read_permission'], s['scope'])] + [(x['permission'], x['scope']) for x in s['conditional_reads']]:
            p = permissions.get(name, {})
            if any((p.get(k) != v for k, v in {'owner': s['owner'], 'scope': scope, 'status': 'active', 'grant': 'role'}.items())):
                errors.append('permission binding')
    return errors

def check_catalogue(c):
    if not CATALOGUE_SCHEMA.is_valid(c):
        return ['catalogue schema']
    errors = []
    ids = [s['id'] for s in c['sources']]
    if ids != sorted(BINDINGS):
        errors.append('source inventory')
    for s in c['sources']:
        if BINDINGS.get(s['id']) != (s['owner'], s['read_permission'], s['footprint']):
            errors.append('source binding')
        if s['scope'] != ('organization' if s['id'] == 'audit.events' else 'device_group'):
            errors.append('scope')
        if s['conditional_reads'] != (CONDITIONAL if s['id'] == 'pki.certificates' else []):
            errors.append('conditional reads')
        names = [f['name'] for f in s['fields']]
        if names != sorted(set(names)) or set(names) & {'time', 'device_groups'}:
            errors.append('field inventory')
        time = next((f for f in s['fields'] if f['name'] == s['time_field']), {})
        if time.get('type') != 'timestamp' or time.get('nullable') is not False:
            errors.append('time field')
    return errors + check_permissions(c)

def check_fixtures(fixtures):
    ids = set()
    for f in fixtures:
        if set(f) != {'id', 'structural', 'accepted', 'sentinel', 'path', 'rule', 'document'} or not re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', f['id']) or f['id'] in ids:
            raise ValueError('fixture contract')
        ids.add(f['id'])
        if type(f['structural']) is not bool or type(f['accepted']) is not bool:
            raise ValueError('fixture boolean')
        if f['accepted'] and (not f['structural'] or any((f[k] for k in ('sentinel', 'path', 'rule')))):
            raise ValueError('fixture success')
        if not f['accepted'] and (f['sentinel'] not in ('ErrCatalogue', 'ErrInput', 'ErrLimit', 'ErrEnvelope', 'ErrSchema', 'ErrSemantic') or f['rule'] not in ('catalogue', 'input', 'budget', 'bytes', 'envelope', 'schema', 'unique', 'reference', 'compatibility', 'output')):
            raise ValueError('fixture diagnostic')
    return fixtures

def load_fixtures():
    return check_fixtures(read(HERE / 'fixtures/templates.json'))

def pointer(p):
    return ''.join(('/' + str(k).replace('~', '~0').replace('/', '~1') for k in p))

def diagnostic(s, p, r):
    return [{'sentinel': s, 'path': pointer(p), 'rule': r}]

def charge(v):
    if v is None:
        return 4
    if type(v) is bool:
        return 4 if v else 5
    if type(v) in (int, float):
        return 24
    if type(v) is str:
        return 2 + sum((6 if ord(c) < 32 else 2 if c in '"\\' else len(c.encode()) for c in v))
    if type(v) is list:
        return 2 + max(0, len(v) - 1) + sum(map(charge, v))
    if type(v) is dict:
        return 2 + max(0, len(v) - 1) + sum((charge(k) + 1 + charge(x) for k, x in v.items()))
    return 0

def preflight(root):
    """Bound decoded traversal before shape checks or allocation for sorted keys."""
    count = raw = 0

    def walk(v, p, depth):
        nonlocal count, raw
        count += 1
        if count > 8192:
            return diagnostic('ErrLimit', p, 'budget')
        if type(v) in (dict, list):
            depth += 1
            if depth > 16:
                return diagnostic('ErrLimit', p, 'budget')
            if type(v) is dict:
                if any((type(k) is not str for k in v)):
                    return diagnostic('ErrInput', p, 'input')
                if 2 * len(v) > 8192 - count:
                    return diagnostic('ErrLimit', p, 'budget')
                key_bytes = 0
                for key in v:
                    if len(key) > 131072 - raw - key_bytes:
                        return diagnostic('ErrLimit', p, 'budget')
                    key_bytes += len(key.encode('utf-8', errors='surrogatepass'))
                    if key_bytes > 131072 - raw:
                        return diagnostic('ErrLimit', p, 'budget')
                for k in sorted(v):
                    err = walk(k, p + (k,), depth) or walk(v[k], p + (k,), depth)
                    if err:
                        return err
            else:
                if len(v) > 8192 - count:
                    return diagnostic('ErrLimit', p, 'budget')
                for i, x in enumerate(v):
                    err = walk(x, p + (i,), depth)
                    if err:
                        return err
        elif type(v) is str:
            if len(v) > 131072 - raw:
                return diagnostic('ErrLimit', p, 'budget')
            n = len(v.encode('utf-8', errors='surrogatepass'))
            if n > 131072 - raw:
                return diagnostic('ErrLimit', p, 'budget')
            raw += n
            try:
                v.encode('utf-8')
            except UnicodeError:
                return diagnostic('ErrInput', p, 'input')
        elif type(v) in (int, float):
            if abs(v) > 9007199254740991 or not math.isfinite(v):
                return diagnostic('ErrInput', p, 'input')
        elif v is not None and type(v) is not bool:
            return diagnostic('ErrInput', p, 'input')
        return []
    return walk(root, (), 0)

def json_equal(a, b):
    """Compare JSON values recursively, keeping booleans distinct from numbers."""
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    return a == b

def shape(v, s, p=(), definition=''):
    """Select structural branches for deterministic diagnostics. TEMPLATE independently checks pure schema acceptance."""
    errors = []

    def bad(q):
        errors.append(q)
    if '$ref' in s:
        name = s['$ref'].split('/')[-1]
        return shape(v, SCHEMAS[0]['$defs'][name], p, name)
    if 'oneOf' in s:
        branches = s['oneOf']
        selected = None
        if definition in ('condition', 'operand'):
            if isinstance(v, dict):
                if definition == 'operand' or 'param' in v:
                    selected = {'$ref': '#/$defs/ref'}
                elif len(v) == 1 and next(iter(v)) in ('eq', 'in', 'not_in', 'gte', 'lte', 'between', 'prefix', 'exists'):
                    selected = next((b for b in branches if next(iter(v)) in b.get('properties', {})))
                else:
                    return [p]
            else:
                selected = {'$ref': '#/$defs/scalar'}
        elif definition in ('parameter', 'block', 'measure'):
            tag = 'fn' if definition == 'measure' else 'type'
            if not isinstance(v, dict):
                return [p]
            if tag not in v:
                return [p + (tag,)]
            selected = next((b for b in branches if ('const' in b['properties'][tag] and v[tag] == b['properties'][tag]['const']) or v[tag] in b['properties'][tag].get('enum', [])), None)
            if selected is None:
                return [p + (tag,)]
        elif isinstance(v, dict):
            refs = [b for b in branches if b.get('$ref') == '#/$defs/ref']
            if refs and (definition != 'time_filter' or 'param' in v):
                selected = refs[0]
            else:
                selected = next((b for b in branches if b.get('type') == 'object' or b.get('$ref') == '#/$defs/time'), None)
        elif isinstance(v, list):
            selected = next((b for b in branches if b.get('type') == 'array' or b.get('$ref') == '#/$defs/groups'), None)
        else:
            selected = next((b for b in branches if b.get('type') == ('boolean' if type(v) is bool else 'number' if type(v) in (int, float) else 'string') or 'const' in b or 'enum' in b or (b.get('$ref') in ('#/$defs/time', '#/$defs/groups'))), None)
        if selected is None:
            return [p]
        return shape(v, selected, p, definition)
    typ = s.get('type')
    valid = {'object': type(v) is dict, 'array': type(v) is list, 'string': type(v) is str, 'boolean': type(v) is bool, 'number': type(v) in (int, float), 'integer': type(v) in (int, float) and float(v).is_integer()}
    if typ and (not valid[typ]):
        return [p]
    if 'const' in s and (type(v) is bool) != (type(s['const']) is bool) or ('const' in s and v != s['const']):
        bad(p)
    if 'enum' in s and v not in s['enum']:
        bad(p)
    if type(v) is dict:
        for k in s.get('required', []):
            if k not in v:
                bad(p + (k,))
        props = s.get('properties', {})
        for k, x in v.items():
            if k in props:
                errors += shape(x, props[k], p + (k,), 'time_filter' if definition == 'filter' and k == 'time' else '')
            elif s.get('additionalProperties') is False:
                bad(p + (k,))
            elif isinstance(s.get('additionalProperties'), dict):
                errors += shape(x, s['additionalProperties'], p + (k,))
            if 'propertyNames' in s:
                errors += shape(k, s['propertyNames'], p + (k,))
        if len(v) > s.get('maxProperties', len(v)):
            bad(p)
        if definition == 'block' and v.get('type') == 'chart':
            if v.get('chart') in ('stacked_bar', 'heatmap') and 'series' not in v:
                bad(p + ('series',))
            if v.get('chart') == 'pie' and 'series' in v:
                bad(p + ('series',))
    if type(v) is list:
        if not s.get('minItems', 0) <= len(v) <= s.get('maxItems', len(v)):
            bad(p)
        if s.get('uniqueItems'):
            if any(json_equal(v[i], v[j]) for i in range(len(v)) for j in range(i)):
                bad(p)
        for i, x in enumerate(v):
            errors += shape(x, s.get('items', {}), p + (i,))
    if type(v) is str:
        if not s.get('minLength', 0) <= len(v) <= s.get('maxLength', len(v)):
            bad(p)
        if 'pattern' in s and (not re.search(s['pattern'], v)):
            bad(p)
    if type(v) in (int, float) and (not s.get('minimum', v) <= v <= s.get('maximum', v)):
        bad(p)
    return errors

def calendar(v):
    try:
        return datetime.datetime.strptime(v, '%Y-%m-%dT%H:%M:%SZ')
    except (ValueError, TypeError):
        return None

def semantics(d):
    """Collect locations separately for each semantic stage, then select the first stage and location."""
    s = d['spec']
    params = s.get('parameters', [])
    datasets = s['datasets']
    layout = s['layout']
    stages = {r: [] for r in ('unique', 'reference', 'compatibility', 'output')}

    def add(r, p):
        stages[r].append(p)

    def unique(items, key, p):
        seen = set()
        for i, x in enumerate(items):
            if x[key] in seen:
                add('unique', p + (i, key))
            seen.add(x[key])
    unique(params, 'name', ('spec', 'parameters'))
    unique(datasets, 'name', ('spec', 'datasets'))
    pm = {x['name']: x for x in params}
    dm = {x['name']: x for x in datasets}

    def ref(v, p):
        if isinstance(v, dict) and 'param' in v and (v['param'] not in pm):
            add('reference', p + ('param',))

    def rangecheck(v, p):
        if isinstance(v, dict):
            for k in ('start', 'end'):
                if calendar(v[k]) is None:
                    add('compatibility', p + (k,))
            if calendar(v['start']) and calendar(v['end']) and (v['start'] >= v['end']):
                add('compatibility', p + ('end',))

    def literal(v, f, p):
        t = f['type']
        ok = False
        if t == 'string':
            ok = type(v) is str
        elif t == 'enum':
            ok = type(v) is str and v in f['values']
        elif t == 'boolean':
            ok = type(v) is bool
        elif t in ('integer', 'number'):
            ok = type(v) in (int, float) and (t == 'number' or float(v).is_integer())
        elif t == 'timestamp':
            ok = type(v) is str and calendar(v) is not None and (re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', v) is not None)
        if not ok:
            add('compatibility', p)
        return ok
    for i, x in enumerate(params):
        p = ('spec', 'parameters', i)
        if x['type'] == 'enum_list':
            source, field = x['field'].split('/')
            f = FIELDS.get(source, {}).get(field)
            if f is None:
                add('reference', p + ('field',))
            elif f['type'] != 'enum':
                add('compatibility', p + ('field',))
            else:
                for j, v in enumerate(x.get('default', [])):
                    literal(v, f, p + ('default', j))
        elif x['type'] == 'time_range' and 'default' in x:
            rangecheck(x['default'], p + ('default',))
    for i, x in enumerate(datasets):
        p = ('spec', 'datasets', i)
        source = x['source']
        fields = FIELDS.get(source)
        unique(x['measures'], 'name', p + ('measures',))
        unique(x.get('order_by', []), 'field', p + ('order_by',))
        if fields is None:
            add('reference', p + ('source',))
        for k, v in x['filter'].items():
            q = p + ('filter', k)
            if k in ('time', 'device_groups'):
                ref(v, q)
                if isinstance(v, dict) and 'param' in v:
                    if v['param'] in pm and pm[v['param']]['type'] != ('time_range' if k == 'time' else 'device_groups'):
                        add('compatibility', q)
                elif k == 'time':
                    rangecheck(v, q)
                continue
            f = fields.get(k) if fields else None
            if fields is not None and f is None:
                add('reference', q)
            op = 'eq'
            operand = v
            operandpath = q
            if isinstance(v, dict) and 'param' not in v:
                op = next(iter(v))
                operand = v[op]
                operandpath = q + (op,)
            ref(operand, operandpath)
            if f is None:
                continue
            if op not in f['operators']:
                add('compatibility', q)
                continue
            if isinstance(operand, dict):
                param = pm.get(operand['param'])
                if param is None:
                    continue
                ok = param['type'] == 'string' and f['type'] == 'string' and (op in ('eq', 'prefix')) or (param['type'] == 'enum_list' and op in ('in', 'not_in') and (param['field'] == source + '/' + k)) or (param['type'] == 'time_range' and f['type'] == 'timestamp' and (op == 'between'))
                if not ok:
                    add('compatibility', operandpath)
            elif op == 'exists':
                pass
            elif isinstance(operand, list):
                valid = [literal(y, f, operandpath + (j,)) for j, y in enumerate(operand)]
                if op == 'between' and all(valid) and (operand[0] > operand[1]):
                    add('compatibility', operandpath + (1,))
            else:
                literal(operand, f, operandpath)
        for j, k in enumerate(x.get('group_by', [])):
            f = fields.get(k) if fields else None
            if fields is not None and f is None:
                add('reference', p + ('group_by', j))
            elif f and (not f['groupable']):
                add('compatibility', p + ('group_by', j))
        for j, m in enumerate(x['measures']):
            q = p + ('measures', j)
            if m['fn'] != 'count':
                f = fields.get(m['field']) if fields else None
                if fields is not None and f is None:
                    add('reference', q + ('field',))
                elif f and m['fn'] not in f['aggregations']:
                    add('compatibility', q + ('fn',))
            if fields and m['name'] in fields:
                add('output', q + ('name',))
        outputs = set(x.get('group_by', [])) | {m['name'] for m in x['measures']}
        for j, o in enumerate(x.get('order_by', [])):
            if o['field'] not in outputs:
                add('output', p + ('order_by', j, 'field'))
    for i, b in enumerate(layout):
        if b['type'] in ('heading', 'text'):
            continue
        p = ('spec', 'layout', i)
        x = dm.get(b['dataset'])
        if x is None:
            add('reference', p + ('dataset',))
            continue
        groups = x.get('group_by', [])
        measures = {m['name'] for m in x['measures']}
        outputs = set(groups) | measures
        if b['type'] == 'kpi':
            if groups:
                add('output', p + ('dataset',))
            if b['measure'] not in measures:
                add('output', p + ('measure',))
        elif b['type'] == 'table':
            for j, k in enumerate(b['columns']):
                if k not in outputs:
                    add('output', p + ('columns', j))
        else:
            if len(groups) != (2 if 'series' in b else 1):
                add('output', p + ('dataset',))
            if b['x'] not in groups:
                add('output', p + ('x',))
            if 'series' in b and (b['series'] not in groups or b['series'] == b['x']):
                add('output', p + ('series',))
            if b['y'] not in measures:
                add('output', p + ('y',))
            f = FIELDS.get(x['source'], {}).get(b['x'])
            if b['chart'] in ('line', 'area') and f and (f['type'] != 'timestamp'):
                add('output', p + ('x',))
    for r, paths in stages.items():
        if paths:
            return diagnostic('ErrSemantic', min(paths), r)
    return []

def validate_template(document):
    error = preflight(document)
    if error:
        return error
    if charge(document) > 65536:
        return diagnostic('ErrLimit', (), 'bytes')
    root = dict(SCHEMAS[0])
    root['properties'] = dict(root['properties'])
    root['properties']['spec'] = {'type': 'object'}
    paths = shape(document, root)
    if paths:
        return diagnostic('ErrEnvelope', min(paths), 'envelope')
    paths = shape(document['spec'], SCHEMAS[0]['properties']['spec'], ('spec',))
    if paths:
        return diagnostic('ErrSchema', min(paths), 'schema')
    return semantics(document)

def main():
    errors = check_catalogue(CATALOGUE)
    for f in load_fixtures():
        if TEMPLATE.is_valid(f['document']) != f['structural']:
            errors.append(f['id'] + ': structural')
        expected = [] if f['accepted'] else [{k: f[k] for k in ('sentinel', 'path', 'rule')}]
        result = validate_template(f['document'])
        if result != expected:
            errors.append(f['id'] + ': ' + str(result) + ' expected ' + str(expected))
    if errors:
        raise SystemExit('\n'.join(errors))
    print('2 schemas valid; 12 sources; 83 fixtures (33 accepted, 50 rejected)')
if __name__ == '__main__':
    main()
