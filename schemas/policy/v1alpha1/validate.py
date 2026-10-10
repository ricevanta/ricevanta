"""Validate policy contracts and fixtures: python3 schemas/policy/v1alpha1/validate.py."""

import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from rfc3339_validator import validate_rfc3339
import yaml


# MDM contracts use an explicit local registry, never reference retrieval.
from functools import lru_cache
from urllib.parse import urldefrag, urljoin, unquote

MDM_KINDS = (
    'apple.declaration', 'apple.profile', 'windows.csp', 'windows.registry',
    'windows.service', 'linux.dconf', 'linux.polkit', 'linux.sysctl',
    'linux.systemd', 'linux.pam', 'linux.file', 'linux.repository',
    'software', 'check.query', 'check.collector', 'os_update', 'encryption',
)
SCHEMA_BASE = 'https://ricevanta.io/schemas/policy/v1alpha1/'
RESOURCE_SCHEMAS = {
    'policy.schema.json': 'Policy', 'exception.schema.json': 'Exception',
    'baseline.schema.json': 'Baseline', 'software-package.schema.json': 'SoftwarePackage',
    'device-group.schema.json': 'DeviceGroup',
}
SCHEMA_FILES = {**RESOURCE_SCHEMAS, 'mdm-common.schema.json': 'MDMCommon',
                **{f'baseline/{kind}.json': kind for kind in MDM_KINDS}}


def _strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise ValueError('Duplicate or nonstring object key')
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError('Nonfinite number')


def _finite_float(text):
    import math
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('Nonfinite number')
    return value


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=_strict_pairs,
                      parse_constant=_nonfinite, parse_float=_finite_float)


class ResourceLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError('YAML aliases are forbidden')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        return _strict_pairs((self.construct_object(key, deep=True),
                              self.construct_object(value, deep=True))
                             for key, value in node.value)


def _yaml_float(loader, node):
    import math
    value = loader.construct_yaml_float(node)
    if not math.isfinite(value):
        raise ValueError('Nonfinite number')
    return value


ResourceLoader.add_constructor('tag:yaml.org,2002:float', _yaml_float)


def load_mdm_schemas():
    directory = Path(__file__).resolve().parent
    missing = [name for name in SCHEMA_FILES if not (directory / name).is_file()]
    if missing:
        raise ValueError('\n'.join(f'Missing required schema: {name}' for name in missing))
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*.json')
              if 'fixtures' not in p.relative_to(directory).parts}
    if actual != set(SCHEMA_FILES):
        raise ValueError('Schema inventory differs from the explicit manifest')
    schemas = {}
    for name, title in SCHEMA_FILES.items():
        path = directory / name
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != directory.parent):
            raise ValueError(f'Schema symlink refused: {name}')
        schema = read_json(path)
        if schema.get('$id') != SCHEMA_BASE + name or schema.get('title') != title:
            raise ValueError(f'Required schema {name} must have its exact id and title {title}')
        if schema.get('$schema') != 'https://json-schema.org/draft/2020-12/schema':
            raise ValueError(f'Wrong schema dialect: {name}')
        if name.startswith('baseline/'):
            check = title in ('check.query', 'check.collector')
            if (schema.get('x-ricevanta-effect') != ('check' if check else 'apply')
                    or schema.get('x-ricevanta-protected-publication') is not (not check)):
                raise ValueError(f'Wrong effect annotation: {name}')
        Draft202012Validator.check_schema(schema)
        schemas[name] = schema
    by_id = {s['$id']: s for s in schemas.values()}
    graph = {}

    def collect(node, base, pointer=''):
        location = base + '#' + pointer
        graph.setdefault(location, [])
        if isinstance(node, dict):
            if pointer and '$id' in node:
                raise ValueError('Nested schema ids are forbidden')
            if any(key in node for key in ('$dynamicRef', '$recursiveRef', '$anchor', '$dynamicAnchor')):
                raise ValueError('Only static JSON pointer references are supported')
            if '$ref' in node:
                target_id, fragment = urldefrag(urljoin(base, node['$ref']))
                if target_id not in by_id or (fragment and not fragment.startswith('/')):
                    raise ValueError(f'Off-tree schema reference: {node["$ref"]}')
                fragment = unquote(fragment)
                target = by_id[target_id]
                try:
                    for part in fragment.split('/')[1:]:
                        if re.search(r'~(?![01])', part):
                            raise ValueError('Invalid JSON pointer escape')
                        part = part.replace('~1', '/').replace('~0', '~')
                        if isinstance(target, list) and re.fullmatch(r'0|[1-9][0-9]*', part) is None:
                            raise ValueError('Noncanonical array pointer')
                        target = target[int(part)] if isinstance(target, list) else target[part]
                except (KeyError, IndexError, ValueError, TypeError):
                    raise ValueError(f'Missing schema reference: {node["$ref"]}') from None
                if not isinstance(target, (dict, bool)):
                    raise ValueError('Reference target must be a schema')
                edge = target_id + '#' + fragment
                graph[location].append(edge)
            children = node.items()
        elif isinstance(node, list):
            children = enumerate(node)
        else:
            children = ()
        for key, child in children:
            if isinstance(child, (dict, list)):
                child_pointer = pointer + '/' + str(key).replace('~', '~0').replace('/', '~1')
                child_location = base + '#' + child_pointer
                native = SCHEMA_BASE + 'mdm-common.schema.json#/$defs/nativeJSON'
                # Only these containment edges descend into another instance value.
                # Keep ref edges so aliases cannot skip that required descent.
                if child_location not in (native + '/oneOf/4/items',
                                          native + '/oneOf/5/additionalProperties'):
                    graph[location].append(child_location)
                collect(child, base, child_pointer)

    for schema in schemas.values():
        collect(schema, schema['$id'])
    active, finished = set(), set()

    def visit(location):
        if location in active:
            raise ValueError('Schema reference cycle')
        if location in finished:
            return
        active.add(location)
        for target in graph.get(location, ()):
            visit(target)
        active.remove(location)
        finished.add(location)

    for location in graph:
        visit(location)

    def refuse(uri):
        raise ValueError(f'External schema retrieval refused: {uri}')

    registry = Registry(retrieve=refuse).with_resources(
        (schema['$id'], Resource.from_contents(schema)) for schema in schemas.values())
    return schemas, registry


@lru_cache(maxsize=1)
def mdm_validators():
    schemas, registry = load_mdm_schemas()
    return {kind: Draft202012Validator(schemas[name], registry=registry)
            for name, kind in RESOURCE_SCHEMAS.items()
            if kind not in ('Policy', 'Exception')}


def check_mdm_fixtures():
    directory = Path(__file__).resolve().parent
    fixture_root = directory / 'fixtures/mdm'
    def checked_file(path):
        for ancestor in (path, *path.parents):
            if ancestor == directory:
                break
            if ancestor.is_symlink():
                raise ValueError('MDM fixture symlink refused')
        return read_json(path)

    manifest = checked_file(fixture_root / 'manifest.json')
    if not isinstance(manifest, list) or not manifest:
        raise ValueError('Invalid MDM manifest')
    names = set()
    failures = []
    expected_errors = checked_file(directory / 'fixtures/expected-errors.json')
    error_names = set()
    for entry in manifest:
        if not isinstance(entry, dict) or set(entry) != {'file', 'structural', 'accepted', 'sentinel', 'path', 'rule'}:
            raise ValueError('Invalid MDM manifest entry')
        name = entry['file']
        if not isinstance(name, str) or re.fullmatch(r'(valid|invalid)/mdm-[a-z0-9-]+[.]json', name) is None:
            raise ValueError('Invalid MDM fixture filename')
        if name in names:
            raise ValueError('Duplicate MDM fixture filename')
        names.add(name)
        if (type(entry['structural']) is not bool or type(entry['accepted']) is not bool
                or any(not isinstance(entry[k], str) for k in ('sentinel', 'path', 'rule'))
                or name.startswith('valid/') != entry['accepted']):
            raise ValueError('Invalid MDM fixture expectation')
        if entry['accepted']:
            if not entry['structural'] or any(entry[k] for k in ('sentinel', 'path', 'rule')):
                raise ValueError('Invalid successful MDM expectation')
        elif (entry['sentinel'], entry['rule']) not in {
            ('ErrInput', 'input'), ('ErrLimit', 'budget'), ('ErrLimit', 'bytes'),
            ('ErrEnvelope', 'envelope'), ('ErrSchema', 'schema'),
            *(('ErrSemantic', rule) for rule in ('unique', 'duration', 'target', 'encoding', 'relation')),
        } or (entry['path'] and not entry['path'].startswith('/')):
            raise ValueError('Invalid failed MDM expectation')
        path = fixture_root / name
        if path.is_symlink() or path.parent.is_symlink() or fixture_root.is_symlink():
            raise ValueError('MDM fixture symlink refused')
        document = checked_file(path)
        kind = document.get('kind') if isinstance(document, dict) else None
        structural = isinstance(kind, str) and kind in mdm_validators() and mdm_validators()[kind].is_valid(document)
        result = validate_mdm(document)
        expected = [] if entry['accepted'] else [{k: entry[k] for k in ('sentinel', 'path', 'rule')}]
        if structural != entry['structural']:
            failures.append(f'{name}: structural {structural}, expected {entry["structural"]}')
        if result != expected:
            failures.append(f'{name}: full result {result}, expected {expected}')
        if not entry['accepted']:
            error_name = 'mdm/' + name
            error_names.add(error_name)
            # The manifest owns RFC 6901 paths; the shared index keeps its field-array layout.
            parts = []
            current = document
            for part in entry['path'].split('/')[1:]:
                part = part.replace('~1', '/').replace('~0', '~')
                key = int(part) if isinstance(current, list) else part
                parts.append(key)
                try:
                    current = current[key]
                except (KeyError, IndexError, TypeError):
                    current = None
            if expected_errors.get(error_name) != parts:
                failures.append(f'{name}: expected-errors.json path differs from manifest')
    actual = {p.relative_to(fixture_root).as_posix() for p in fixture_root.rglob('*') if p.is_file()}
    if actual != names | {'manifest.json'}:
        failures.append('MDM fixture inventory differs from manifest')
    if {name for name in expected_errors if name.startswith('mdm/')} != error_names:
        failures.append('MDM errors differ from expected-errors.json')
    return failures, len(names)


import base64 as _mdm_base64
import math as _mdm_math
import re as _mdm_re
from urllib.parse import unquote as _mdm_unquote


def _mdm_pointer(parts):
    return ''.join('/' + str(p).replace('~', '~0').replace('/', '~1') for p in parts)


def _mdm_order(parts):
    return tuple((1, p) if isinstance(p, int) else (0, p.encode('utf-8')) for p in parts)


def _mdm_failure(sentinel, path, rule):
    return [{'sentinel': sentinel, 'path': _mdm_pointer(path), 'rule': rule}]


def _mdm_scan(value):
    count = raw = 0
    def walk(v, path, level):
        nonlocal count, raw
        count += 1
        if count > 100000:
            return _mdm_failure('ErrLimit', path, 'budget')
        if type(v) in (dict, list):
            level += 1
            if level > 32:
                return _mdm_failure('ErrLimit', path, 'budget')
            if type(v) is dict:
                if any(type(k) is not str for k in v):
                    return _mdm_failure('ErrInput', path, 'input')
                # Invalid scalar keys sort by their surrogate-pass UTF-8 bytes.
                for k in sorted(v, key=lambda s: s.encode('utf-8', 'surrogatepass')):
                    error = walk(k, path + [k], level)
                    if error:
                        return error
                    error = walk(v[k], path + [k], level)
                    if error:
                        return error
            else:
                for i, child in enumerate(v):
                    error = walk(child, path + [i], level)
                    if error:
                        return error
        elif type(v) is str:
            try:
                raw += len(v.encode('utf-8'))
            except UnicodeEncodeError:
                return _mdm_failure('ErrInput', path, 'input')
            if raw > 2097152:
                return _mdm_failure('ErrLimit', path, 'budget')
        elif type(v) in (int, float):
            if abs(v) > 9007199254740991 or not _mdm_math.isfinite(v):
                return _mdm_failure('ErrInput', path, 'input')
        elif v is not None and type(v) is not bool:
            return _mdm_failure('ErrInput', path, 'input')
        return []
    return walk(value, [], 0)


def _mdm_charge(v):
    if v is None:
        return 4
    if type(v) is bool:
        return 4 if v else 5
    if type(v) in (float, int):
        return 24
    if type(v) is str:
        return 2 + sum(6 if ord(c) < 32 else 2 if c in '\\"' else len(c.encode('utf-8')) for c in v)
    if type(v) is list:
        return 2 + max(0, len(v)-1) + sum(_mdm_charge(x) for x in v)
    return 2 + max(0, len(v)-1) + sum(_mdm_charge(k)+1+_mdm_charge(x) for k, x in v.items())


def _mdm_diagnostics(errors):
    ranked = []
    priority = {'required': 0, 'additionalProperties': 1, 'false': 1, 'type': 2, 'enum': 3, 'const': 3,
                'minimum': 4, 'maximum': 4, 'minLength': 4, 'maxLength': 4, 'minItems': 4,
                'maxItems': 4, 'minProperties': 4, 'maxProperties': 4, 'uniqueItems': 4, 'pattern': 5}
    def visit(error):
        path = list(error.absolute_path)
        if error.context:
            contexts = error.context
            if error.validator in ('oneOf', 'anyOf'):
                branches = error.schema[error.validator]
                if all(isinstance(branch, dict) and isinstance(branch.get('type'), str)
                       for branch in branches):
                    selected_types = {i for i, branch in enumerate(branches)
                                      if Draft202012Validator.TYPE_CHECKER.is_type(error.instance, branch['type'])}
                    if selected_types:
                        contexts = [child for child in contexts
                                    if list(child.schema_path)[0] in selected_types]
            if error.validator in ('oneOf', 'anyOf') and type(error.instance) is dict:
                branches = error.schema[error.validator]
                tags = ('kind', 'os', 'platform', 'format', 'type', 'mode', 'operator', 'manager')
                candidates = set(range(len(branches)))
                had_tag = False
                for tag in tags:
                    constraints = {i: branches[i].get('properties', {}).get(tag, {}) for i in candidates}
                    constraints = {i: c for i, c in constraints.items() if 'const' in c or 'enum' in c}
                    if not constraints:
                        continue
                    had_tag = True
                    matches = {i for i, c in constraints.items() if tag in error.instance and error.instance[tag] in c.get('enum', [c.get('const')])}
                    if not matches:
                        ranked.append((path+[tag], 0 if tag not in error.instance else 3))
                        return
                    candidates = matches | (candidates-set(constraints))
                # Table branches can share os/format and differ by nested tags.
                # Narrow only when a nested discriminator matches a candidate.
                for field in ('source', 'signature', 'detection'):
                    instance = error.instance.get(field)
                    if type(instance) is not dict:
                        continue
                    for tag in ('type', 'manager'):
                        constraints = {i: branches[i].get('properties', {}).get(field, {}).get('properties', {}).get(tag, {}) for i in candidates}
                        constraints = {i: c for i, c in constraints.items() if 'const' in c or 'enum' in c}
                        matches = {i for i, c in constraints.items() if tag in instance and instance[tag] in c.get('enum', [c.get('const')])}
                        if matches:
                            candidates = matches | (candidates-set(constraints))
                if had_tag:
                    contexts = [c for c in contexts if list(c.schema_path)[0] in candidates]
            for child in contexts:
                visit(child)
            return
        if error.validator == 'required' and type(error.instance) is dict:
            for key in error.validator_value:
                if key not in error.instance:
                    ranked.append((path+[key], 0))
            return
        if error.validator == 'additionalProperties' and type(error.instance) is dict:
            props = error.schema.get('properties', {})
            patterns = error.schema.get('patternProperties', {})
            for key in error.instance:
                if key not in props and not any(_mdm_re.search(p, key) for p in patterns):
                    ranked.append((path+[key], 1))
            return
        # A not-required conditional marks each supplied forbidden child.
        if error.validator == 'not' and type(error.instance) is dict:
            required = list(error.validator_value.get('required', []))
            for branch in error.validator_value.get('anyOf', []):
                required.extend(branch.get('required', []))
            if required:
                ranked.extend((path+[key], 1) for key in required if key in error.instance)
                return
        ranked.append((path, priority.get(error.validator, 6)))
    for error in errors:
        visit(error)
    # A union can match multiple branches when a required discriminator is absent.
    # Prefer the concrete child defect over that speculative parent constraint.
    ranked = [(path, rank) for path, rank in ranked
              if rank != 6 or not any(len(child) > len(path) and child[:len(path)] == path
                                      and child_rank < 6 for child, child_rank in ranked)]
    return min(ranked, key=lambda x: (_mdm_order(x[0]), x[1]))[0] if ranked else None


def _mdm_duration(value):
    if type(value) in (int, float) and value == 0:
        return 0
    match = _mdm_re.fullmatch(r'([1-9][0-9]{0,5})([smhd])', value)
    return int(match[1]) * {'s':1, 'm':60, 'h':3600, 'd':86400}[match[2]]


def _mdm_https(value):
    if not value.startswith('https://') or any(c.isspace() or ord(c) < 32 or ord(c)==127 for c in value) or '\\' in value or '#' in value:
        return False
    rest = value[8:]
    authority = _mdm_re.split(r'[/?]', rest, maxsplit=1)[0]
    if not authority or '%' in authority or '@' in authority or authority.count(':') > 1:
        return False
    host, sep, port = authority.partition(':')
    if sep and (not _mdm_re.fullmatch(r'[1-9][0-9]{0,4}', port) or int(port)>65535):
        return False
    if _mdm_re.fullmatch(r'[0-9.]+', host):
        octets = host.split('.')
        if len(octets)!=4 or any(not _mdm_re.fullmatch(r'0|[1-9][0-9]{0,2}', x) or int(x)>255 for x in octets):
            return False
    elif len(host)>253 or not all(_mdm_re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in host.split('.')):
        return False
    suffix = rest[len(authority):]
    if _mdm_re.search(r'%(?![0-9a-fA-F]{2})', suffix):
        return False
    path = suffix.split('?',1)[0]
    for encoded in _mdm_re.findall(r'%([0-9a-fA-F]{2})', path):
        byte = int(encoded,16)
        if byte in (47,92,37,127) or byte<32:
            return False
    return not any(x in ('.','..') for x in _mdm_unquote(path).split('/'))


def _mdm_semantic(document):
    defects = {rule: [] for rule in ('unique','duration','target','encoding','relation')}
    def add(rule, path):
        defects[rule].append(path)
    def unique(entries, field, path):
        seen = set()
        for index, entry in enumerate(entries):
            value = entry[field]
            if value in seen:
                add('unique',path+[index,field])
            seen.add(value)
    def duration(value, path):
        seconds = _mdm_duration(value)
        if seconds>2592000:
            add('duration',path)
        return seconds
    def encoding(value, path, qword=False):
        if qword:
            if int(value)>18446744073709551615:
                add('encoding',path)
        else:
            try:
                if _mdm_base64.b64encode(_mdm_base64.b64decode(value,validate=True)).decode('ascii')!=value:
                    add('encoding',path)
            except (ValueError, _mdm_base64.binascii.Error):
                add('encoding',path)
    spec=document['spec']; kind=document['kind']; root=['spec']
    if kind=='Baseline':
        unique(spec['items'],'id',root+['items'])
        for index,item in enumerate(spec['items']):
            path=root+['items',index]; settings=item['settings']; sp=path+['settings']; ik=item['kind']
            if 'grace' in item:
                grace=duration(item['grace'],path+['grace'])
                if item['severity']=='critical' and grace!=0:
                    add('duration',path+['grace'])
            if ik=='apple.profile':
                unique(settings['payloads'],'PayloadIdentifier',sp+['payloads'])
            if ik=='linux.systemd' and 'dropIn' in settings:
                unique(settings['dropIn']['sections'],'name',sp+['dropIn','sections'])
            if ik=='windows.registry':
                key=settings['key']; segments=key.split('\\'); lower=[x.lower() for x in segments]
                if any(x in ('.','..') or x.strip()!=x for x in segments) or 'wow6432node' in lower or lower[:2]==['software','policies']:
                    add('target',sp+['key'])
                if settings['type'] in ('binary','qword'):
                    encoding(settings['value'],sp+['value'],settings['type']=='qword')
            if ik=='windows.csp':
                if any(x in ('.','..') for x in settings['locUri'].split('/')[4:]):
                    add('target',sp+['locUri'])
                if settings['format']=='b64':
                    encoding(settings['value'],sp+['value'])
            if ik in ('linux.file','linux.dconf'):
                key='path' if ik=='linux.file' else 'key'; target=settings[key]
                if any(x in ('.','..') for x in target.split('/')) or (ik=='linux.file' and (not target.startswith('/etc/') or any(target==x or target.startswith(x+'/') for x in ('/etc/pam.d','/etc/ricevanta')))):
                    add('target',sp+[key])
            if ik=='linux.repository' and not _mdm_https(settings['url']):
                add('target',sp+['url'])
            if ik in ('os_update','encryption') and settings['platform']!=spec['os']:
                add('relation',sp+['platform'])
            if ik=='windows.service' and settings['startType']=='disabled' and settings['state']=='running':
                add('relation',sp+['state'])
            if ik=='os_update':
                reboot=settings['reboot']; rp=sp+['reboot']; notify=duration(reboot['notify'],rp+['notify']); deadline=duration(reboot['deadline'],rp+['deadline'])
                if deadline==0:
                    add('duration',rp+['deadline'])
                if notify>deadline:
                    add('duration',rp+['notify'])
                if settings['platform']=='macos' and settings.get('targetVersion')=='latest' and 'targetBuild' in settings:
                    add('relation',sp+['targetBuild'])
                if settings['platform']=='windows' and settings['activeHours']['start']==settings['activeHours']['end']:
                    add('relation',sp+['activeHours','end'])
    elif kind=='SoftwarePackage':
        source=spec['source']; detection=spec['detection']
        if source['type']=='blob' and any(x in ('.','..') for x in source['blobKey'].split('/')):
            add('target',root+['source','blobKey'])
        if spec['reboot']['mode']=='exit-code':
            unique(spec['reboot']['codes'],'code',root+['reboot','codes'])
        if 'version' in detection and detection['version']!=spec['version']:
            add('relation',root+['detection','version'])
        if detection['type']=='package' and detection['name']!=(source['package'] if source['type']=='repository' else spec['name']):
            add('relation',root+['detection','name'])
    for rule, paths in defects.items():
        if paths:
            return _mdm_failure('ErrSemantic',min(paths,key=_mdm_order),rule)
    return []


def validate_mdm(document):
    """Return the first ordered MDM input, limit, envelope, schema or semantic error."""
    error=_mdm_scan(document)
    if error:
        return error
    if _mdm_charge(document)>1048576:
        return _mdm_failure('ErrLimit',[],'bytes')
    if type(document) is dict and document.get('kind')=='Baseline' and type(document.get('spec')) is dict and type(document['spec'].get('items')) is list:
        for index,item in enumerate(document['spec']['items']):
            if type(item) is dict and 'settings' in item and _mdm_charge(item['settings'])>65536:
                return _mdm_failure('ErrLimit',['spec','items',index,'settings'],'bytes')
    if type(document) is not dict:
        return _mdm_failure('ErrEnvelope',[],'envelope')
    validators=mdm_validators()
    kind=document.get('kind')
    # Use a recognized root schema to diagnose envelope defects in path order.
    validator=validators.get(kind,validators['Baseline']) if type(kind) is str else validators['Baseline']
    schema=dict(validator.schema)
    schema['properties']=dict(schema.get('properties',{}))
    schema['properties']['spec']={'type':'object'}
    schema.pop('allOf',None)
    path=_mdm_diagnostics(validator.evolve(schema=schema).iter_errors(document))
    if path is not None:
        return _mdm_failure('ErrEnvelope',path,'envelope')
    path=_mdm_diagnostics(validator.iter_errors(document))
    if path is not None:
        return _mdm_failure('ErrSchema',path,'schema')
    return _mdm_semantic(document)


def main():
    root = Path(__file__).resolve().parents[3]
    directory = Path(__file__).resolve().parent
    required = RESOURCE_SCHEMAS
    missing = [name for name in required if not (directory / name).is_file()]
    if missing:
        print("\n".join(f"Missing required schema: {name}" for name in missing), file=sys.stderr)
        return 1
    formats = FormatChecker(formats=[])
    formats.checks("date-time")(lambda value: not isinstance(value, str) or (value == value.strip() and validate_rfc3339(value.upper())))
    validators = {}
    schema_files, registry = load_mdm_schemas()
    schemas = list(schema_files.values())
    for name, kind in required.items():
        validators[kind] = Draft202012Validator(schema_files[name], registry=registry, format_checker=formats)
    failures = []
    for name, kind in required.items():
        if json.loads((directory / name).read_text()).get("title") != kind:
            failures.append(f"Required schema {name} must have title {kind}")
    expected_errors = json.loads((directory / "fixtures/expected-errors.json").read_text())
    invalid_names = {path.name for path in (directory / "fixtures/invalid").glob("*.json")}
    if invalid_names != {name for name in expected_errors if not name.startswith("mdm/")}:
        failures.append("Invalid fixtures differ from expected-errors.json")
    count = 0
    for expectation in ('valid', 'invalid'):
        paths = sorted((directory / 'fixtures' / expectation).glob('*.json'))
        if not paths:
            failures.append(f'No {expectation} fixtures')
        for path in paths:
            document = json.loads(path.read_text())
            errors = list(validators[document['kind']].iter_errors(document))
            count += 1
            if expectation == "invalid" and errors:
                expected_path = expected_errors.get(path.name)
                if not any(list(error.absolute_path) == expected_path for error in errors):
                    failures.append(f"{path.relative_to(root)}: rejection missed expected field {expected_path}")
            if bool(errors) != (expectation == 'invalid'):
                reason = '; '.join(error.message for error in errors) or 'accepted invalid policy'
                failures.append(f'{path.relative_to(root)}: {reason}')
    mdm_failures, mdm_count = check_mdm_fixtures()
    failures.extend(mdm_failures)
    count += mdm_count
    examples = {kind: 0 for kind in required.values()}
    for filename in ('policy-envelope.md', 'mdm-resource-schemas.md'):
        spec = root / 'docs/specs' / filename
        for block in re.findall(r'```yaml\n(.*?)\n```', spec.read_text(), re.S):
            for document in yaml.load_all(block, Loader=ResourceLoader):
                if not isinstance(document, dict) or 'apiVersion' not in document or 'kind' not in document:
                    failures.append(f'{spec.relative_to(root)}: Resource example requires apiVersion and kind')
                    continue
                kind = document['kind']
                if not isinstance(kind, str) or kind not in examples:
                    failures.append(f'{spec.relative_to(root)}: Unknown resource kind: {kind}')
                    continue
                examples[kind] += 1
                for error in validators[kind].iter_errors(document):
                    failures.append(f'{spec.relative_to(root)} {kind} example: {error.message}')
                if kind in mdm_validators():
                    for error in validate_mdm(document):
                        failures.append(f'{spec.relative_to(root)} {kind} example: {error}')
    for kind, count_for_kind in examples.items():
        if not count_for_kind:
            failures.append(f'No {kind} example validated')
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'Validated {len(schemas)} schemas, {len(validators)} resource kinds, {count} fixtures and {sum(examples.values())} YAML examples')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, yaml.YAMLError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
