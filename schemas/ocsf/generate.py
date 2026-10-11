"""Offline verification of the pinned OCSF source inventory."""
import hashlib
import json
from pathlib import Path
import re
import stat

COMMIT = '856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba'
TREE = 'e759895035eef590258c37901fadaaafc629ee3d'
MAX_FILE_BYTES = 1048576
MAX_FILES = 512
MAX_SOURCE_BYTES = 16777216
LOCK_KEYS = {'format', 'release', 'tag', 'commit', 'tree', 'repository', 'files'}
FILE_KEYS = {'path', 'bytes', 'git_blob', 'sha256'}
ROOT_FILES = {'version.json', 'categories.json', 'dictionary.json', 'LICENSE', 'NOTICE'}
SOURCE_DIRS = {'events', 'objects', 'profiles', 'includes', 'extensions', 'metaschema'}


def _fail(code):
    raise ValueError(code)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail('source.duplicate_key')
        value[key] = item
    return value


def _read(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        _fail('vendor.file_type')
    if info.st_size > MAX_FILE_BYTES:
        _fail('source.budget')
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        _fail('source.budget')
    return data


def _json(data):
    def constant(_):
        _fail('source.json')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail('source.json')


def _path(value):
    if not isinstance(value, str) or not value or value.startswith('/'):
        _fail('vendor.path')
    parts = value.split('/')
    if any(part in ('', '.', '..') for part in parts) or '\\' in value or '\0' in value:
        _fail('vendor.path')
    if value not in ROOT_FILES and not (parts[0] in SOURCE_DIRS and len(parts) > 1 and value.endswith('.json')):
        _fail('vendor.selection')
    return parts


def _inventory(directory):
    found = set()
    pending = [directory]
    while pending:
        parent = pending.pop()
        if not stat.S_ISDIR(parent.lstat().st_mode):
            _fail('vendor.file_type')
        for child in parent.iterdir():
            mode = child.lstat().st_mode
            if stat.S_ISDIR(mode):
                pending.append(child)
            elif stat.S_ISREG(mode):
                found.add(child.relative_to(directory).as_posix())
                if len(found) > MAX_FILES:
                    _fail('source.budget')
            else:
                _fail('vendor.file_type')
    return found


def verify_vendor(root: Path) -> None:
    """Verify exact locked bytes, selection, pins and bounded local paths."""
    try:
        _verify_vendor(root)
    except OSError:
        _fail('vendor.io')


def _verify_vendor(root):
    lock = _json(_read(root / 'upstream.lock.json'))
    if not isinstance(lock, dict) or set(lock) != LOCK_KEYS:
        _fail('vendor.lock')
    expected = {'format': 1, 'release': '1.9.0', 'tag': '1.9.0', 'commit': COMMIT,
                'tree': TREE, 'repository': 'https://github.com/ocsf/ocsf-schema.git'}
    if type(lock['format']) is not int or any(lock[key] != value for key, value in expected.items()):
        _fail('vendor.pin')
    entries = lock['files']
    if not isinstance(entries, list) or not entries or len(entries) > MAX_FILES:
        _fail('vendor.lock')
    paths = []
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != FILE_KEYS:
            _fail('vendor.lock')
        _path(entry['path'])
        if type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= MAX_FILE_BYTES:
            _fail('source.budget')
        total += entry['bytes']
        if total > MAX_SOURCE_BYTES:
            _fail('source.budget')
        for key, length in (('git_blob', 40), ('sha256', 64)):
            if not isinstance(entry[key], str) or re.fullmatch('[0-9a-f]{' + str(length) + '}', entry[key]) is None:
                _fail('vendor.lock')
        paths.append(entry['path'])
    if paths != sorted(set(paths)) or not ROOT_FILES.issubset(paths):
        _fail('vendor.inventory')
    directory = root / 'upstream/1.9.0'
    if (root / 'upstream').is_symlink() or directory.is_symlink():
        _fail('vendor.file_type')
    if _inventory(directory) != set(paths):
        _fail('vendor.inventory')
    actual_total = 0
    for entry in entries:
        data = _read(directory / entry['path'])
        actual_total += len(data)
        if actual_total > MAX_SOURCE_BYTES:
            _fail('source.budget')
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()
        if len(data) != entry['bytes'] or blob != entry['git_blob'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            _fail('vendor.digest')
    if _json(_read(directory / 'version.json')) != {'version': '1.9.0'}:
        _fail('vendor.version')

# Only these annotations and structural keywords belong to compiled format 1.
KEYWORDS = set('$schema $id $defs $ref title description type properties required additionalProperties items minItems maxItems minLength maxLength minimum maximum enum const pattern allOf anyOf oneOf not if then else x-source x-restriction x-maxBytes x-integer x-sourceKind x-rule'.split())
RULES = ['type_uid', 'bundle_state', 'coverage', 'sequence_range', 'health_identity', 'pipeline_activity', 'policy_activity', 'certificate_activity', 'unmapped', 'truncation']
CLASS_IDS = [99901001, 99901002, 99901003, 99903001]
CLASS_SOURCES = {99901001: ['agent'], 99901002: ['agent', 'server'], 99901003: ['agent', 'server'], 99903001: ['server']}
SOURCE_KEYS = set('caption description name uid category extends profiles attributes constraints associations observable references @deprecated'.split())
ATTR_KEYS = set('caption description group requirement type is_array enum observable references @deprecated sibling source suppress_checks'.split())


def _strings(value):
    return isinstance(value, list) and all(type(x) is str for x in value)


def _metadata(value):
    for k in ('caption', 'description', 'name', 'group', 'sibling', 'source', 'type', 'extends', 'category'):
        if k in value and type(value[k]) is not str:
            _fail('source.metadata')
    if 'references' in value:
        if not isinstance(value['references'], list):
            _fail('source.references')
        for r in value['references']:
            if not isinstance(r, dict) or set(r) != {'description', 'url'} or any(type(x) is not str for x in r.values()):
                _fail('source.references')
    if '@deprecated' in value:
        d = value['@deprecated']
        if not isinstance(d, dict) or not {'since', 'message'} <= set(d) <= {'since', 'message', 'superseded_by'} or any(type(d[k]) is not str for k in ('since', 'message')) or ('superseded_by' in d and not _strings(d['superseded_by'])):
            _fail('source.deprecated')
    for k in ('uid', 'observable'):
        if k in value and (type(value[k]) is not int or value[k] < 0):
            _fail('source.metadata')


def check_attribute(v, numeric_enum=True):
    if not isinstance(v, dict) or set(v) - ATTR_KEYS:
        _fail('source.attribute')
    _metadata(v)
    if 'requirement' in v and v['requirement'] not in ('required', 'recommended', 'optional'):
        _fail('source.requirement')
    if 'is_array' in v and type(v['is_array']) is not bool:
        _fail('source.array')
    if 'suppress_checks' in v and not _strings(v['suppress_checks']):
        _fail('source.metadata')
    if 'enum' in v:
        if not isinstance(v['enum'], dict):
            _fail('source.enum')
        for k, e in v['enum'].items():
            if (numeric_enum and re.fullmatch('0|[1-9][0-9]*', k) is None) or not isinstance(e, dict) or not {'caption'} <= set(e) <= {'caption', 'description', 'references', '@deprecated'}:
                _fail('source.enum')
            _metadata(e)


def check_source(v, kind):
    allowed = SOURCE_KEYS | ({'meta', 'annotations'} if kind == 'profile' else set())
    if not isinstance(v, dict) or set(v) - allowed or not {'name', 'attributes'} <= set(v):
        _fail('source.root')
    _metadata(v)
    if '@deprecated' in v:
        _fail('source.deprecated')
    if kind == 'profile':
        if v.get('meta') != 'profile':
            _fail('source.profile')
        a = v.get('annotations', {})
        if not isinstance(a, dict) or set(a) - {'group'} or any(type(x) is not str for x in a.values()):
            _fail('source.annotations')
    if 'profiles' in v and not _strings(v['profiles']):
        _fail('source.profiles')
    if 'constraints' in v:
        c = v['constraints']
        if not isinstance(c, dict) or set(c) - {'at_least_one'} or ('at_least_one' in c and (not _strings(c['at_least_one']) or not c['at_least_one'])):
            _fail('source.constraints')
    if 'associations' in v and (not isinstance(v['associations'], dict) or any(not _strings(a) for a in v['associations'].values())):
        _fail('source.associations')
    if not isinstance(v['attributes'], dict):
        _fail('source.attributes')
    for k, a in v['attributes'].items():
        if k == '$include':
            if not _strings(a):
                _fail('source.include')
        elif a is not None:
            check_attribute(a)


class SourceResolver:
    """Resolve only local selected dependencies, parent first and host-only includes."""
    def __init__(self, root):
        self.root = root
        self.cache = {}
        self.active = set()
        self.dictionary = _json(_read(root / 'upstream/1.9.0/dictionary.json'))
        if set(self.dictionary) != {'caption', 'description', 'name', 'attributes', 'types'}:
            _fail('source.dictionary')
        _metadata(self.dictionary)
        for a in self.dictionary['attributes'].values():
            check_attribute(a, numeric_enum=False)
        types = self.dictionary['types']
        if set(types) - {'caption', 'description', 'attributes'}:
            _fail('source.types')
        for a in types['attributes'].values():
            if set(a) - (ATTR_KEYS | {'type_name', 'regex', 'range', 'values', 'max_len'}):
                _fail('source.type')
            _metadata(a)
        extension = _json(_read(root / 'extensions/ricevanta/dictionary.json'))
        if set(extension) != {'caption', 'description', 'name', 'attributes'}:
            _fail('source.dictionary')
        self.attributes = dict(self.dictionary['attributes'])
        for k, a in extension['attributes'].items():
            check_attribute(a)
            if k in self.attributes and (a.get('type'), a.get('is_array', False)) != (self.attributes[k].get('type'), self.attributes[k].get('is_array', False)):
                _fail('source.collision')
            self.attributes[k] = a

    def find(self, name, folder, upstream_only=False):
        candidates = []
        for base in (['upstream/1.9.0'] if upstream_only else ['extensions/ricevanta', 'upstream/1.9.0']):
            for p in (self.root / base / folder).rglob(name + '.json'):
                if p.stem == name:
                    candidates.append(p.relative_to(self.root).as_posix())
            if candidates:
                break
        if len(candidates) != 1:
            _fail('source.reference')
        return candidates[0]

    def resolve(self, path):
        parts = path.split('/')
        if any(p in ('', '.', '..') for p in parts) or '\\' in path or not path.startswith(('upstream/1.9.0/', 'extensions/ricevanta/')):
            _fail('source.path')
        if path in self.cache:
            return self.cache[path]
        if path in self.active or len(self.active) >= 64:
            _fail('source.cycle')
        self.active.add(path)
        try:
            v = _json(_read(self.root / path))
            kind = 'profile' if '/profiles/' in path else 'event' if '/events/' in path else 'object'
            check_source(v, kind)
            attrs, groups = {}, []
            if 'extends' in v:
                folder = 'events' if kind == 'event' else 'objects'
                parent = self.find(v['extends'], folder, v['extends'] == v['name'] or path.startswith('upstream/'))
                p = self.resolve(parent)
                attrs.update(p['attributes'])
                groups += p.get('groups', [])
            for inc in v['attributes'].get('$include', []):
                if inc.startswith('profiles/') and inc != 'profiles/host.json':
                    continue
                if not inc.startswith(('profiles/', 'includes/')):
                    _fail('source.include')
                p = self.resolve('upstream/1.9.0/' + inc)
                attrs.update(p['attributes'])
                groups += p.get('groups', [])
            for k, a in v['attributes'].items():
                if k == '$include':
                    continue
                if a is None or '@deprecated' in a:
                    if attrs.get(k, {}).get('requirement') == 'required':
                        _fail('source.required_removal')
                    attrs.pop(k, None)
                    continue
                merged = dict(self.attributes.get(k, {}), **attrs.get(k, {}))
                enums = dict(merged.get('enum', {}), **a.get('enum', {}))
                merged.update(a)
                if enums:
                    merged['enum'] = enums
                attrs[k] = merged
            if 'constraints' in v:
                groups.append(v['constraints']['at_least_one'])
            value = dict(v, attributes=attrs, groups=groups)
            self.cache[path] = value
            return value
        finally:
            self.active.remove(path)

    def primitive(self, name):
        seen = set()
        while name not in ('integer_t', 'long_t', 'timestamp_t', 'float_t', 'boolean_t', 'string_t', 'object'):
            if name in seen:
                _fail('source.cycle')
            seen.add(name)
            t = self.dictionary['types']['attributes'].get(name)
            if t is None:
                self.resolve(self.find(name, 'objects'))
                return 'object'
            name = t.get('type', 'string_t')
        return {'integer_t': 'integer', 'long_t': 'integer', 'timestamp_t': 'integer', 'float_t': 'number', 'boolean_t': 'boolean', 'string_t': 'string', 'object': 'object'}[name]


def _literal(value, depth=0):
    import math
    if depth > 64:
        _fail('schema.budget')
    if type(value) is str:
        try:
            value.encode('utf-8')
        except UnicodeError:
            _fail('schema.literal')
    elif type(value) is float:
        if not math.isfinite(value):
            _fail('schema.literal')
    elif type(value) in (int, bool):
        pass
    elif type(value) is list:
        for child in value:
            _literal(child, depth + 1)
    elif type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                _fail('schema.literal')
            _literal(key, depth + 1)
            _literal(child, depth + 1)
    else:
        _fail('schema.literal')


def check_schema(schema):
    """Check the closed grammar and local acyclic reference graph before use."""
    definitions = schema.get('$defs', {}) if isinstance(schema, dict) else {}
    if not isinstance(definitions, dict) or len(definitions) > 256:
        _fail('schema.definitions')
    nodes = 0
    refs = {}
    def walk(s, depth, owner):
        nonlocal nodes
        nodes += 1
        if depth > 64 or nodes > 4096:
            _fail('schema.budget')
        if not isinstance(s, dict) or set(s) - KEYWORDS:
            _fail('schema.keyword')
        if '$defs' in s and depth != 1:
            _fail('schema.definitions')
        if 'type' in s and s['type'] not in ('object', 'array', 'string', 'integer', 'number', 'boolean'):
            _fail('schema.type')
        if 'additionalProperties' in s and s['additionalProperties'] is not False:
            _fail('schema.open_object')
        for k in ('minItems', 'maxItems', 'minLength', 'maxLength', 'x-maxBytes'):
            if k in s and (type(s[k]) is not int or s[k] < (1 if k == 'x-maxBytes' else 0)):
                _fail('schema.bound')
        for k in ('minimum', 'maximum'):
            if k in s and type(s[k]) not in (int, float):
                _fail('schema.bound')
        for k in ('title', 'description', '$id', '$schema', 'x-source', 'x-restriction'):
            if k in s and type(s[k]) is not str:
                _fail('schema.annotation')
        if 'x-integer' in s and s['x-integer'] not in ('uint64', 'int64'):
            _fail('schema.integer')
        if 'x-sourceKind' in s and s['x-sourceKind'] not in ('agent', 'server'):
            _fail('schema.source')
        if 'required' in s and (not _strings(s['required']) or len(set(s['required'])) != len(s['required'])):
            _fail('schema.required')
        if 'enum' in s and (not isinstance(s['enum'], list) or not s['enum']):
            _fail('schema.enum')
        if 'const' in s:
            _literal(s['const'])
        if 'enum' in s:
            _literal(s['enum'])
        if 'x-rule' in s:
            rules = s['x-rule']
            if depth != 1 or not _strings(rules) or rules != [r for r in RULES if r in rules]:
                _fail('schema.rule')
        if 'pattern' in s:
            p = s['pattern']
            # Format 1 permits the reviewed pattern set, avoiding cross-runtime dialect drift.
            if p not in PATTERNS:
                _fail('schema.pattern')
        if '$ref' in s:
            ref = s['$ref']
            if not isinstance(ref, str) or not ref.startswith('#/$defs/') or ref[8:] not in definitions:
                _fail('schema.reference')
            refs.setdefault(owner, set()).add(ref[8:])
        for k in ('properties', '$defs'):
            if k in s:
                if not isinstance(s[k], dict):
                    _fail('schema.mapping')
                for n, child in s[k].items():
                    walk(child, depth + 1, n if k == '$defs' else owner)
        for k in ('items', 'not', 'if', 'then', 'else'):
            if k in s:
                walk(s[k], depth + 1, owner)
        for k in ('allOf', 'anyOf', 'oneOf'):
            if k in s:
                if not isinstance(s[k], list) or not s[k]:
                    _fail('schema.composition')
                for child in s[k]:
                    walk(child, depth + 1, owner)
    walk(schema, 1, '')
    active, done = set(), set()
    def visit(n):
        if n in active:
            _fail('schema.cycle')
        if n in done:
            return
        active.add(n)
        for child in refs.get(n, set()):
            visit(child)
        active.remove(n)
        done.add(n)
    for n in refs:
        visit(n)


PATTERNS = {
    r'^[^\x00-\x1f\x7f]+$', r'^[a-z][a-z0-9_.-]*$',
    r'^[0-9a-f]{64}$', r'^([0-9a-f]{2}){1,20}$',
    r'^[A-Za-z0-9_.:-]+$', r'^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$',
    r'^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$',
}


def _encode(v):
    return (json.dumps(v, sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def _bind(root, resolver, s, definitions, use=''):
    source = s.get('x-source')
    if source:
        if '#' not in source:
            _fail('binding.path')
        path, pointer = source.split('#', 1)
        if pointer == '':
            native = resolver.resolve(path)
            props, required = s.get('properties', {}), set(s.get('required', []))
            for key, a in native['attributes'].items():
                if a.get('requirement') == 'required' and key not in required:
                    _fail('binding.required')
            for group in native['groups']:
                if not required.intersection(group):
                    _fail('binding.constraint')
        else:
            if not pointer.startswith('/attributes/') or len(pointer.split('/')) != 3:
                _fail('binding.path')
            key = pointer.split('/')[-1]
            if path.endswith('/dictionary.json'):
                if path not in ('upstream/1.9.0/dictionary.json', 'extensions/ricevanta/dictionary.json'):
                    _fail('binding.path')
                a = resolver.attributes.get(key) if path.startswith('extensions/') else resolver.dictionary['attributes'].get(key)
            else:
                a = resolver.resolve(path)['attributes'].get(key)
            if a is None or 'type' not in a:
                _fail('binding.reference')
            is_array = a.get('is_array', False)
            if is_array != (s.get('type') == 'array'):
                _fail('binding.array')
            node = s['items'] if is_array else s
            if '$ref' in node and a['type'] != 'object' and node['$ref'][8:] != a['type']:
                _fail('binding.object')
            typ = definitions[node['$ref'][8:]]['type'] if '$ref' in node else node.get('type')
            if typ != resolver.primitive(a['type']):
                _fail('binding.type')
            if a['type'] == 'long_t' and node.get('x-integer') == 'uint64':
                if key != 'bytes' or use not in ('pipeline_activity.bytes', 'spool_sample.bytes') or 'x-restriction' not in s:
                    _fail('binding.unsigned')
            if a.get('enum'):
                values = node.get('enum', [node['const']] if 'const' in node else [])
                if any(str(x) not in a['enum'] for x in values):
                    _fail('binding.enum')
    for k, v in s.get('properties', {}).items():
        _bind(root, resolver, v, definitions, use.split('.')[0] + '.' + k)
    for k in ('items', 'not', 'if', 'then', 'else'):
        if k in s:
            _bind(root, resolver, s[k], definitions, use)
    for k in ('allOf', 'anyOf', 'oneOf'):
        for child in s.get(k, []):
            _bind(root, resolver, child, definitions, use)


def compile_profile(root: Path) -> dict[str, bytes]:
    try:
        return _compile_profile(root)
    except (OSError, KeyError, TypeError, UnicodeError, RecursionError):
        _fail('source.invalid')


def _compile_profile(root: Path) -> dict[str, bytes]:
    import copy
    verify_vendor(root)
    resolver = SourceResolver(root)
    extension = _json(_read(root / 'extensions/ricevanta/extension.json'))
    if set(extension) != {'caption', 'name', 'uid', 'version', 'description'} or extension['name'] != 'ricevanta' or type(extension['uid']) is not int or extension['uid'] != 999 or extension['version'] != '1.9.0':
        _fail('source.extension')
    p = _json(_read(root / 'profile.json'))
    if not isinstance(p, dict) or set(p) != {'format', 'profile', 'classes', 'objects'} or type(p['format']) is not int or p['format'] != 1 or p['profile'] != 'ricevanta-ocsf-1':
        _fail('profile.root')
    if not isinstance(p['classes'], list) or [c.get('class_uid') for c in p['classes']] != CLASS_IDS or not isinstance(p['objects'], dict):
        _fail('profile.classes')
    inputs = ['upstream.lock.json', 'limits.yaml', 'profile.json']
    inputs += ['upstream/1.9.0/' + e['path'] for e in _json(_read(root / 'upstream.lock.json'))['files']]
    inputs += [f.relative_to(root).as_posix() for f in (root / 'extensions/ricevanta').rglob('*.json')]
    if len(inputs) > MAX_FILES or sum(len(_read(root / n)) for n in inputs) > MAX_SOURCE_BYTES:
        _fail('source.budget')
    h = hashlib.sha256()
    for name in sorted(inputs):
        h.update(name.encode() + b'\0' + hashlib.sha256(_read(root / name)).hexdigest().encode() + b'\n')
    # Other limits name deferred classes or CEL inputs and remain unchanged.
    limits = _read(root / 'limits.yaml').decode('utf-8')
    for key, expected in [('device.labels', 32), ('device.groups', 64), ('unmapped', 32768)]:
        match = re.search(r'^  ' + re.escape(key) + r': ([0-9]+)(?: +#.*)?$', limits, re.MULTILINE)
        if not match or int(match[1]) != expected:
            _fail('profile.limits')
    def data_bindings(node):
        if 'x-source' not in node or node.get('type') != 'object' or node.get('additionalProperties') is not False:
            _fail('binding.root')
        for value in node.get('properties', {}).values():
            if 'x-source' not in value:
                _fail('binding.missing')
    for name, node in p['objects'].items():
        data_bindings(node)
        _bind(root, resolver, node, p['objects'], name)
    outputs, classes = {}, []
    for c in p['classes']:
        if set(c) != {'name', 'local_uid', 'category_uid', 'class_uid', 'source_kinds', 'schema'} or c['class_uid'] != 99900000 + c['category_uid'] * 1000 + c['local_uid'] or c['source_kinds'] != [s for s in ['agent', 'server'] if s in c['source_kinds']]:
            _fail('profile.class')
        data_bindings(c['schema'])
        expected_rules = ['type_uid', 'bundle_state']
        if c['class_uid'] == 99901001:
            expected_rules += ['coverage', 'health_identity']
        elif c['class_uid'] == 99901002:
            expected_rules += ['policy_activity']
        elif c['class_uid'] == 99901003:
            expected_rules += ['sequence_range', 'pipeline_activity']
        else:
            expected_rules += ['certificate_activity']
        if c['schema'].get('x-rule') != expected_rules + ['unmapped', 'truncation']:
            _fail('profile.rules')
        s = copy.deepcopy(c['schema'])
        s.update({'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'https://ricevanta.io/schemas/ocsf/compiled/' + str(c['class_uid']) + '.schema.json', '$defs': p['objects']})
        check_schema(s)
        native = resolver.resolve(s['x-source'].split('#')[0])
        if native['name'] != c['name'].split('/')[1] or native['uid'] != c['local_uid'] or native['category'] != ('system' if c['category_uid'] == 1 else 'iam'):
            _fail('binding.class')
        _bind(root, resolver, s, p['objects'], native['name'])
        if c['source_kinds'] != CLASS_SOURCES[c['class_uid']] or [b.get('x-sourceKind') for b in s.get('anyOf', [])] != c['source_kinds']:
            _fail('binding.sources')
        # Host-profile requirements are narrowed by every agent branch.
        agent = [b for b in s.get('anyOf', []) if b.get('x-sourceKind') == 'agent']
        if 'agent' in c['source_kinds'] and (len(agent) != 1 or 'device' not in agent[0].get('required', [])):
            _fail('binding.host')
        data = _encode(s)
        if len(data) > MAX_FILE_BYTES:
            _fail('schema.budget')
        path = 'compiled/' + str(c['class_uid']) + '.schema.json'
        outputs[path] = data
        classes.append({'class_uid': c['class_uid'], 'path': path.split('/')[1], 'sha256': hashlib.sha256(data).hexdigest()})
    outputs['compiled/manifest.json'] = _encode({'format': 1, 'profile': p['profile'], 'upstream_commit': COMMIT, 'inputs_sha256': h.hexdigest(), 'classes': classes})
    if sum(map(len, outputs.values())) > 8388608:
        _fail('schema.budget')
    for path, data in list(outputs.items()):
        outputs['server/internal/events/ocsf/schema/' + path.split('/')[1]] = data
    return outputs


def _output_path(root, name):
    return root.parents[1] / name if name.startswith('server/') else root / name


def check_outputs(root: Path, outputs: dict[str, bytes]) -> None:
    for folder in (root / 'compiled', root.parents[1] / 'server/internal/events/ocsf/schema'):
        wanted = { _output_path(root, n) for n in outputs if _output_path(root, n).parent == folder }
        if not folder.is_dir() or set(folder.iterdir()) != wanted:
            _fail('output.inventory')
    for name, data in outputs.items():
        if _read(_output_path(root, name)) != data:
            _fail('output.drift')


def main():
    import argparse
    import os
    import tempfile
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    outputs = compile_profile(root)
    if args.check:
        check_outputs(root, outputs)
    else:
        for name, data in outputs.items():
            path = _output_path(root, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
                f.write(data)
                temporary = f.name
            os.replace(temporary, path)
        check_outputs(root, outputs)
    print('OCSF pinned sources and 4 compiled schemas verified')


if __name__ == '__main__':
    main()
