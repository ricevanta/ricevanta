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
            attrs, groups, required = {}, [], set()
            if 'extends' in v:
                folder = 'events' if kind == 'event' else 'objects'
                parent = self.find(v['extends'], folder, v['extends'] == v['name'] or path.startswith('upstream/'))
                p = self.resolve(parent)
                attrs.update(p['attributes'])
                required.update(p['required_attributes'])
                groups += p.get('groups', [])
            for inc in v['attributes'].get('$include', []):
                if inc.startswith('profiles/') and inc != 'profiles/host.json':
                    continue
                if not inc.startswith(('profiles/', 'includes/')):
                    _fail('source.include')
                p = self.resolve('upstream/1.9.0/' + inc)
                attrs.update(p['attributes'])
                required.update(p['required_attributes'])
                groups += p.get('groups', [])
            for k, a in v['attributes'].items():
                if k == '$include':
                    continue
                if a is None or '@deprecated' in a:
                    if k in required or attrs.get(k, {}).get('requirement') == 'required':
                        _fail('source.required_removal')
                    attrs.pop(k, None)
                    continue
                merged = dict(self.attributes.get(k, {}), **attrs.get(k, {}))
                enums = dict(merged.get('enum', {}), **a.get('enum', {}))
                merged.update(a)
                if enums:
                    merged['enum'] = enums
                attrs[k] = merged
                if merged.get('requirement') == 'required':
                    required.add(k)
            if 'constraints' in v:
                groups.append(v['constraints']['at_least_one'])
            value = dict(v, attributes=attrs, groups=groups, required_attributes=required)
            self.cache[path] = value
            return value
        finally:
            self.active.remove(path)

    def primitive(self, name):
        seen = set()
        while name not in ('integer_t', 'long_t', 'float_t', 'boolean_t', 'string_t', 'object'):
            if name in seen:
                _fail('source.cycle')
            seen.add(name)
            t = self.dictionary['types']['attributes'].get(name)
            if t is None:
                self.resolve(self.find(name, 'objects'))
                return 'object'
            name = t.get('type', 'string_t')
        return {'integer_t': 'integer', 'long_t': 'integer', 'float_t': 'number', 'boolean_t': 'boolean', 'string_t': 'string', 'object': 'object'}[name]

    def integer_bounds(self, name):
        """Intersect native ranges along the type chain, including signed long width."""
        seen, ranges = set(), []
        while name not in seen:
            seen.add(name)
            if name == 'long_t':
                ranges.append((-2**63, 2**63 - 1))
            node = self.dictionary['types']['attributes'].get(name, {})
            if 'range' in node:
                ranges.append(tuple(node['range']))
            if 'type' not in node:
                break
            name = node['type']
        else:
            _fail('source.cycle')
        if not ranges:
            return None
        return max(low for low, _ in ranges), min(high for _, high in ranges), 'long_t' in seen


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


COMPOSITION = set('allOf anyOf oneOf not if then else'.split())
ROOT_KEYWORDS = set('type properties required additionalProperties title description x-source'.split()) | COMPOSITION
TYPE_KEYWORDS = {
    'string': set('minLength maxLength pattern x-maxBytes'.split()),
    'integer': set('minimum maximum x-integer'.split()),
    'number': {'minimum', 'maximum'},
    'boolean': set(),
    'array': {'items', 'minItems', 'maxItems'},
}


def _check_node_grammar(s, kind, compiled=False):
    """Reject misplaced keywords before resolving any native binding."""
    if not isinstance(s, dict):
        _fail('schema.grammar.' + kind + ':node')
    if kind in ('class', 'definition'):
        allowed = ROOT_KEYWORDS | ({'x-rule'} if kind == 'class' else set())
        if compiled and kind == 'class':
            allowed |= {'$schema', '$id', '$defs'}
    elif '$ref' in s:
        kind, allowed = 'reference', {'$ref', 'x-source'}
    elif 'type' in s:
        typ = s['type']
        if not isinstance(typ, str) or typ not in TYPE_KEYWORDS:
            _fail('schema.grammar.' + kind + ':type')
        kind = typ
        allowed = {'type', 'x-source', 'x-restriction'} | COMPOSITION | TYPE_KEYWORDS[typ]
        if typ != 'array':
            allowed |= {'enum', 'const'}
    elif kind == 'fragment':
        allowed = COMPOSITION | {'enum', 'const'}
        groups = [
            ('object_fragment', {'properties', 'required', 'x-sourceKind'}),
            ('string_fragment', TYPE_KEYWORDS['string']),
            ('number_fragment', TYPE_KEYWORDS['integer']),
            ('array_fragment', TYPE_KEYWORDS['array']),
        ]
        selected = [(name, keys) for name, keys in groups if set(s) & keys]
        if len(selected) > 1:
            _fail('schema.grammar.fragment:mixed_keywords')
        if selected:
            kind, keys = selected[0]
            allowed |= keys
            if kind in ('object_fragment', 'array_fragment'):
                allowed -= {'enum', 'const'}
    else:
        _fail('schema.grammar.' + kind + ':type')
    extra = sorted(set(s) - allowed)
    if extra:
        _fail('schema.grammar.' + kind + ':' + extra[0])
    if kind in ('class', 'definition') and s.get('type') != 'object':
        _fail('schema.grammar.' + kind + ':type')
    if s.get('type') == 'array' and 'items' not in s:
        _fail('schema.grammar.array:items')


def check_schema(schema, *, root_kind=None, definitions=None, compiled=True):
    """Check the closed grammar and local acyclic reference graph before use."""
    if definitions is None:
        definitions = schema.get('$defs', {}) if isinstance(schema, dict) else {}
    if root_kind is None:
        root_kind = 'class' if isinstance(schema, dict) and schema.get('type') == 'object' else 'fragment'
    if not isinstance(definitions, dict) or len(definitions) > 256:
        _fail('schema.definitions')
    nodes = 0
    refs = {}
    def walk(s, depth, owner, kind):
        nonlocal nodes
        nodes += 1
        if depth > 64 or nodes > 4096:
            _fail('schema.budget')
        _check_node_grammar(s, kind, compiled and depth == 1)
        if '$defs' in s and depth != 1:
            _fail('schema.definitions')
        if 'type' in s and s['type'] not in ('object', 'array', 'string', 'integer', 'number', 'boolean'):
            _fail('schema.type')
        if s.get('type') == 'object' and s.get('additionalProperties') is not False:
            _fail('schema.open_object')
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
                    child_kind = 'definition' if k == '$defs' else ('fragment' if kind == 'fragment' else 'attribute')
                    walk(child, depth + 1, n if k == '$defs' else owner, child_kind)
        for k in ('items', 'not', 'if', 'then', 'else'):
            if k in s:
                walk(s[k], depth + 1, owner, 'item' if k == 'items' else 'fragment')
        for k in ('allOf', 'anyOf', 'oneOf'):
            if k in s:
                if not isinstance(s[k], list) or not s[k]:
                    _fail('schema.composition')
                for child in s[k]:
                    walk(child, depth + 1, owner, 'fragment')
    walk(schema, 1, '', root_kind)
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


def _binding_source(s, kind):
    if 'x-source' not in s:
        if kind is not None:
            _fail('binding.missing')
        return None
    source = s.get('x-source')
    if type(source) is not str:
        _fail('binding.path')
    if not source:
        _fail('binding.empty')
    if source.count('#') != 1:
        _fail('binding.path')
    path, pointer = source.split('#')
    if kind in ('object', 'class'):
        folder = 'objects' if kind == 'object' else 'events'
        if pointer or not any(path.startswith(base + '/' + folder + '/')
                              for base in ('upstream/1.9.0', 'extensions/ricevanta')):
            _fail('binding.kind')
    else:
        if not pointer:
            _fail('binding.kind')
        if not pointer.startswith('/attributes/') or len(pointer.split('/')) != 3:
            _fail('binding.path')
        if not any(path == base + '/dictionary.json' or
                   path.startswith((base + '/objects/', base + '/events/'))
                   for base in ('upstream/1.9.0', 'extensions/ricevanta')):
            _fail('binding.kind')
    return source


def _root_binding(resolver, s, name, kind):
    source = _binding_source(s, kind)
    folder = 'events' if kind == 'class' else 'objects'
    path = source.split('#')[0]
    if path != resolver.find(name, folder):
        _fail('binding.root')
    native = resolver.resolve(path)
    if native['name'] != name:
        _fail('binding.root')
    return native


def _bind(root, resolver, s, definitions, use='', native_attribute=None, kind=None,
          native_object=None, fragment=False, array_item=False,
          projection=None, data_field=None):
    node_kind = ('definition' if kind == 'object' else 'class' if kind == 'class'
                 else 'fragment' if fragment else 'item' if array_item else 'attribute')
    _check_node_grammar(s, node_kind, compiled=kind == 'class')
    # References belong to fields and array items, never to a data definition.
    if '$ref' in s and (kind in ('object', 'class') or
                       (native_object is not None and native_attribute is None)):
        _fail('binding.definition_reference')
    if kind not in ('object', 'class') and s.get('type') == 'object':
        _fail('binding.object_reference')
    native = native_object
    if kind in ('object', 'class'):
        projection = s
    a = native_attribute
    key = use.rsplit('.', 1)[-1]
    source = _binding_source(s, kind)
    if source is not None:
        path, pointer = source.split('#', 1)
        if pointer == '':
            native = _root_binding(resolver, s, use.split('.')[0], kind)
            props, required = s.get('properties', {}), set(s.get('required', []))
            if not native['required_attributes'] <= required.intersection(props):
                _fail('binding.required')
            if set(props) - set(native['attributes']):
                _fail('binding.reference')
            for group in native['groups']:
                if not required.intersection(group):
                    _fail('binding.constraint')
        else:
            if not pointer.startswith('/attributes/') or len(pointer.split('/')) != 3:
                _fail('binding.path')
            key = pointer.split('/')[-1]
            if key != use.rsplit('.', 1)[-1]:
                _fail('binding.attribute')
            if path.endswith('/dictionary.json'):
                if path not in ('upstream/1.9.0/dictionary.json', 'extensions/ricevanta/dictionary.json'):
                    _fail('binding.path')
                a = resolver.attributes.get(key) if path.startswith('extensions/') else resolver.dictionary['attributes'].get(key)
            else:
                a = resolver.resolve(path)['attributes'].get(key)
            if a is None or 'type' not in a:
                _fail('binding.reference')
            if native_attribute is not None:
                for field, default in (('type', None), ('is_array', False), ('enum', None)):
                    if a.get(field, default) != native_attribute.get(field, default):
                        _fail('binding.attribute')
    if native is not None and a is None:
        if ('type' in s and s['type'] != 'object') or set(s) & set().union(*TYPE_KEYWORDS.values()):
            _fail('binding.type')
        if 'enum' in s or 'const' in s:
            _fail('binding.literal_type')
    if a is not None:
        is_array = a.get('is_array', False) and not array_item
        if (not fragment or 'type' in s) and is_array != (s.get('type') == 'array'):
            _fail('binding.array')
        if is_array and ('const' in s or 'enum' in s):
            _fail('binding.literal_type')
        node = s.get('items', {}) if is_array else s
        expected = resolver.primitive(a['type'])
        outer_type = 'array' if is_array else expected
        constraint_keys = set().union(*TYPE_KEYWORDS.values()) | {'properties', 'required', 'x-sourceKind'}
        allowed_constraints = (TYPE_KEYWORDS.get(outer_type, set()) if outer_type != 'object'
                               else {'properties', 'required', 'x-sourceKind'})
        if (set(s) & constraint_keys) - allowed_constraints:
            _fail('binding.type')
        # Data projections must use named objects; constraint fragments may omit a type.
        if expected == 'object' and (not fragment or 'type' in node or '$ref' in node):
            if '$ref' not in node:
                _fail('binding.object_reference')
        if '$ref' in node and a['type'] != 'object' and node['$ref'][8:] != a['type']:
            _fail('binding.object')
        if 'type' in node and node['type'] != expected:
            _fail('binding.type')
        typ = definitions[node['$ref'][8:]]['type'] if '$ref' in node else node.get('type')
        if (not fragment or typ is not None) and typ != expected:
            _fail('binding.type')
        bounds = resolver.integer_bounds(a['type']) if expected == 'integer' else None
        if bounds is not None:
            low, high, signed_long = bounds
            unsigned_override = (a['type'] == 'long_t' and key == 'bytes'
                                 and use in ('pipeline_activity.bytes', 'spool_sample.bytes')
                                 and s.get('x-source') == 'upstream/1.9.0/dictionary.json#/attributes/bytes'
                                 and bool(s.get('x-restriction'))
                                 and node.get('x-integer') == 'uint64')
            if unsigned_override:
                low, high = 0, 2**64 - 1
            values = [node[k] for k in ('minimum', 'maximum', 'const') if k in node]
            values += node.get('enum', [])
            if (any(type(value) is not int or not low <= value <= high for value in values)
                    or (not fragment and any(k not in node for k in ('minimum', 'maximum')))
                    or node.get('minimum', low) > node.get('maximum', high)):
                _fail('binding.integer_range')
            if signed_long and node.get('x-integer') == 'uint64' and not unsigned_override:
                _fail('binding.unsigned')
        if a.get('enum') and (not fragment or 'enum' in node or 'const' in node):
            values = node.get('enum', []) + ([node['const']] if 'const' in node else [])
            if not values:
                low, high = node.get('minimum'), node.get('maximum')
                if typ != 'integer' or type(low) is not int or type(high) is not int or not 0 <= high - low < len(a['enum']):
                    _fail('binding.enum')
                values = range(low, high + 1)
            if not values or any(type(x) is not int or str(x) not in a['enum'] for x in values):
                _fail('binding.enum')
        literal_types = {'string': (str,), 'integer': (int,), 'number': (int, float),
                         'boolean': (bool,)}
        values = ([node['const']] if 'const' in node else []) + node.get('enum', [])
        if any(type(value) not in literal_types.get(expected, ()) for value in values):
            _fail('binding.literal_type')
        if expected == 'object' and not is_array:
            # Generic objects inherit the native context of the selected data projection.
            selected = data_field if data_field is not None else s
            ref = selected.get('$ref')
            if ref is not None:
                projection = definitions[ref[8:]]
                native = _root_binding(resolver, projection, ref[8:], 'object')
            elif a['type'] != 'object':
                native = resolver.resolve(resolver.find(a['type'], 'objects'))
    if '$ref' in s and native is None:
        definition = definitions[s['$ref'][8:]]
        native = _root_binding(resolver, definition, s['$ref'][8:], 'object')
        projection = definition
    for k, v in s.get('properties', {}).items():
        attribute = native['attributes'].get(k) if native is not None else None
        if native is not None and attribute is None:
            _fail('binding.reference')
        # Conditional fragments constrain fields already bound by the data definition.
        child_kind = 'attribute' if kind is not None else None
        _bind(root, resolver, v, definitions, use.split('.')[0] + '.' + k,
              attribute, child_kind, fragment=fragment,
              data_field=projection.get('properties', {}).get(k) if projection is not None else None)
    if 'items' in s:
        _bind(root, resolver, s['items'], definitions, use, a,
              fragment=fragment, array_item=True,
              data_field=(data_field or s).get('items'))
    for k in ('not', 'if', 'then', 'else'):
        if k in s:
            _bind(root, resolver, s[k], definitions, use, a,
                  native_object=native, fragment=True, array_item=array_item,
                  projection=projection, data_field=data_field)
    for k in ('allOf', 'anyOf', 'oneOf'):
        for child in s.get(k, []):
            _bind(root, resolver, child, definitions, use, a,
                  native_object=native, fragment=True, array_item=array_item,
                  projection=projection, data_field=data_field)


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
    for node in p['objects'].values():
        check_schema(node, root_kind='definition', definitions=p['objects'], compiled=False)
    for c in p['classes']:
        check_schema(c['schema'], root_kind='class', definitions=p['objects'], compiled=False)
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
    def data_bindings(node, name, kind):
        native = _root_binding(resolver, node, name, kind)
        if node.get('type') != 'object' or node.get('additionalProperties') is not False:
            _fail('binding.root')
        for value in node.get('properties', {}).values():
            _binding_source(value, 'attribute')
        return native
    for name, node in p['objects'].items():
        data_bindings(node, name, 'object')
        _bind(root, resolver, node, p['objects'], name, kind='object')
    outputs, classes = {}, []
    for c in p['classes']:
        if set(c) != {'name', 'local_uid', 'category_uid', 'class_uid', 'source_kinds', 'schema'} or c['class_uid'] != 99900000 + c['category_uid'] * 1000 + c['local_uid'] or c['source_kinds'] != [s for s in ['agent', 'server'] if s in c['source_kinds']]:
            _fail('profile.class')
        native = data_bindings(c['schema'], c['name'].split('/')[1], 'class')
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
        if native['name'] != c['name'].split('/')[1] or native['uid'] != c['local_uid'] or native['category'] != ('system' if c['category_uid'] == 1 else 'iam'):
            _fail('binding.class')
        _bind(root, resolver, s, p['objects'], native['name'], kind='class')
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
