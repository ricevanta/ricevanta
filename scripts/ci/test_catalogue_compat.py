"""Catalogue compatibility reads reviewed base and candidate objects from Git."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

import check_policy
import inventory

ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = 'schemas/permissions/v1/catalogue.json'
SCHEMA = 'schemas/permissions/v1/catalogue.schema.json'
EMBEDDED = 'server/internal/authz/catalogue/catalogue.json'
PROBE = 'mdm.commands.restart'
COMMAND = 'python -B scripts/ci/catalogue_compat.py --root . --base-sha "$BASE_SHA" --candidate-sha "$CANDIDATE_SHA"'
TOMBSTONE = PROBE + ': tombstone changed; retired rows keep all metadata and retired_in'


def entry(cat, name):
    return next(p for p in cat['permissions'] if p['name'] == name)


def new_entry(introduced, **fields):
    row = {'name': 'mdm.devices.test', 'owner': 'mdm', 'scope': 'device_group', 'protection': 'none',
           'approval': 'none', 'rule': 'none', 'grant': 'role', 'status': 'active', 'introduced': introduced,
           'uses': ['api:test-device'], 'source': 'docs/design/mdm.md#8', 'note': 'Fixture entry.'}
    row.update(fields)
    return row


def add(cat, row):
    cat['permissions'].append(row)
    cat['permissions'].sort(key=lambda p: p['name'])


def weakened_schema(schema):
    """A PR-controlled schema that drops closed members, bounds, grammar and grant rules."""
    weak = copy.deepcopy(schema)
    weak['additionalProperties'] = True
    weak['properties']['revision'] = {'type': 'integer'}
    weak['properties']['permissions'] = {'type': 'array', 'items': {'$ref': '#/$defs/permission'}}
    permission = weak['$defs']['permission']
    permission['additionalProperties'] = True
    permission['required'] = ['name']
    for field in ('introduced', 'retired_in'):
        permission['properties'][field] = {'type': 'integer'}
    for field in ('owner', 'scope', 'protection', 'approval', 'rule', 'grant', 'status', 'source', 'note'):
        permission['properties'][field] = {'type': 'string'}
    permission['properties']['uses'] = {}
    del permission['allOf']
    weak['$defs']['name'] = {'type': 'string'}
    return weak


class CatalogueCompatTests(unittest.TestCase):
    def setUp(self):
        import catalogue_compat
        self.compat = catalogue_compat
        self.tmp = tempfile.TemporaryDirectory(prefix='ci-catalogue-compat-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-b', 'master')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        self.schema_bytes = (ROOT / SCHEMA).read_bytes()
        self.schema = json.loads(self.schema_bytes)
        self.catalogue_bytes = (ROOT / CATALOGUE).read_bytes()
        self.catalogue = json.loads(self.catalogue_bytes)
        # Fixture revisions and the probe's current scope come from the live catalogue.
        self.rb = self.catalogue['revision']
        self.rc = self.rb + 1
        probe = entry(self.catalogue, PROBE)
        self.assertEqual(probe['status'], 'active')
        self.scope = probe['scope']
        self.other_scope = 'organization' if self.scope == 'device_group' else 'device_group'
        self.write(SCHEMA, self.schema_bytes)
        self.write('README.md', b'fixture\n')
        self.base = self.commit(self.catalogue_bytes)

    def git(self, *args, data=None):
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        return subprocess.run(['git', '-c', 'core.excludesFile=' + os.devnull, '-C', str(self.root), *args],
                              env=env, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True).stdout.decode().strip()

    def write(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def encode(self, value):
        return value if isinstance(value, bytes) else (json.dumps(value, indent=1) + '\n').encode()

    def commit(self, catalogue=None, schema=None):
        """Commit catalogue bytes (or a decoded catalogue) into both canonical and embedded copies."""
        if catalogue is not None:
            self.write(CATALOGUE, self.encode(catalogue))
            self.write(EMBEDDED, self.encode(catalogue))
        if schema is not None:
            self.write(SCHEMA, self.encode(schema))
        self.git('add', '-A', '.')
        self.git('commit', '-q', '--allow-empty', '-m', 'Fixture')
        return self.git('rev-parse', 'HEAD')

    def commit_mode(self, mode, data=None, oid=None, path=CATALOGUE):
        """Record an index entry of an arbitrary Git mode without using host filesystem features."""
        if oid is None:
            oid = self.git('hash-object', '-w', '--stdin', data=data)
        self.git('update-index', '--add', '--cacheinfo', f'{mode},{oid},{path}')
        self.git('commit', '-q', '-m', 'Mode fixture')
        head = self.git('rev-parse', 'HEAD')
        self.assertTrue(self.git('ls-tree', head, '--', path).startswith(mode + ' '))
        self.git('read-tree', '-q', '--reset', self.base)
        return head

    def changed(self, change, revision=None):
        cat = copy.deepcopy(self.catalogue)
        cat['revision'] = self.rc if revision is None else revision
        change(cat)
        return cat

    def compare(self, base, candidate):
        return self.compat.compare(self.root, base, candidate)

    def reject(self, base, candidate, *fragments):
        with self.assertRaises(ValueError) as caught:
            self.compare(base, candidate)
        message = str(caught.exception)
        for fragment in fragments:
            self.assertIn(fragment, message)
        return message

    def test_identical_bytes_and_revision_only_increase_pass(self):
        head = self.commit()
        report = self.compare(self.base, head)
        self.assertEqual((report['base']['sha'], report['candidate']['sha']), (self.base, head))
        self.assertEqual((report['base']['revision'], report['candidate']['revision']), (self.rb, self.rb))
        self.assertEqual(report['base']['blob'], report['candidate']['blob'])
        self.assertEqual(report['base']['blob'], self.git('rev-parse', self.base + ':' + CATALOGUE))
        self.assertEqual(report['base']['schema'], self.git('rev-parse', self.base + ':' + SCHEMA))
        self.assertTrue(report['unchanged'])
        self.assertFalse(report['schema_changed'])
        head = self.commit(self.changed(lambda cat: None))
        report = self.compare(self.base, head)
        self.assertEqual(report['candidate']['revision'], self.rc)
        self.assertFalse(report['unchanged'])

    def test_formatting_and_member_order_keep_revision(self):
        reordered = {'permissions': [dict(reversed(list(p.items()))) for p in self.catalogue['permissions']],
                     'revision': self.rb, 'format_version': 1}
        head = self.commit((json.dumps(reordered, indent=4, separators=(' , ', ' : ')) + '\n\n').encode())
        report = self.compare(self.base, head)
        self.assertFalse(report['unchanged'])
        self.assertEqual(report['candidate']['revision'], self.rb)

    def test_note_source_new_name_retirement_and_uses_order(self):
        def note(cat):
            entry(cat, PROBE)['note'] = 'Corrected wording.'
            entry(cat, PROBE)['source'] = 'docs/design/mdm.md#8.1'
        def new_name(cat):
            add(cat, new_entry(self.rc))
        def retire(cat):
            entry(cat, PROBE).update(status='retired', retired_in=self.rc)
        def uses_reordered(cat):
            row = entry(cat, 'audit.events.export')
            self.assertGreater(len(row['uses']), 1)
            row['uses'].reverse()
        for change in (note, new_name, retire, uses_reordered):
            with self.subTest(change=change.__name__):
                head = self.commit(self.changed(change))
                self.assertEqual(self.compare(self.base, head)['candidate']['revision'], self.rc)
        head = self.commit(self.changed(retire, revision=self.rc + 1))
        self.assertEqual(self.compare(self.base, head)['candidate']['revision'], self.rc + 1)
        # A uses reorder is decoded content, so it needs the revision increase; it is not semantic.
        head = self.commit(self.changed(uses_reordered, revision=self.rb))
        message = self.reject(self.base, head, 'without a revision increase')
        self.assertNotIn('uses changed', message)

    def test_audit_probe_scope_change_at_base_revision_is_rejected(self):
        def probe(cat):
            entry(cat, PROBE)['scope'] = self.other_scope
        head = self.commit(self.changed(probe, revision=self.rb))
        # Both repository copies carry the mutated bytes; compatibility still fails.
        self.assertEqual((self.root / CATALOGUE).read_bytes(), (self.root / EMBEDDED).read_bytes())
        message = self.reject(self.base, head, PROBE + ': scope changed from', repr(self.scope), repr(self.other_scope),
                              'without a revision increase')
        self.assertIn(self.base, message)
        head = self.commit(self.changed(probe))
        message = self.reject(self.base, head, PROBE + ': scope changed from', repr(self.other_scope))
        self.assertNotIn('without a revision increase', message)

    def test_semantic_field_changes_fail_with_bumped_revision(self):
        def delete(cat):
            cat['permissions'] = [p for p in cat['permissions'] if p['name'] != PROBE]
        def approval(cat):
            entry(cat, PROBE).update(rule='always', protection='always', approval='access_policy')
        def owner(cat):
            entry(cat, PROBE)['owner'] = 'devices'
        def uses_added(cat):
            entry(cat, PROBE)['uses'].append('api:restart-device')
        def uses_replaced(cat):
            entry(cat, PROBE)['uses'] = ['createDeviceAction#reboot']
        def introduced(cat):
            entry(cat, PROBE)['introduced'] = self.rc
        def stale_introduced(cat):
            add(cat, new_entry(self.rb))
        def stale_retirement(cat):
            entry(cat, PROBE).update(status='retired', retired_in=self.rb)
        cases = ((delete, PROBE + ': deleted'), (approval, PROBE + ': rule changed from'),
                 (owner, PROBE + ': owner changed from'), (uses_added, PROBE + ': uses changed'),
                 (uses_replaced, PROBE + ': uses changed'), (introduced, PROBE + ': introduced changed from'),
                 (stale_introduced, f'mdm.devices.test: new name introduced {self.rb} must exceed base revision {self.rb}'),
                 (stale_retirement, f'{PROBE}: retired_in {self.rb} must exceed base revision {self.rb}'))
        for change, fragment in cases:
            with self.subTest(change=change.__name__):
                head = self.commit(self.changed(change))
                self.reject(self.base, head, fragment)

    def test_defects_cover_grant_window_tombstones_and_schema_change_directly(self):
        """Rules the v1 schema also rejects keep their own lifecycle defect text."""
        rb, rc = self.rb, self.rc
        defects = self.compat.defects
        candidate = self.changed(lambda cat: entry(cat, PROBE).update(grant='direct'))
        self.assertEqual(defects(self.catalogue, candidate),
                         [f"{PROBE}: grant changed from 'role' to 'direct'; introduce a new name"])
        window = 'mdm.devices.test: new name introduced {} must exceed base revision %d and not exceed %d' % (rb, rc)
        for introduced in (rb, rc + 1):
            candidate = self.changed(lambda cat: add(cat, new_entry(introduced)))
            self.assertEqual(defects(self.catalogue, candidate), [window.format(introduced)])
        self.assertEqual(defects(self.catalogue, self.changed(lambda cat: add(cat, new_entry(rc)))), [])
        retired = self.changed(lambda cat: entry(cat, PROBE).update(status='retired', retired_in=rc))
        self.assertEqual(defects(self.catalogue, retired), [])
        for change in ({'note': 'Edited tombstone.'}, {'retired_in': rc + 1}, {'scope': self.other_scope},
                       {'status': 'active'}):
            cat = copy.deepcopy(retired)
            cat['revision'] = rc + 1
            entry(cat, PROBE).update(change)
            if change == {'status': 'active'}:
                del entry(cat, PROBE)['retired_in']
            self.assertEqual(defects(retired, cat), [TOMBSTONE])
        self.assertEqual(defects(self.catalogue, self.changed(lambda cat: None, revision=rb - 1)),
                         [f'revision decreased from {rb} to {rb - 1}'])
        self.assertEqual(defects(self.catalogue, self.catalogue, schema_changed=True),
                         [f'schema changed without a revision increase (revision {rb}); a validation contract change must be explicit'])
        self.assertEqual(defects(self.catalogue, self.changed(lambda cat: None), schema_changed=True), [])

    def test_tombstone_mutation_and_resurrection_fail(self):
        retired = self.commit(self.changed(lambda cat: entry(cat, PROBE).update(status='retired', retired_in=self.rc)))
        self.compare(self.base, retired)
        retired_cat = json.loads((self.root / CATALOGUE).read_bytes())
        def mutate(cat):
            entry(cat, PROBE)['note'] = 'Edited tombstone.'
        def later(cat):
            entry(cat, PROBE)['retired_in'] = self.rc + 1
        def resurrect(cat):
            entry(cat, PROBE)['status'] = 'active'
            del entry(cat, PROBE)['retired_in']
        for change in (mutate, later, resurrect):
            with self.subTest(change=change.__name__):
                cat = copy.deepcopy(retired_cat)
                cat['revision'] = self.rc + 1
                change(cat)
                head = self.commit(cat)
                self.reject(retired, head, TOMBSTONE)

    def test_revision_decrease_overflow_and_unbumped_note(self):
        head = self.commit(self.changed(lambda cat: entry(cat, PROBE).update(note='Changed without bump.'), revision=self.rb))
        self.reject(self.base, head, 'without a revision increase')
        head = self.commit(self.changed(lambda cat: None, revision=self.rb - 1))
        self.reject(self.base, head, f'revision decreased from {self.rb} to {self.rb - 1}')
        head = self.commit(self.changed(lambda cat: None, revision=4294967296))
        self.reject(self.base, head, 'candidate: revision 4294967296 outside 1..4294967295')
        head = self.commit(self.changed(lambda cat: cat.update(format_version=2)))
        self.reject(self.base, head, 'candidate: unsupported format_version 2')

    def test_candidate_schema_cannot_weaken_the_contract(self):
        """R-01: shape, bounds, grammar and grant rules hold independently of the candidate's schema."""
        weak = weakened_schema(self.schema)
        def abuse(cat):
            cat['revision'] = 4294967296
            cat['shadow'] = 1
            entry(cat, PROBE).update(shadow_scope='organization', note='café')
            add(cat, new_entry(4, grant='direct'))
            add(cat, new_entry(4, name='MDM.Bad-Name.é'))
        head = self.commit(self.changed(abuse), schema=weak)
        message = self.reject(self.base, head, 'candidate: revision 4294967296 outside 1..4294967295',
                              "unknown root member 'shadow'", f"{PROBE}: unknown member 'shadow_scope'",
                              f'{PROBE}: note must be 1..512 printable ASCII bytes', 'name grammar',
                              "grant must be 'role'")
        self.assertIn(self.git('rev-parse', head + ':' + SCHEMA), message)
        singles = {
            'overflow': (lambda cat: cat.update(revision=4294967296), 'revision 4294967296 outside'),
            'root member': (lambda cat: cat.update(shadow=1), "unknown root member 'shadow'"),
            'entry member': (lambda cat: entry(cat, PROBE).update(shadow_scope='organization'), "unknown member 'shadow_scope'"),
            'non-ascii note': (lambda cat: entry(cat, PROBE).update(note='café'), 'note must be 1..512 printable ASCII'),
            'long note': (lambda cat: entry(cat, PROBE).update(note='x' * 513), 'note must be 1..512 printable ASCII'),
            'long source': (lambda cat: entry(cat, PROBE).update(source='x' * 161), 'source must be 1..160 printable ASCII'),
            'name grammar': (lambda cat: add(cat, new_entry(self.rc, name='mdm.Devices.test')), 'name grammar'),
            'name length': (lambda cat: add(cat, new_entry(self.rc, name='mdm.' + 'a' * 33 + '.test')), 'name grammar'),
            'grant restriction': (lambda cat: add(cat, new_entry(self.rc, grant='direct')), "grant must be 'role'"),
            'owner mapping': (lambda cat: add(cat, new_entry(self.rc, owner='pki')), 'owner must be one of'),
            'rule agreement': (lambda cat: add(cat, new_entry(self.rc, rule='always')), 'protection/approval must be'),
            'unknown rule': (lambda cat: add(cat, new_entry(self.rc, rule='sometimes')), 'rule must be one of'),
            'unknown scope': (lambda cat: entry(cat, PROBE).update(scope='tenant'), 'scope must be one of'),
            'introduced overflow': (lambda cat: add(cat, new_entry(4294967296)), 'introduced 4294967296 outside 1..4294967295'),
            'introduced zero': (lambda cat: add(cat, new_entry(0)), 'introduced 0 outside 1..4294967295'),
            'duplicate uses': (lambda cat: entry(cat, PROBE)['uses'].append(entry(cat, PROBE)['uses'][0]), 'uses must be 1..32 unique'),
            'empty uses': (lambda cat: entry(cat, PROBE).update(uses=[]), 'uses must be 1..32 unique'),
            'long use': (lambda cat: entry(cat, PROBE).update(uses=['x' * 161]), 'uses must be 1..32 unique'),
            'retired without retired_in': (lambda cat: entry(cat, PROBE).update(status='retired'), "missing member 'retired_in'"),
            'active with retired_in': (lambda cat: entry(cat, PROBE).update(retired_in=self.rc), "unknown member 'retired_in'"),
            'retired_in one': (lambda cat: entry(cat, PROBE).update(status='retired', retired_in=1), 'retired_in 1 outside 2..4294967295'),
            'unsorted names': (lambda cat: cat['permissions'].reverse(), 'names must be unique and strictly ascending'),
            'duplicate names': (lambda cat: cat['permissions'].append(dict(entry(cat, PROBE))), 'names must be unique and strictly ascending'),
            'wrong type': (lambda cat: entry(cat, PROBE).update(uses='api:string'), 'uses must be 1..32 unique'),
            'missing member': (lambda cat: entry(cat, PROBE).pop('owner'), "missing member 'owner'"),
            'non-object entry': (lambda cat: cat['permissions'].append('row'), 'permissions['),
            'empty permissions': (lambda cat: cat.update(permissions=[]), 'permissions must hold 1..2048 entries'),
            'too many permissions': (lambda cat: cat.update(permissions=cat['permissions'] * 7), 'permissions must hold 1..2048 entries'),
            # N-01: unhashable member values are defects, not a TypeError out of invariants().
            'list scope': (lambda cat: entry(cat, PROBE).update(scope=['organization']), 'scope must be one of'),
            'object rule': (lambda cat: entry(cat, PROBE).update(rule={}), 'rule must be one of'),
            'list owner': (lambda cat: entry(cat, PROBE).update(owner=['mdm']), 'owner must be one of'),
            'object status': (lambda cat: entry(cat, PROBE).update(status={}), 'status must be one of'),
            'list grant': (lambda cat: entry(cat, PROBE).update(grant=['role']), 'grant must be one of'),
        }
        for label, (change, fragment) in singles.items():
            with self.subTest(single=label):
                head = self.commit(self.changed(change), schema=weak)
                self.reject(self.base, head, 'candidate: ', fragment)
        # A weakened schema with unchanged catalogue bytes is itself an explicit contract change.
        head = self.commit(self.catalogue_bytes, schema=weak)
        self.reject(self.base, head, 'schema changed without a revision increase')
        head = self.commit(self.changed(lambda cat: None), schema=weak)
        report = self.compare(self.base, head)
        self.assertNotEqual(report['base']['schema'], report['candidate']['schema'])
        self.assertTrue(report['schema_changed'])
        # The candidate's own schema still applies when it is stricter than the base.
        strict = copy.deepcopy(self.schema)
        strict['properties']['revision'] = {'type': 'integer', 'minimum': 1, 'maximum': self.rb}
        head = self.commit(self.changed(lambda cat: None), schema=strict)
        self.reject(self.base, head, 'candidate: schema: $.revision')
        # A candidate the base schema rejects (new verb) passes only with an explicit schema change.
        extended = copy.deepcopy(self.schema)
        pattern = extended['$defs']['permission']['allOf'][6]['properties']['name']['pattern']
        extended['$defs']['permission']['allOf'][6]['properties']['name']['pattern'] = pattern.replace('|withdraw)', '|withdraw|frobnicate)')
        verb = lambda cat: add(cat, new_entry(self.rc, name='mdm.devices.frobnicate'))
        head = self.commit(self.changed(verb), schema=extended)
        self.assertTrue(self.compare(self.base, head)['schema_changed'])
        head = self.commit(self.changed(verb), schema=self.schema)
        self.reject(self.base, head, 'candidate: schema: $.permissions[')

    def test_missing_malformed_and_identical_commits(self):
        head = self.commit(self.changed(lambda cat: None))
        self.reject('f' * 40, head)
        self.reject(self.base, 'f' * 40)
        with self.assertRaises(ValueError): self.compare('HEAD', head)
        with self.assertRaises(ValueError): self.compare(self.base, 'master')
        self.reject(self.base, self.base, 'same commit')
        (self.root / CATALOGUE).unlink()
        absent = self.commit()
        self.reject(absent, head, CATALOGUE + ' absent')
        self.reject(self.base, absent, CATALOGUE + ' absent')
        self.commit(self.changed(lambda cat: None))
        (self.root / SCHEMA).unlink()
        no_schema = self.commit()
        self.reject(self.base, no_schema, SCHEMA + ' absent')
        self.reject(no_schema, head, SCHEMA + ' absent')
        self.write(SCHEMA, self.schema_bytes)
        revision = b'"revision": ' + str(self.rb).encode()
        self.assertIn(revision, self.catalogue_bytes)
        malformed = {
            'duplicate key': b'{"format_version":1,"revision":3,"revision":3,"permissions":[]}\n',
            'truncated': self.catalogue_bytes[:-20],
            'trailing value': self.catalogue_bytes + b'{}\n',
            'fraction revision': self.catalogue_bytes.replace(revision, revision + b'.0', 1),
            'exponent revision': self.catalogue_bytes.replace(revision, revision + b'e0', 1),
            'bool introduced': self.catalogue_bytes.replace(b'"introduced": 1', b'"introduced": true', 1),
            'BOM': b'\xef\xbb\xbf' + self.catalogue_bytes,
            'invalid UTF-8': self.catalogue_bytes.replace(b'"note": "', b'"note": "\xff', 1),
            'unknown field': self.catalogue_bytes.replace(b'"format_version": 1,', b'"format_version": 1, "extra": 1,', 1),
            'oversized': self.catalogue_bytes[:-2] + b' ' * (1 << 20) + b'}\n',
            'deep nesting': b'[' * 100000,
            'depth 13': b'{"a":' + b'[' * 12 + b']' * 12 + b'}',
            'scalar root': b'1\n',
            'empty': b'',
        }
        for label, data in malformed.items():
            with self.subTest(malformed=label):
                self.assertNotEqual(data, self.catalogue_bytes)
                bad = self.commit(data)
                self.reject(bad, head)
                self.reject(self.base, bad)
        schemas = {'bad type': b'{"type": 5}\n', 'bad regex': b'{"type": "object", "patternProperties": {"(unclosed": {}}}\n',
                   'not object': b'[]\n', 'duplicate key': b'{"type": "object", "type": "object"}\n',
                   'deep nesting': b'[' * 100000, 'invalid JSON': b'{'}
        for label, schema in schemas.items():
            with self.subTest(schema=label):
                bad = self.commit(self.changed(lambda cat: None), schema=schema)
                # N-02: a candidate schema failure still names the candidate commit and catalogue blob.
                self.reject(self.base, bad, 'candidate schema', f'candidate commit {bad}',
                            'catalogue blob ' + self.git('rev-parse', bad + ':' + CATALOGUE))
        gitlink = self.commit_mode('160000', oid=self.base, path=SCHEMA)
        self.reject(self.base, gitlink, f'candidate commit {gitlink}', SCHEMA, 'must be a regular file blob')

    def test_unhashable_members_return_defects_directly(self):
        """N-01: invariants() reports unhashable values as defects through the library contract."""
        for field, value in (('scope', ['organization']), ('rule', {}), ('owner', ['mdm']), ('protection', {}),
                             ('approval', []), ('grant', {}), ('status', [])):
            with self.subTest(field=field):
                cat = self.changed(lambda cat: entry(cat, PROBE).update({field: value}))
                found = self.compat.invariants(cat)
                self.assertTrue(any(d.startswith(f'{PROBE}: {field} must be one of') for d in found), found)

    def test_vocabulary_matches_the_live_schema(self):
        """N-04: the schema-independent vocabulary cannot drift from schemas/permissions/v1."""
        c, schema = self.compat, self.schema
        permission = schema['$defs']['permission']
        props = permission['properties']
        for field, values in c.ENUMS.items():
            self.assertEqual(values, set(props[field]['enum']), field)
        self.assertEqual(set().union(*c.OWNERS.values()), set(props['owner']['enum']))
        self.assertEqual(c.ROOT_FIELDS, set(schema['properties']))
        self.assertEqual(c.ROOT_FIELDS, set(schema['required']))
        self.assertEqual(c.ENTRY_FIELDS, set(permission['required']))
        self.assertEqual(c.ENTRY_FIELDS | {'retired_in'}, set(props))
        self.assertEqual(schema['properties']['revision']['maximum'], c.MAX_REVISION)
        self.assertEqual(props['introduced']['maximum'], c.MAX_REVISION)
        self.assertEqual(props['retired_in']['maximum'], c.MAX_REVISION)
        self.assertEqual(schema['properties']['permissions']['maxItems'], c.MAX_ENTRIES)
        name = schema['$defs']['name']
        self.assertEqual((name['minLength'], name['maxLength']), c.NAME_LENGTH)
        anchored = '^' + c.NAME.pattern.removesuffix(r'\Z') + r'$(?![\s\S])'
        self.assertEqual(name['pattern'], anchored)
        uses = props['uses']
        self.assertEqual((uses['minItems'], uses['maxItems'], uses['items']['maxLength']), c.USES)
        for field, limit in c.TEXT_BYTES.items():
            self.assertEqual(props[field]['maxLength'], limit, field)
        printable = '^' + c.PRINTABLE.pattern.removesuffix(r'\Z') + r'$(?![\s\S])'
        for spec in (uses['items'], props['source'], props['note']):
            self.assertEqual(spec['pattern'], printable)
        rules, owners, grants, namespaces = {}, {}, {}, None
        conditional = None
        for clause in permission['allOf']:
            cond = clause.get('if', {}).get('properties', {})
            then = clause.get('then', {}).get('properties', {})
            if 'rule' in cond and 'const' in cond['rule']:
                rules[cond['rule']['const']] = (then['protection']['const'], then['approval']['const'])
            elif 'rule' in cond:
                conditional = (set(cond['rule']['not']['enum']), (then['protection']['const'], then['approval']['const']))
            elif 'name' in cond and 'pattern' in cond['name']:
                owners[cond['name']['pattern'].removeprefix('^').removesuffix(r'\.')] = set(then['owner']['enum'])
            elif 'name' in cond and 'const' in cond['name']:
                node = clause
                while 'if' in node:
                    grants[node['if']['properties']['name']['const']] = node['then']['properties']['grant']['const']
                    node = node['else']
                self.assertEqual(node['properties']['grant']['const'], 'role')
            elif 'name' in clause.get('properties', {}):
                namespaces = clause['properties']['name']['pattern'].split(')', 1)[0].removeprefix('^(').split('|')
        self.assertEqual(c.GRANTS, grants)
        self.assertEqual(c.OWNERS, owners)
        self.assertEqual(set(c.OWNERS), set(namespaces))
        self.assertEqual(conditional[0], set(rules))
        rules.update({rule: conditional[1] for rule in set(props['rule']['enum']) - conditional[0]})
        self.assertEqual(c.RULES, rules)

    def test_catalogue_path_object_modes(self):
        """R-02/R-06/R-08: index modes come from Git plumbing, not host filesystem features."""
        blob = self.git('rev-parse', self.base + ':' + CATALOGUE)
        executable = self.commit_mode('100755', oid=blob)
        self.assertTrue(self.compare(self.base, executable)['unchanged'])
        linked = self.commit_mode('120000', data=b'../../../' + EMBEDDED.encode())
        self.reject(self.base, linked, CATALOGUE, 'must be a regular file blob')
        self.reject(linked, executable, 'must be a regular file blob')
        gitlink = self.commit_mode('160000', oid=self.base)
        self.reject(self.base, gitlink, 'must be a regular file blob')
        (self.root / CATALOGUE).unlink()
        (self.root / CATALOGUE).mkdir()
        (self.root / CATALOGUE / 'inner.json').write_bytes(self.catalogue_bytes)
        tree = self.commit()
        self.assertTrue(self.git('ls-tree', tree, '--', CATALOGUE).startswith('040000 tree'))
        self.reject(self.base, tree, 'must be a regular file blob')
        shutil.rmtree(self.root / CATALOGUE)
        self.commit(self.changed(lambda cat: None))
        schema_link = self.commit_mode('120000', oid=self.git('rev-parse', self.base + ':' + SCHEMA), path=SCHEMA)
        self.reject(self.base, schema_link, SCHEMA, 'must be a regular file blob')

    def run_cli(self, env, base, candidate):
        full_env = dict(os.environ, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', **env)
        return subprocess.run([sys.executable, '-B', str(Path(self.compat.__file__)), '--root', '.',
                               '--base-sha', base, '--candidate-sha', candidate],
                              cwd=self.root, env=full_env, capture_output=True, text=True)

    def test_cli_binds_push_event_and_rejects_substitution(self):
        middle = self.commit(self.changed(lambda cat: None))
        head = self.commit(self.changed(lambda cat: None, revision=self.rc + 1))
        event = self.root / 'event.json'
        event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': self.base, 'after': head}))
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(event), 'GITHUB_SHA': head}
        run = self.run_cli(env, self.base, head)
        self.assertEqual(run.returncode, 0, run.stderr)
        for value in (self.base, head, str(self.rb), str(self.rc + 1), self.git('rev-parse', head + ':' + CATALOGUE),
                      self.git('rev-parse', head + ':' + SCHEMA)):
            self.assertIn(value, run.stdout)
        # A valid ancestor substituted for the event base is still rejected.
        for base, candidate in ((middle, head), (self.base, middle), (head, head)):
            with self.subTest(base=base, candidate=candidate):
                run = self.run_cli(env, base, candidate)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn('substitut', run.stderr)
        run = self.run_cli(dict(env, GITHUB_EVENT_NAME='workflow_dispatch'), self.base, head)
        self.assertNotEqual(run.returncode, 0)
        run = self.run_cli(env, 'HEAD', head)
        self.assertNotEqual(run.returncode, 0)
        run = self.run_cli({k: v for k, v in env.items() if k != 'GITHUB_EVENT_PATH'}, self.base, head)
        self.assertEqual(run.returncode, 1)
        self.assertIn('catalogue compatibility failed', run.stderr)
        self.assertNotIn('Traceback', run.stderr)
        probe_head = self.commit(self.changed(lambda cat: entry(cat, PROBE).update(scope=self.other_scope), revision=self.rb))
        event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': self.base, 'after': probe_head}))
        run = self.run_cli(dict(env, GITHUB_SHA=probe_head), self.base, probe_head)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(PROBE + ': scope changed from', run.stderr)
        self.assertIn(self.base, run.stdout)
        # R-04: invalid candidate schema and deep nesting fail cleanly with the base already logged.
        for label, catalogue, schema in (('bad schema', self.changed(lambda cat: None), b'{"type": 5}\n'),
                                         ('bad regex', self.changed(lambda cat: None), b'{"type": "object", "patternProperties": {"(unclosed": {}}}\n'),
                                         ('deep nesting', b'[' * 100000, self.schema_bytes)):
            with self.subTest(clean_failure=label):
                bad = self.commit(catalogue, schema=schema)
                event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': self.base, 'after': bad}))
                run = self.run_cli(dict(env, GITHUB_SHA=bad), self.base, bad)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn('catalogue compatibility failed', run.stderr)
                self.assertNotIn('Traceback', run.stderr)
                self.assertIn(self.base, run.stdout)

    def test_cli_pull_request_uses_event_base_not_merge_base(self):
        self.git('checkout', '-q', '-b', 'fork')
        head = self.commit(self.changed(lambda cat: None))
        self.git('checkout', '-q', 'master')
        self.write('docs/other.md', b'master moved\n')
        base = self.commit()
        self.git('merge', '-q', '--no-ff', 'fork', '-m', 'Integration')
        tested = self.git('rev-parse', 'HEAD')
        event = self.root / 'event.json'
        event.write_text(json.dumps({'pull_request': {'base': {'sha': base, 'ref': 'master'}, 'head': {'sha': head}}}))
        env = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_EVENT_PATH': str(event), 'GITHUB_SHA': tested}
        run = self.run_cli(env, base, tested)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(base, run.stdout)
        self.assertIn(tested, run.stdout)
        merge_base = self.git('merge-base', base, head)
        self.assertEqual(merge_base, self.base)
        for substitute in ((merge_base, tested), (base, head), (head, tested)):
            with self.subTest(substitute=substitute):
                run = self.run_cli(env, *substitute)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn('substitut', run.stderr)

    def test_design_workflow_wires_the_blocking_check(self):
        data = yaml.load((ROOT / '.github/workflows/design.yml').read_text(), Loader=yaml.BaseLoader)
        steps = data['jobs']['validate']['steps']
        checkout = next(s for s in steps if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with'].get('fetch-depth'), '0')
        step = next(s for s in steps if s.get('run') == COMMAND)
        self.assertEqual(step.get('env'), {'BASE_SHA': '${{ fromJSON(inputs.route).baseSha }}',
                                           'CANDIDATE_SHA': '${{ fromJSON(inputs.route).testedSha }}'})
        self.assertEqual(step.get('shell'), 'bash --noprofile --norc -p -e -o pipefail {0}')
        self.assertEqual(step.get('working-directory'), '.')
        self.assertNotIn('if', step)
        self.assertNotIn('continue-on-error', step)
        self.assertIn(COMMAND, inventory.DESIGN_COMMANDS)
        self.assertIn('catalogue-compat', inventory.checks('design'))
        proof = next(s for s in steps if s.get('id') == 'proof')
        self.assertIn('catalogue-compat', json.loads(proof['env']['CHECKS']))
        self.assertEqual(check_policy.check(ROOT), [])
        with tempfile.TemporaryDirectory(prefix='ci-compat-policy-') as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / '.github', root / '.github')
            shutil.copytree(ROOT / 'scripts/ci', root / 'scripts/ci')
            shutil.copytree(ROOT / 'schemas/ci', root / 'schemas/ci')
            path = root / '.github/workflows/design.yml'
            for mutation in ('remove', 'conditional', 'tolerated'):
                with self.subTest(mutation=mutation):
                    mutated = copy.deepcopy(data)
                    mutated_steps = mutated['jobs']['validate']['steps']
                    target = next(s for s in mutated_steps if s.get('run') == COMMAND)
                    if mutation == 'remove': mutated_steps.remove(target)
                    elif mutation == 'conditional': target['if'] = 'false'
                    else: target['continue-on-error'] = 'true'
                    path.write_text(yaml.safe_dump(mutated, sort_keys=False))
                    errors = check_policy.check(root)
                    self.assertTrue(any('catalogue_compat' in error for error in errors), errors)


if __name__ == '__main__': unittest.main()
