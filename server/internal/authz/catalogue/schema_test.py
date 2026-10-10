"""Read-only, offline permission schema and reviewed binding checks."""
import argparse
import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import tempfile

from jsonschema import Draft202012Validator
from referencing import Registry

ROOT = Path(__file__).resolve().parents[4]
ASSETS = Path('schemas/permissions/v1')
FIXED = ('dlp.evidence.read', 'identity.tokens.manage', 'identity.authority.approve',
         'authz.approvals.read', 'audit.events.read', 'policy.ownership.override', 'events.reports.run')
BRANCHES = {
    'updateTrustList#add-publisher-key-revocation': ('extensions.trust.revoke', 'none'),
    'api:revoke-extension-id': ('extensions.packages.revoke', 'extension_dependency'),
    'api:revoke-extension-version': ('extensions.packages.revoke', 'extension_dependency'),
    'updateTrustList#add-id-revocation': ('extensions.packages.revoke', 'extension_dependency'),
    'updateTrustList#add-version-revocation': ('extensions.packages.revoke', 'extension_dependency'),
    'updateTrustList#trust-change': ('extensions.trust.update', 'always'),
}
EXEMPTIONS = {'subject-session', 'protocol-enrollment', 'automatic-workers', 'offline-recovery',
              'endpoint-local', 'deployment-settings', 'gateway-cutover', 'external-portals',
              'qualification', 'automatic-policy', 'external-ca', 'spool-codec',
              'spool-manager-recovery', 'spool-pipeline-recovery', 'cel-declaration-loader',
              'cel-compiler-environment'}


def require(ok, defect):
    if not ok:
        raise ValueError(defect)


def read(root, path):
    return json.loads((root / path).read_bytes())


def refuse_remote(uri):
    raise ValueError('remote schema reference: ' + uri)


def validator(schema):
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=Registry(retrieve=refuse_remote))


def classification(rule):
    if rule == 'none':
        return 'none', 'none'
    if rule == 'identity_authority':
        return 'always', 'identity_authority'
    return ('always' if rule == 'always' else 'conditional'), 'access_policy'


def branch_check(cat):
    found = {key: [] for key in BRANCHES}
    for p in cat['permissions']:
        for use in p['uses']:
            if use.startswith('updateTrustList'):
                require(use in BRANCHES, 'branch unknown: ' + use)
            if use in found:
                found[use].append(p)
    for use, (name, rule) in BRANCHES.items():
        rows = found[use]
        require(len(rows) == 1, 'branch cardinality: ' + use)
        p = rows[0]
        require(p['name'] == name, 'branch name: ' + use)
        require(p['rule'] == rule, 'branch rule: ' + use)
        protection, approval = classification(rule)
        for field, want in [('protection', protection), ('approval', approval),
                            ('grant', 'role'), ('status', 'active')]:
            require(p[field] == want, 'branch ' + field + ': ' + use)


def action_check(cat, a):
    by_name = {p['name']: p for p in cat['permissions']}
    ident = a['id']
    require(a['name'] in by_name, 'entry: ' + ident)
    p = by_name[a['name']]
    require(ident in p['uses'], 'selector: ' + ident)
    protection, approval = classification(a['rule'])
    for field, want in [('owner', a['owner']), ('note', a['note']), ('scope', a['scope']),
                        ('rule', a['rule']), ('protection', protection), ('approval', approval),
                        ('grant', 'role'), ('status', 'active')]:
        require(p[field] == want, field + ': ' + ident)
    for name in a['requires']:
        require(name in by_name and by_name[name]['status'] == 'active'
                and by_name[name]['grant'] == 'role', 'composed: ' + ident + ': ' + name)


def binding_check(cat, coverage):
    by_name = {p['name']: p for p in cat['permissions']}
    for name in FIXED:
        require(name in by_name, 'fixed name: ' + name)
    for a in coverage['actions']:
        action_check(cat, a)
    for use, (name, rule) in BRANCHES.items():
        rows = [a for a in coverage['actions'] if a['id'] == use]
        require(len(rows) == 1 and rows[0]['name'] == name and rows[0]['rule'] == rule,
                'manifest branch: ' + use)
    branch_check(cat)


def lifecycle(cat):
    names = [p['name'] for p in cat['permissions']]
    require(names == sorted(set(names)), 'unique ASCII name order')
    for p in cat['permissions']:
        require(p['introduced'] <= cat['revision'], 'introduced revision')
        if p['status'] == 'retired':
            require(p['introduced'] < p['retired_in'] <= cat['revision'], 'retired revision')


def section(root, reference):
    path, number = reference.split('#')
    text = (root / path).read_text()
    lines = text.splitlines(keepends=True)
    start = None
    level = None
    for i, line in enumerate(lines):
        m = re.match(r'^(#{1,6})\s+(\d+(?:\.\d+)*)\.?\s', line)
        if m and m[2] == number:
            start, level = i, len(m[1])
            break
    require(start is not None, 'source section: ' + reference)
    end = len(lines)
    for i in range(start + 1, len(lines)):
        m = re.match(r'^(#{1,6})\s', lines[i])
        if m and len(m[1]) <= level:
            end = i
            break
    return ''.join(lines[start:end])


def console_operations(root):
    operations = set()
    for i in range(1, 17):
        text = section(root, 'docs/design/console.md#5.' + str(i))
        for line in text.splitlines():
            if line.startswith('- Operations:'):
                operations.update(re.findall(r'`([A-Za-z][A-Za-z0-9]+)`', line))
        if i == 8:
            require('same set for exceptions and baselines' in text, 'console same set')
            for noun in ('Exception', 'Baseline'):
                operations.update((f'list{noun}s', f'get{noun}', f'create{noun}', f'update{noun}',
                                   f'delete{noun}', f'validate{noun}', f'list{noun}Versions'))
    return operations


def console_check(root, cat):
    uses = {u.split('#')[0] for p in cat['permissions'] for u in p['uses']}
    for op in sorted(console_operations(root)):
        require(op in uses, 'console operation: ' + op)


def sources(root, cat, coverage):
    console_check(root, cat)
    for a in coverage['actions']:
        require(a['anchor'] in section(root, a['source']), 'source anchor: ' + a['id'])
    require({e['id'] for e in coverage['exemptions']} == EXEMPTIONS, 'exemption inventory')
    for e in coverage['exemptions']:
        require(bool(e['authority'].strip()), 'exemption authority: ' + e['id'])
        section(root, e['source'])
    for p in cat['permissions']:
        section(root, p['source'])
    pinned = [d['path'] for d in coverage['documents']]
    require(pinned == sorted(set(pinned)), 'source inventory order')
    actual = sorted(p.relative_to(root).as_posix() for folder in ('design', 'specs')
                    for p in (root / 'docs' / folder).glob('*.md'))
    require(pinned == actual, 'source inventory: ' + ', '.join(sorted(set(pinned) ^ set(actual))))
    for d in coverage['documents']:
        require(hashlib.sha256((root / d['path']).read_bytes()).hexdigest() == d['sha256'],
                'source digest: ' + d['path'])


def fragment_check(v, row):
    require(v.is_valid(row['catalogue']) == row['schema_valid'], 'fragment expectation: ' + row['id'])


def validate(root, check_sources=False):
    require(importlib.metadata.version('jsonschema') == '4.25.1', 'jsonschema version must be 4.25.1')
    v = validator(read(root, ASSETS / 'catalogue.schema.json'))
    fv = validator(read(root, ASSETS / 'fixtures.schema.json'))
    cv = validator(read(root, ASSETS / 'coverage.schema.json'))
    cat = read(root, ASSETS / 'catalogue.json')
    coverage = read(root, ASSETS / 'fixtures/coverage.json')
    cv.validate(coverage)
    binding_check(cat, coverage)
    v.validate(cat)
    lifecycle(cat)
    for filename in ('catalogues', 'names', 'revocations'):
        wrapper = read(root, ASSETS / f'fixtures/{filename}.json')
        fv.validate(wrapper)
        if filename == 'catalogues':
            for row in wrapper['cases']:
                if 'wire_hex' in row:
                    bytes.fromhex(row['wire_hex'])  # Go owns the strict byte profile.
                else:
                    fragment_check(v, row)
        if filename == 'revocations':
            for row in wrapper['revocation_cases']:
                v.validate(row['catalogue'])
                try:
                    branch_check(row['catalogue'])
                    accepted = True
                except ValueError:
                    accepted = False
                require(accepted == row['coverage_valid'], 'revocation expectation: ' + row['id'])
    if check_sources:
        sources(root, cat, coverage)
    return cat, coverage, v


def expect_failure(call, defect):
    try:
        call()
    except ValueError as err:
        require(defect in str(err), f'wrong mutation failure: {err}; wanted {defect}')
        return
    raise ValueError('mutation accepted: ' + defect)


def self_tests(root, cat, coverage, v, check_sources):
    count = 0
    fragment = next(r for r in read(root, ASSETS / 'fixtures/catalogues.json')['cases']
                    if r.get('schema_valid'))
    fragment = copy.deepcopy(fragment)
    fragment['schema_valid'] = False
    expect_failure(lambda: fragment_check(v, fragment), 'fragment expectation')
    count += 1
    for name in FIXED:
        changed = copy.deepcopy(cat)
        changed['permissions'] = [p for p in changed['permissions'] if p['name'] != name]
        expect_failure(lambda: binding_check(changed, coverage), 'fixed name')
        count += 1
    for a in coverage['actions']:
        for field in ('entry', 'selector', 'rename', 'owner', 'note', 'scope', 'rule',
                      'protection', 'approval', 'grant', 'status', *a['requires']):
            changed = copy.deepcopy(cat)
            p = next(p for p in changed['permissions'] if p['name'] == a['name'])
            defect = field
            if field == 'entry' or field in a['requires']:
                name = a['name'] if field == 'entry' else field
                changed['permissions'] = [p for p in changed['permissions'] if p['name'] != name]
                defect = 'entry' if field == 'entry' else 'composed'
            elif field in ('selector', 'rename'):
                p['uses'].remove(a['id'])
                if field == 'rename':
                    p['uses'].append(a['id'] + '-wrong')
                defect = 'selector'
            else:
                p[field] += '-wrong'
            # Earlier manifest rows may require the removed row as a composed name.
            if field == 'entry':
                one = {'actions': [a]}
                expect_failure(lambda: action_check(changed, a), defect)
            elif field in a['requires']:
                expect_failure(lambda: action_check(changed, a), defect)
            else:
                expect_failure(lambda: action_check(changed, a), defect)
            count += 1
    for use in BRANCHES:
        changed = copy.deepcopy(coverage)
        changed['actions'] = [a for a in changed['actions'] if a['id'] != use]
        expect_failure(lambda: binding_check(cat, changed), 'manifest branch')
        changed = copy.deepcopy(coverage)
        next(a for a in changed['actions'] if a['id'] == use)['name'] = 'wrong.branch.read'
        expect_failure(lambda: binding_check(cat, changed), 'entry')
        count += 2
    if check_sources:
        for op in console_operations(root):
            changed = copy.deepcopy(cat)
            for p in changed['permissions']:
                p['uses'] = [u for u in p['uses'] if u.split('#')[0] != op]
            expect_failure(lambda: console_check(root, changed), 'console operation: ' + op)
            count += 1
        for a in coverage['actions']:
            changed = copy.deepcopy(coverage)
            next(r for r in changed['actions'] if r['id'] == a['id'])['anchor'] = 'absent reviewed anchor'
            expect_failure(lambda: sources(root, cat, changed), 'source anchor')
            count += 1
        for e in coverage['exemptions']:
            section(root, e['source'])
            changed = copy.deepcopy(coverage)
            changed['exemptions'] = [r for r in changed['exemptions'] if r['id'] != e['id']]
            expect_failure(lambda: sources(root, cat, changed), 'exemption inventory')
            count += 1
        with tempfile.TemporaryDirectory(prefix='permission-sources-') as tmp:
            tree = Path(tmp)
            shutil.copytree(root / ASSETS, tree / ASSETS)
            shutil.copytree(root / 'docs', tree / 'docs')
            path = tree / 'docs/design/console.md'
            original = path.read_bytes()
            path.write_bytes(original + b'\nUnrelated prose.\n')
            validate(tree)
            expect_failure(lambda: validate(tree, True), 'source digest: docs/design/console.md')
            path.write_bytes(original)
            added = tree / 'docs/specs/extra-source.md'
            added.write_text('# Extra source\n')
            validate(tree)
            expect_failure(lambda: validate(tree, True), 'source inventory: docs/specs/extra-source.md')
            added.unlink()
            removed = tree / 'docs/specs/core-primitives.md'
            original = removed.read_bytes()
            removed.unlink()
            validate(tree)
            expect_failure(lambda: validate(tree, True), 'source inventory')
            removed.write_bytes(original)
            shutil.rmtree(tree / 'docs')
            validate(tree)
            count += 4
        for d in coverage['documents']:
            changed = copy.deepcopy(coverage)
            next(r for r in changed['documents'] if r['path'] == d['path'])['sha256'] = '0' * 64
            expect_failure(lambda: sources(root, cat, changed), 'source digest: ' + d['path'])
            count += 1
    print(f'PASS: {count} intended mutation failures; wire byte-profile checks belong to Go')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-sources', action='store_true')
    args = parser.parse_args()
    try:
        cat, coverage, v = validate(ROOT, args.check_sources)
        self_tests(ROOT, cat, coverage, v, args.check_sources)
    except (ValueError, OSError) as err:
        raise SystemExit(str(err)) from None
    print('PASS: schemas, fixtures and bindings' + ('; source coverage and freshness' if args.check_sources else ''))


if __name__ == '__main__':
    main()
