"""Negative tests for validate.py: every document mutation and strict-YAML defect must fail.

Usage: python schemas/openapi/v1/test_validate.py [--root PATH]
"""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate  # noqa: E402

YAML_DEFECTS = [
    ('Y01', 'a: 1\na: 2\n'),
    ('Y03', 'a: &x 1\nb: *x\n'),
    ('Y04', 'a: !!str 1\n'),
    ('Y06', 'a: 1\n---\nb: 2\n'),
    ('Y02', '1: a\n'),
]


def synthetic_proposal():
    """Independent catalogue fragments, never derived from the shipped revision."""
    base = {'format_version': 1, 'revision': 3, 'permissions': [{
        'name': 'identity.sessions.read', 'owner': 'identity', 'scope': 'organization',
        'protection': 'none', 'approval': 'none', 'rule': 'none', 'grant': 'role',
        'status': 'active', 'introduced': 1, 'uses': ['listSessions'],
        'source': 'docs/specs/identity-sessions.md#3', 'note': 'Synthetic read fixture.',
    }]}
    proposal = {'base_revision': 3, 'revision': 4, 'add_permissions': [{
        'name': 'identity.providers.create', 'owner': 'identity', 'scope': 'organization',
        'protection': 'always', 'approval': 'identity_authority',
        'rule': 'identity_authority', 'grant': 'role', 'status': 'active',
        'introduced': 4, 'uses': ['createIdentityProvider'],
        'source': 'docs/specs/identity-login.md#5', 'note': 'Synthetic create fixture.',
    }], 'add_uses': [{'name': 'identity.sessions.read', 'use': 'view:session-fixture'}]}
    return base, proposal


def apply(document, op):
    parts = [p.replace('~1', '/').replace('~0', '~') for p in op['path'][1:].split('/')]
    node = document
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    last = parts[-1]
    if op['op'] == 'delete':
        if isinstance(node, list):
            del node[int(last)]
        else:
            del node[last]
    elif isinstance(node, list):
        index = int(last)
        if index == len(node):
            node.append(op['value'])
        else:
            node[index] = op['value']
    else:
        node[last] = op['value']


def run_document(root, document, catalogue, registry):
    """Return the set of rule codes the mutated document triggers."""
    base = registry.contents(validate.SCHEMA_BASE)
    errors = list(validate.Draft202012Validator(base, registry=registry).iter_errors(document))
    if errors:
        return {'S01'}
    try:
        diagnostics, _ = validate.check_document(root, document, catalogue)
    except validate.Failure as failure:
        return {str(failure)[:3]}
    return {line[:3] for line in diagnostics}


def run(root):
    failures = []
    text = (root / validate.HERE / 'openapi.yaml').read_text(encoding='utf-8')
    original = validate.load_yaml(text)
    registry = validate.upstream_registry(root)
    catalogue = validate.merged_catalogue(root)
    if run_document(root, copy.deepcopy(original), catalogue, registry):
        failures.append('unmutated document must pass')
    cases = json.loads((root / validate.HERE / 'fixtures/document-mutations.json').read_text())['cases']
    for case in cases:
        document = copy.deepcopy(original)
        for op in case['ops']:
            apply(document, op)
        codes = run_document(root, document, catalogue, registry)
        if case['expect'] not in codes:
            failures.append(f'{case["id"]}: expected {case["expect"]}, got {sorted(codes) or "pass"}')
    for code, snippet in YAML_DEFECTS:
        try:
            validate.load_yaml(snippet)
            failures.append(f'YAML defect {code} accepted')
        except validate.Failure as failure:
            if not str(failure).startswith(code):
                failures.append(f'YAML defect {code} reported as {failure}')
        except Exception as error:  # PyYAML errors for malformed documents are also rejections.
            failures.append(f'YAML defect {code} raised {type(error).__name__}')
    stale, bad = synthetic_proposal()
    bad['add_uses'].append({'name': 'identity.sessions.read', 'use': 'listSessions'})
    try:
        validate.merged_catalogue_from(stale, bad, root)
        failures.append('duplicate proposed use accepted')
    except validate.Failure as failure:
        if not str(failure).startswith('C06'):
            failures.append(f'duplicate proposed use reported as {failure}')
    for line in failures:
        print('FAIL:', line)
    if failures:
        return 1
    print(f'PASS: {len(cases)} document mutations and {len(YAML_DEFECTS)} YAML defects rejected')
    return 0


class ContractTests(unittest.TestCase):
    def test_document_mutations(self):
        self.assertEqual(run(Path(__file__).resolve().parents[3]), 0)

    def test_all_fixtures(self):
        diagnostics, _ = validate.validate(Path(__file__).resolve().parents[3])
        self.assertEqual(diagnostics, [])

    def test_each_versioned_write_requires_canonical_if_match(self):
        root = Path(__file__).resolve().parents[3]
        original = validate.load_yaml((root / validate.HERE / 'openapi.yaml').read_text())
        catalogue = validate.merged_catalogue(root)
        checked = set()
        for path, item in original['paths'].items():
            for method, op in item.items():
                if method not in validate.METHODS or op['operationId'] not in validate.VERSIONED_WRITES:
                    continue
                checked.add(op['operationId'])
                for defect in ('missing', 'optional', 'weak', 'list', 'wrong-location'):
                    document = copy.deepcopy(original)
                    params = document['paths'][path][method]['parameters']
                    index = next(i for i, p in enumerate(params)
                                 if validate.deref(document, p).get('name') == 'If-Match')
                    header = copy.deepcopy(validate.deref(document, params[index]))
                    if defect == 'missing':
                        del params[index]
                    else:
                        params[index] = header
                        if defect == 'optional':
                            header['required'] = False
                        elif defect == 'wrong-location':
                            header['in'] = 'query'
                        else:
                            header['schema'] = {'type': 'string', 'maxLength': 100,
                                'pattern': '.*' if defect == 'weak' else '^.+(,.+)*$'}
                    with self.subTest(operation=op['operationId'], defect=defect):
                        diagnostics, _ = validate.check_document(root, document, catalogue)
                        self.assertTrue(any(line.startswith('R24') for line in diagnostics))
        self.assertEqual(checked, validate.VERSIONED_WRITES)

    def test_approval_predicates_after_consumption(self):
        root = Path(__file__).resolve().parents[3]
        cases = validate.load_json((root / validate.HERE / 'fixtures/security.json').read_text())['cases']
        by_id = {case['id']: case['input'] for case in cases}
        decision = copy.deepcopy(by_id['authority-approval'])
        replay = copy.deepcopy(by_id['exact-result-replay'])
        application = copy.deepcopy(by_id['approved-application-consumed-evidence'])
        self.assertTrue(validate.models.security('decision', decision))
        decision.update(pending=False, evidence_consumed=True)
        self.assertFalse(validate.models.security('decision', decision))
        self.assertTrue(validate.models.security('decision_replay', replay))
        self.assertTrue(validate.models.security('application', application))
        application['application_consumed'] = True
        self.assertFalse(validate.models.security('application', application))
        self.assertTrue(validate.models.security('decision_replay', replay))
        application.update(application_consumed=False, fresh=False)
        self.assertFalse(validate.models.security('application', application))
        self.assertTrue(validate.models.security('decision_replay', replay))
        replay['visible'] = False
        self.assertFalse(validate.models.security('decision_replay', replay))

    def test_duplicate_json_and_nonfinite_rejected(self):
        for data in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(data=data), self.assertRaises(validate.Failure):
                validate.load_json(data)

    def test_catalogue_proposal_cannot_reapply(self):
        root = Path(__file__).resolve().parents[3]
        base, proposal = synthetic_proposal()
        catalogue = validate.merged_catalogue_from(base, proposal, root)
        with self.assertRaisesRegex(validate.Failure, 'C01'):
            validate.merged_catalogue_from(catalogue, proposal, root)

    def test_catalogue_proposal_guards(self):
        root = Path(__file__).resolve().parents[3]
        cases = (
            ('C01', 'already-applied'), ('C02', 'wrong-base'),
            ('C03', 'existing-name'), ('C03', 'duplicate-new-name'),
            ('C04', 'introduced'), ('C05', 'unknown-target'), ('C05', 'retired-target'),
            ('C06', 'existing-use'), ('C06', 'duplicate-new-use'), ('C07', 'schema'),
        )
        for code, defect in cases:
            base, proposal = synthetic_proposal()
            if defect == 'already-applied':
                base['revision'] = 4
            elif defect == 'wrong-base':
                base['revision'] = 2
            elif defect == 'existing-name':
                proposal['add_permissions'][0]['name'] = 'identity.sessions.read'
            elif defect == 'duplicate-new-name':
                proposal['add_permissions'].append(copy.deepcopy(proposal['add_permissions'][0]))
            elif defect == 'introduced':
                proposal['add_permissions'][0]['introduced'] = 3
            elif defect == 'unknown-target':
                proposal['add_uses'][0]['name'] = 'identity.providers.delete'
            elif defect == 'retired-target':
                base['permissions'][0].update(status='retired', retired_in=2)
            elif defect == 'existing-use':
                proposal['add_uses'][0]['use'] = 'listSessions'
            elif defect == 'duplicate-new-use':
                proposal['add_uses'].append(copy.deepcopy(proposal['add_uses'][0]))
            elif defect == 'schema':
                proposal['add_permissions'][0]['grant'] = 'direct'
            with self.subTest(defect=defect), self.assertRaisesRegex(validate.Failure, '^' + code):
                validate.merged_catalogue_from(base, proposal, root)

    def test_catalogue_proposal_is_valid_and_does_not_mutate_inputs(self):
        root = Path(__file__).resolve().parents[3]
        base, proposal = synthetic_proposal()
        saved = copy.deepcopy((base, proposal))
        result = validate.merged_catalogue_from(base, proposal, root)
        expected_read = copy.deepcopy(base['permissions'][0])
        expected_read['uses'] = ['listSessions', 'view:session-fixture']
        self.assertEqual(result, {'format_version': 1, 'revision': 4,
                                 'permissions': [proposal['add_permissions'][0], expected_read]})
        result['permissions'][0]['uses'].append('view:caller-edit')
        self.assertEqual((base, proposal), saved)

    def test_canonical_catalogue_without_proposal_is_schema_checked(self):
        root = Path(__file__).resolve().parents[3]
        canonical = validate.load_json((root / validate.CATALOGUE / 'catalogue.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            target = temporary / validate.CATALOGUE
            target.mkdir(parents=True)
            (target / 'catalogue.schema.json').write_bytes(
                (root / validate.CATALOGUE / 'catalogue.schema.json').read_bytes())
            (target / 'catalogue.json').write_text(json.dumps(canonical))
            self.assertEqual(validate.merged_catalogue(temporary), canonical)
            canonical['permissions'][0]['unexpected'] = True
            (target / 'catalogue.json').write_text(json.dumps(canonical))
            with self.assertRaisesRegex(validate.Failure, '^C07'):
                validate.merged_catalogue(temporary)

    def test_active_proposal_file_still_checks_lifecycle(self):
        root = Path(__file__).resolve().parents[3]
        base, proposal = synthetic_proposal()
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            catalogue_dir = temporary / validate.CATALOGUE
            proposal_dir = temporary / validate.HERE
            catalogue_dir.mkdir(parents=True)
            proposal_dir.mkdir(parents=True)
            (catalogue_dir / 'catalogue.schema.json').write_bytes(
                (root / validate.CATALOGUE / 'catalogue.schema.json').read_bytes())
            (catalogue_dir / 'catalogue.json').write_text(json.dumps(base))
            (proposal_dir / 'catalogue-proposal.json').write_text(json.dumps(proposal))
            expected = validate.merged_catalogue_from(base, proposal, root)
            self.assertEqual(validate.merged_catalogue(temporary), expected)
            (catalogue_dir / 'catalogue.json').write_text(json.dumps(expected))
            with self.assertRaisesRegex(validate.Failure, '^C01'):
                validate.merged_catalogue(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='.')
    return run(Path(parser.parse_args().root))


if __name__ == '__main__':
    sys.exit(main())
