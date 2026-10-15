"""Validate the /api/v1 OpenAPI document, its catalogue proposal and shared fixtures.

Usage: python schemas/openapi/v1/validate.py [--root PATH]

The document is checked against the vendored OpenAPI 3.1 schema, then against the
Ricevanta profile of docs/specs/api-foundation.md. Fixture files are checked against
fixtures.schema.json and against the reference models in models.py, so Go and console
tests consume the same decision tables. Exit status 0 means every check passed.
"""
import argparse
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import models  # noqa: E402

HERE = Path('schemas/openapi/v1')
UPSTREAM = Path('schemas/openapi/upstream')
CATALOGUE = Path('schemas/permissions/v1')
SCHEMA_BASE = 'https://spec.openapis.org/oas/3.1/schema-base/2026-08-03'
METHODS = ('get', 'put', 'post', 'delete', 'patch', 'head', 'options', 'trace')
UNSAFE = {'put', 'post', 'delete', 'patch'}
OPERATION_ID = re.compile(r'^[a-z][a-zA-Z0-9]{2,63}$')
SEGMENT = re.compile(r'^([a-z][a-z0-9-]*(\.yaml)?|\{[a-z][a-z0-9_]*\})$')
GATES = {'BE-12'}
CSRF_CLASSES = {'none', 'synchronizer', 'origin', 'navigation', 'navigation_callback', 'cross_site_post'}
REAUTH_PERMISSIONS = {'authz.approvals.approve', 'authz.approvals.reject',
                      'identity.authority.approve', 'identity.tokens.create'}
REQUEST_HEADERS = {'If-Match', 'Idempotency-Key', 'X-Ricevanta-Background'}
FIXTURES = ('problems', 'http-guards', 'return-paths', 'totp', 'sse', 'sessions', 'login',
            'document-mutations', 'security', 'wire')


class Failure(Exception):
    pass


def load_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Failure('J01 duplicate JSON key')
            result[key] = value
        return result

    def invalid_constant(_):
        raise Failure('J01 non-finite JSON number')

    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys and non-string keys."""


def _mapping(loader, node, deep=False):
    keys = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise Failure(f'Y02 non-string mapping key at line {key_node.start_mark.line + 1}')
        if key in keys:
            raise Failure(f'Y01 duplicate key {key!r} at line {key_node.start_mark.line + 1}')
        keys.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_yaml(text):
    """Load one YAML document with no anchors, aliases, explicit tags or duplicate keys."""
    if len(text.encode()) > 1048576:
        raise Failure('Y05 document larger than 1 MiB')
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, 'anchor', None):
            raise Failure('Y03 anchors and aliases are not allowed')
        tag = getattr(event, 'tag', None)
        implicit = getattr(event, 'implicit', True)
        if tag is not None and not (implicit is True or (isinstance(implicit, tuple) and any(implicit))):
            raise Failure('Y04 explicit tags are not allowed')
    documents = list(yaml.load_all(text, Loader=StrictLoader))
    if len(documents) != 1:
        raise Failure('Y06 exactly one YAML document is required')
    return documents[0]


def _refuse(uri):
    raise Failure('R18 nonlocal schema reference ' + uri)


def upstream_registry(root):
    lock = load_json((root / UPSTREAM / 'lock.json').read_text())
    resources = []
    for entry in lock['schemas']:
        data = (root / UPSTREAM / entry['file']).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise Failure('U01 vendored schema digest mismatch: ' + entry['file'])
        contents = load_json(data)
        if contents.get('$id') != entry['id']:
            raise Failure('U02 vendored schema id mismatch: ' + entry['file'])
        resources.append((entry['id'], Resource.from_contents(contents)))
    license_bytes = (root / UPSTREAM / lock['license']['file']).read_bytes()
    if hashlib.sha256(license_bytes).hexdigest() != lock['license']['sha256']:
        raise Failure('U03 vendored license digest mismatch')
    return Registry(retrieve=_refuse).with_resources(resources).crawl()


def pointer(document, ref):
    if not ref.startswith('#/'):
        raise Failure('R18 external reference ' + ref)
    node = document
    for part in ref[2:].split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        if not isinstance(node, dict) or part not in node:
            raise Failure('R18 unresolved reference ' + ref)
        node = node[part]
    return node


def deref(document, node, seen=()):
    while isinstance(node, dict) and '$ref' in node:
        ref = node['$ref']
        if ref in seen:
            raise Failure('R18 reference cycle ' + ref)
        seen = seen + (ref,)
        node = pointer(document, ref)
    return node


def all_refs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == '$ref':
                yield value
            else:
                yield from all_refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from all_refs(value)


def merged_catalogue(root):
    catalogue = load_json((root / CATALOGUE / 'catalogue.json').read_text())
    proposal_path = root / HERE / 'catalogue-proposal.json'
    if not proposal_path.exists():
        return catalogue
    return merged_catalogue_from(catalogue, load_json(proposal_path.read_text()), root)


def merged_catalogue_from(catalogue, proposal, root):
    """Apply catalogue-proposal.json to the canonical catalogue and validate the result."""
    if catalogue['revision'] >= proposal['revision']:
        raise Failure('C01 catalogue already at the proposed revision; remove catalogue-proposal.json')
    if catalogue['revision'] != proposal['base_revision']:
        raise Failure('C02 proposal base revision does not match the catalogue')
    merged = copy.deepcopy(catalogue)
    merged['revision'] = proposal['revision']
    names = {p['name']: p for p in merged['permissions']}
    for entry in proposal['add_permissions']:
        if entry['name'] in names:
            raise Failure('C03 proposed permission already exists: ' + entry['name'])
        if entry['introduced'] != proposal['revision']:
            raise Failure('C04 proposed permission must be introduced at the proposed revision')
        names[entry['name']] = copy.deepcopy(entry)
    for item in proposal['add_uses']:
        target = names.get(item['name'])
        if target is None or target['status'] != 'active':
            raise Failure('C05 proposed use targets an unknown or retired permission: ' + item['name'])
        if item['use'] in target['uses']:
            raise Failure('C06 proposed use already present: ' + item['use'])
        target['uses'].append(item['use'])
    merged['permissions'] = [names[n] for n in sorted(names)]
    schema = load_json((root / CATALOGUE / 'catalogue.schema.json').read_text())
    errors = sorted(e.message for e in Draft202012Validator(schema).iter_errors(merged))
    if errors:
        raise Failure('C07 merged catalogue fails its schema: ' + errors[0])
    return merged


def bounded(document, schema, where, diagnostics, depth=0):
    """Request bodies are closed and bounded: objects closed, strings, arrays and integers limited."""
    if depth > 24:
        diagnostics.append(f'R12 {where}: request schema nests too deeply')
        return
    schema = deref(document, schema)
    if 'oneOf' in schema:
        for index, branch in enumerate(schema['oneOf']):
            bounded(document, branch, f'{where}/oneOf/{index}', diagnostics, depth + 1)
        return
    kind = schema.get('type')
    if 'const' in schema or 'enum' in schema:
        return
    if kind == 'object':
        if schema.get('additionalProperties') is not False:
            diagnostics.append(f'R12 {where}: request object must set additionalProperties false')
        for name, child in schema.get('properties', {}).items():
            bounded(document, child, f'{where}/{name}', diagnostics, depth + 1)
    elif kind == 'array':
        if 'maxItems' not in schema:
            diagnostics.append(f'R12 {where}: request array needs maxItems')
        bounded(document, schema.get('items', {}), f'{where}[]', diagnostics, depth + 1)
    elif kind == 'string':
        if 'maxLength' not in schema:
            diagnostics.append(f'R12 {where}: request string needs maxLength')
    elif kind == 'integer':
        if 'minimum' not in schema or 'maximum' not in schema:
            diagnostics.append(f'R12 {where}: request integer needs minimum and maximum')
    elif kind != 'boolean':
        diagnostics.append(f'R12 {where}: request schema needs an explicit type')


def check_operation(document, path, method, op, catalogue, extension_validator, diagnostics):
    oid = op.get('operationId', '<missing>')
    here = f'{method.upper()} {path} ({oid})'
    if not OPERATION_ID.match(oid):
        diagnostics.append(f'R04 {here}: operationId grammar')
    if not op.get('summary') or not op.get('tags'):
        diagnostics.append(f'R20 {here}: summary and tags are required')
    declared_tags = {t['name'] for t in document.get('tags', [])}
    if not set(op.get('tags', [])) <= declared_tags:
        diagnostics.append(f'R20 {here}: undeclared tag')
    authz = op.get('x-ricevanta-authorization')
    if authz is None:
        diagnostics.append(f'R05 {here}: x-ricevanta-authorization is required')
        return
    errors = sorted(e.message for e in extension_validator.iter_errors(authz))
    if errors:
        diagnostics.append(f'R05 {here}: {errors[0]}')
        return
    principal, csrf = authz['principal'], authz['csrf']
    credentials = authz.get('credentials', [])
    perms = authz.get('permissions', [])
    unsafe = method in UNSAFE
    responses = op.get('responses', {})

    # R06: OpenAPI security mirrors the credential binding.
    security = op.get('security')
    if principal in ('public', 'protocol'):
        if security != []:
            diagnostics.append(f'R06 {here}: public and protocol operations declare security: []')
    else:
        expected = []
        for credential in credentials:
            if credential == 'session':
                expected.append({'session': [], 'csrf': []} if csrf == 'synchronizer' else {'session': []})
            else:
                expected.append({'token': []})
        if security != expected:
            diagnostics.append(f'R06 {here}: security must be {expected}')

    # R07: permission bindings exist in the merged catalogue.
    by_name = {p['name']: p for p in catalogue['permissions']}
    selectors = [p['selector'] for p in perms if 'selector' in p]
    if len(selectors) != len(set(selectors)):
        diagnostics.append(f'R19 {here}: duplicate selector')
    if principal == 'subject' and any('selector' not in p for p in perms):
        diagnostics.append(f'R19 {here}: subject operations may add permissions only through selectors')
    for perm in perms:
        entry = by_name.get(perm['name'])
        if entry is None or entry['status'] != 'active':
            diagnostics.append(f'R07 {here}: unknown or retired permission {perm["name"]}')
            continue
        if perm['uses'] not in entry['uses']:
            diagnostics.append(f'R07 {here}: catalogue {perm["name"]} does not list use {perm["uses"]}')
        base = perm['uses'].split('#')[0]
        if base != oid:
            diagnostics.append(f'R07 {here}: binding use {perm["uses"]} names another operation')
        if 'selector' in perm and perm['uses'] != f'{oid}#{perm["selector"]}' :
            diagnostics.append(f'R07 {here}: selector {perm["selector"]} not in use {perm["uses"]}')

    # R08: fresh authentication.
    entries = [by_name[p['name']] for p in perms if p['name'] in by_name]
    needs_reauth = any(e['approval'] == 'identity_authority' or e['name'] in REAUTH_PERMISSIONS for e in entries)
    if needs_reauth and authz['reauth'] == 'none':
        diagnostics.append(f'R08 {here}: permission requires recent authentication')
    if authz['reauth'] != 'none' and credentials != ['session']:
        diagnostics.append(f'R08 {here}: re-authenticated operations accept the session only')
    if authz['reauth'] == 'bound' and not any(e['name'] == 'identity.authority.approve' for e in entries):
        diagnostics.append(f'R08 {here}: bound re-authentication is for identity-authority approval only')

    # R09: protected actions answer 202 with an approval request.
    protected = any(e['protection'] != 'none' for e in entries)
    if protected and responses.get('202', {}).get('$ref') != '#/components/responses/ApprovalAccepted':
        diagnostics.append(f'R09 {here}: protected operation must answer 202 ApprovalAccepted')
    if '202' in responses:
        if op.get('x-ricevanta-idempotency') != 'required':
            diagnostics.append(f'R09 {here}: 202 operations require Idempotency-Key')
        params = [deref(document, p).get('name') for p in op.get('parameters', [])]
        if 'Idempotency-Key' not in params:
            diagnostics.append(f'R09 {here}: Idempotency-Key parameter missing')

    # R10: request-forgery class fits the method and principal.
    rule = {
        'synchronizer': unsafe and 'session' in credentials,
        'origin': unsafe and principal in ('public', 'protocol'),
        'navigation': method == 'get' and principal in ('public', 'subject'),
        'navigation_callback': method == 'get' and authz.get('protocol') == 'oidc_callback',
        'cross_site_post': method == 'post' and authz.get('protocol') == 'saml_acs',
        'none': not unsafe and principal != 'protocol',
    }[csrf]
    if not rule:
        diagnostics.append(f'R10 {here}: csrf class {csrf} does not fit the operation')
    if unsafe and 'session' in credentials and csrf != 'synchronizer':
        diagnostics.append(f'R10 {here}: unsafe session operations need the synchronizer token')

    # R11: response shapes.
    navigation = csrf in ('navigation', 'navigation_callback', 'cross_site_post')
    if navigation:
        if set(responses) != {'303'}:
            diagnostics.append(f'R11 {here}: navigation operations answer only 303')
    elif responses.get('default', {}).get('$ref') != '#/components/responses/Problem':
        diagnostics.append(f'R11 {here}: default response must be the Problem response')

    # R12 and R13: bodies are bounded; unsafe methods declare idempotency.
    body = op.get('requestBody')
    if body is not None:
        limit = op.get('x-ricevanta-max-body-bytes')
        if not isinstance(limit, int) or not 1 <= limit <= 1048576:
            diagnostics.append(f'R12 {here}: x-ricevanta-max-body-bytes between 1 and 1048576 required')
        for media, content in body.get('content', {}).items():
            if media not in ('application/json', 'application/x-www-form-urlencoded'):
                diagnostics.append(f'R12 {here}: request media type {media}')
            bounded(document, content.get('schema', {}), f'{here} body', diagnostics)
    elif 'x-ricevanta-max-body-bytes' in op:
        diagnostics.append(f'R12 {here}: body limit without a body')
    if unsafe and op.get('x-ricevanta-idempotency') not in ('required', 'not_supported'):
        diagnostics.append(f'R13 {here}: unsafe operations declare x-ricevanta-idempotency')

    # R14: gates.
    if op.get('x-ricevanta-gates') != ['BE-12']:
        diagnostics.append(f'R14 {here}: every identity-dependent operation requires exactly BE-12')

    # R15 and R21: parameters.
    names = set()
    for param in op.get('parameters', []):
        param = deref(document, param)
        key = (param['in'], param['name'])
        if key in names:
            diagnostics.append(f'R15 {here}: duplicate parameter {param["name"]}')
        names.add(key)
        if param['in'] == 'path':
            if param.get('required') is not True or param.get('schema', {}).get('$ref') != '#/components/schemas/Uid':
                diagnostics.append(f'R15 {here}: path parameter {param["name"]} must be a required Uid')
        bounded(document, param.get('schema', {}), f'{here} parameter {param["name"]}', diagnostics)
        if param['in'] == 'header' and param['name'] not in REQUEST_HEADERS:
            diagnostics.append(f'R21 {here}: undeclared request header {param["name"]}')
    for template in re.findall(r'\{([a-z_]+)\}', path):
        if ('path', template) not in names:
            diagnostics.append(f'R15 {here}: path template {template} not declared')

    # R22: decision routes cannot exchange their freshness or credential policy.
    if oid == 'approveIdentityAuthorityRequest' and authz['reauth'] != 'bound':
        diagnostics.append(f'R22 {here}: identity approval requires bound evidence')
    if principal == 'protocol' and csrf not in ('origin', 'navigation_callback', 'cross_site_post'):
        diagnostics.append(f'R22 {here}: protocol proof requires its request guard')
    # R17: event streams declare their events.
    for code, response in responses.items():
        response = deref(document, response)
        for media, content in response.get('content', {}).items():
            if media == 'text/event-stream':
                events = content.get('x-ricevanta-events')
                if not events:
                    diagnostics.append(f'R17 {here}: event stream without x-ricevanta-events')
                for event in events or []:
                    deref(document, event['data'])


def check_document(root, document, catalogue):
    diagnostics = []
    if document.get('openapi') != '3.1.2':
        diagnostics.append('R01 openapi must be 3.1.2')
    if not re.match(r'^1\.[1-9][0-9]*$', str(document.get('info', {}).get('version', ''))):
        diagnostics.append('R02 info.version must be 1.<revision>')
    for ref in all_refs(document):
        pointer(document, ref)
    extension_schema = load_json((root / HERE / 'extensions.schema.json').read_text())
    Draft202012Validator.check_schema(extension_schema)
    extension_validator = Draft202012Validator(extension_schema)
    seen = {}
    for path, item in document.get('paths', {}).items():
        segments = path.split('/')[1:]
        if not path.startswith('/api/v1/') or not all(SEGMENT.match(s) for s in segments[2:]):
            diagnostics.append(f'R03 {path}: path grammar')
        for method in METHODS:
            if method not in item:
                continue
            op = item[method]
            oid = op.get('operationId')
            if oid in seen:
                diagnostics.append(f'R04 {path}: duplicate operationId {oid}')
            seen[oid] = (method, path)
            check_operation(document, path, method, op, catalogue, extension_validator, diagnostics)
    problem_types = pointer(document, '#/components/schemas/Problem')['properties']['type']['enum']
    expected = ['https://ricevanta.io/problems/' + code for code in models.PROBLEMS]
    if problem_types != expected:
        diagnostics.append('R16 Problem.type enum must equal the problem table in models.PROBLEMS')
    # R23: topic permissions are checked separately from the subject stream binding.
    by_name = {p['name']: p for p in catalogue['permissions']}
    topic_bindings = dict(models.TOPIC_PERMISSIONS)
    topic_bindings['approvals-all'] = 'authz.approvals.read'
    for topic, name in topic_bindings.items():
        if name is None:
            continue
        entry = by_name.get(name, {})
        use = 'streamChanges#' + topic.replace('.', '-')
        if entry.get('status') != 'active' or use not in entry.get('uses', []):
            diagnostics.append(f'R23 topic {topic}: missing active catalogue binding')
    return sorted(set(diagnostics)), seen


def schema_bundle(document):
    """Expose components.schemas as a 2020-12 bundle for instance validation."""
    text = json.dumps(document['components']['schemas']).replace('#/components/schemas/', '#/$defs/')
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$defs': json.loads(text)}


def instance_validator(bundle, name):
    schema = dict(bundle)
    schema['$ref'] = '#/$defs/' + name
    checker = FormatChecker()

    @checker.checks('date-time')
    def utc_timestamp(value):
        if not isinstance(value, str):
            return True
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z', value):
            return False
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
            return True
        except ValueError:
            return False

    return Draft202012Validator(schema, format_checker=checker)


def check_fixtures(root, document, operations):
    diagnostics = []
    fixture_schema = load_json((root / HERE / 'fixtures.schema.json').read_text())
    Draft202012Validator.check_schema(fixture_schema)
    bundle = schema_bundle(document)
    for name in FIXTURES:
        data = load_json((root / HERE / 'fixtures' / f'{name}.json').read_text())
        schema = dict(fixture_schema)
        schema['$ref'] = '#/$defs/' + name.replace('-', '_')
        errors = sorted(e.message for e in Draft202012Validator(schema).iter_errors(data))
        if errors:
            diagnostics.append(f'F01 fixtures/{name}.json shape: {errors[0]}')
            continue
        ids = [case['id'] for case in data['cases']]
        if len(ids) != len(set(ids)):
            diagnostics.append(f'F02 fixtures/{name}.json duplicate case id')
        diagnostics.extend(models.check(name, data, bundle, instance_validator, operations))
    return diagnostics


def validate(root):
    document = load_yaml((root / HERE / 'openapi.yaml').read_text(encoding='utf-8'))
    registry = upstream_registry(root)
    base = registry.contents(SCHEMA_BASE)
    errors = sorted(e.message for e in Draft202012Validator(base, registry=registry).iter_errors(document))
    if errors:
        raise Failure('S01 OpenAPI 3.1 schema: ' + errors[0])
    catalogue = merged_catalogue(root)
    diagnostics, operations = check_document(root, document, catalogue)
    if not diagnostics:
        diagnostics = check_fixtures(root, document, operations)
    return diagnostics, len(operations)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='.')
    args = parser.parse_args()
    root = Path(args.root)
    try:
        diagnostics, count = validate(root)
    except Failure as failure:
        print('FAIL:', failure)
        return 1
    for line in diagnostics:
        print('FAIL:', line)
    if diagnostics:
        return 1
    print(f'PASS: OpenAPI 3.1 schema, profile rules for {count} operations, catalogue bindings and fixtures')
    return 0


if __name__ == '__main__':
    sys.exit(main())
