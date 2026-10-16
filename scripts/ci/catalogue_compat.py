"""Compare the candidate permission catalogue with the reviewed base, both read from Git objects."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

import inventory
import required
import route as routing

CATALOGUE = 'schemas/permissions/v1/catalogue.json'
SCHEMA = 'schemas/permissions/v1/catalogue.schema.json'
MAX_BYTES = 1 << 20
MAX_DEPTH = 12
MAX_ENTRIES = 2048
MAX_REVISION = 4294967295
NAME_LENGTH = (5, 98)
USES = (1, 32, 160)  # minimum and maximum entries, maximum bytes per entry
TEXT_BYTES = {'source': 160, 'note': 512}
# Fields an existing name can never change in place; `uses` is compared as a set below.
IMMUTABLE = ('owner', 'scope', 'grant', 'rule', 'protection', 'approval', 'introduced')
# Permission catalogue spec sections 2 and 4, enforced independently of any schema the candidate carries.
ROOT_FIELDS = {'format_version', 'revision', 'permissions'}
ENTRY_FIELDS = {'name', 'owner', 'scope', 'protection', 'approval', 'rule', 'grant', 'status',
                'introduced', 'uses', 'source', 'note'}
NAME = re.compile(r'[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}\Z')
PRINTABLE = re.compile(r'[\x20-\x7e]+\Z')
CONDITIONAL = ('audit_retention', 'child_union', 'destination_change', 'extension_dependency', 'fleet_gt_10',
               'gateway_widen', 'grant_sensitive', 'group_change', 'hold_narrow', 'policy_change', 'published_content')
RULES = {'none': ('none', 'none'), 'always': ('always', 'access_policy'),
         'identity_authority': ('always', 'identity_authority'),
         **{rule: ('conditional', 'access_policy') for rule in CONDITIONAL}}
ENUMS = {'scope': {'organization', 'device_group'}, 'protection': {'none', 'always', 'conditional'},
         'approval': {'none', 'access_policy', 'identity_authority'}, 'rule': set(RULES),
         'grant': {'role', 'direct', 'connector'}, 'status': {'active', 'retired'}}
OWNERS = {'audit': {'audit'}, 'authz': {'authz'}, 'dlp': {'dlp'}, 'edr': {'detection'}, 'events': {'events'},
          'extensions': {'extensions'}, 'identity': {'identity'}, 'lineage': {'lineage'}, 'mdm': {'mdm', 'devices'},
          'pki': {'pki'}, 'platform': {'platform'}, 'policy': {'policy'}, 'radius': {'radius'}}
GRANTS = {'identity.authority.approve': 'direct', 'extensions.ca_callback.complete': 'connector'}


# Sole reviewed exception: docs/specs/permission-api-migration.md section 2.
# Implementation data only. No proposal in either tree or the working directory is authoritative.
_MIGRATION_BASE_DIGEST = '1966faf9ad11b86f5244747e8847fb56163187fc1c738c709bff466bbcb9615f'
_MIGRATION_DELTA_DIGEST = '09706e63ca1eaf7e1be223b5c456d8cf9cbbb588ba1f317db14658c9acf2b876'
_MIGRATION_RESULT_DIGEST = '78a1b1ecaef5fade010e8bdaad85b6d57e968639cbfbc826f17c58e579727621'
_ACTIVE_PROPOSAL = 'schemas/openapi/v1/catalogue-proposal.json'
_MIGRATION_DELTA_JSON = r'''{
  "base_revision": 3,
  "revision": 4,
  "add_permissions": [
    {
      "name": "identity.providers.create",
      "owner": "identity",
      "scope": "organization",
      "protection": "always",
      "approval": "identity_authority",
      "rule": "identity_authority",
      "grant": "role",
      "status": "active",
      "introduced": 4,
      "uses": [
        "createIdentityProvider"
      ],
      "source": "docs/specs/identity-login.md#5",
      "note": "Creating a provider adds an authentication authority; fresh authentication and an unaffected direct authority approver are required."
    },
    {
      "name": "identity.providers.delete",
      "owner": "identity",
      "scope": "organization",
      "protection": "always",
      "approval": "identity_authority",
      "rule": "identity_authority",
      "grant": "role",
      "status": "active",
      "introduced": 4,
      "uses": [
        "deleteIdentityProvider"
      ],
      "source": "docs/specs/identity-login.md#5",
      "note": "Deleting a provider removes an authentication authority and its links; fresh authentication and an unaffected direct authority approver are required."
    }
  ],
  "add_uses": [
    {
      "name": "authz.approvals.approve",
      "use": "approveApprovalRequest"
    },
    {
      "name": "authz.approvals.read",
      "use": "listApprovalRequests#all"
    },
    {
      "name": "authz.approvals.read",
      "use": "getApprovalRequest#any"
    },
    {
      "name": "authz.approvals.reject",
      "use": "rejectApprovalRequest"
    },
    {
      "name": "identity.authority.approve",
      "use": "approveIdentityAuthorityRequest"
    },
    {
      "name": "identity.authority.approve",
      "use": "rejectIdentityAuthorityRequest"
    },
    {
      "name": "identity.break_glass.create",
      "use": "createBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.delete",
      "use": "deleteBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.disable",
      "use": "disableBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.enable",
      "use": "enableBreakGlassAccount"
    },
    {
      "name": "identity.break_glass.read",
      "use": "listBreakGlassAccounts"
    },
    {
      "name": "identity.break_glass.replace_factor",
      "use": "replaceBreakGlassFactor"
    },
    {
      "name": "identity.break_glass.reset",
      "use": "resetBreakGlassAccount"
    },
    {
      "name": "identity.principal_links.read",
      "use": "listPrincipalLinks"
    },
    {
      "name": "identity.principal_links.read",
      "use": "listPrincipalLinkRequests"
    },
    {
      "name": "identity.principal_links.update",
      "use": "createPrincipalLink"
    },
    {
      "name": "identity.principal_links.update",
      "use": "deletePrincipalLink"
    },
    {
      "name": "identity.sessions.revoke",
      "use": "revokeUserSessions"
    },
    {
      "name": "authz.approvals.read",
      "use": "getApprovalRequestTargets#any"
    },
    {
      "name": "mdm.devices.read",
      "use": "streamChanges#devices"
    },
    {
      "name": "edr.alerts.read",
      "use": "streamChanges#alerts"
    },
    {
      "name": "dlp.findings.read",
      "use": "streamChanges#dlp-findings"
    },
    {
      "name": "mdm.enrollments.read",
      "use": "streamChanges#enrollments"
    },
    {
      "name": "pki.certificates.read",
      "use": "streamChanges#certificates"
    },
    {
      "name": "pki.infrastructure.read",
      "use": "streamChanges#certificates-infrastructure"
    },
    {
      "name": "mdm.rollouts.read",
      "use": "streamChanges#rollouts"
    },
    {
      "name": "extensions.packages.read",
      "use": "streamChanges#extensions"
    },
    {
      "name": "events.destinations.read",
      "use": "streamChanges#exports"
    },
    {
      "name": "mdm.devices.read",
      "use": "streamChanges#device"
    },
    {
      "name": "edr.alerts.read",
      "use": "streamChanges#alert"
    },
    {
      "name": "mdm.commands.read",
      "use": "streamChanges#commands"
    },
    {
      "name": "authz.approvals.read",
      "use": "streamChanges#approvals-all"
    }
  ]
}
'''


def schema_test():
    """Reuse the default validator's strict schema construction and lifecycle relations."""
    path = inventory.ROOT / 'server/internal/authz/catalogue/schema_test.py'
    spec = importlib.util.spec_from_file_location('permission_schema_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def blob(root, commit, path):
    """Read one regular-file blob from a commit without touching the working tree."""
    routing.sha(commit)
    routing.git(root, 'cat-file', '-e', commit + '^{commit}')
    entry = routing.git(root, 'ls-tree', '-z', commit, '--', path)
    if not entry:
        raise ValueError(f'{path} absent from commit {commit}')
    mode, kind, oid = entry.split(b'\t', 1)[0].split()
    # The executable bit is accepted like the other catalogue readers; links, gitlinks and trees are not.
    if mode not in (b'100644', b'100755') or kind != b'blob':
        raise ValueError(f'{path} in {commit} must be a regular file blob, not mode {mode.decode()} {kind.decode()}')
    if int(routing.git(root, 'cat-file', '-s', oid)) > MAX_BYTES:
        raise ValueError(f'{path} in {commit} exceeds {MAX_BYTES} bytes')
    return oid.decode(), routing.git(root, 'cat-file', 'blob', oid)


def bound_depth(text, what):
    """Reject container nesting beyond the Go parser's depth before recursive decoding."""
    level, in_string, escaped = 0, False, False
    for char in text:
        if in_string:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': in_string = False
        elif char == '"': in_string = True
        elif char in '[{':
            level += 1
            if level > MAX_DEPTH:
                raise ValueError(f'{what}: nesting depth exceeds {MAX_DEPTH}')
        elif char in ']}': level -= 1


def decode(data, what):
    """Strict wire profile: UTF-8, no BOM, bounded depth, unique keys, integer tokens only, one value."""
    if len(data) > MAX_BYTES:
        raise ValueError(f'{what}: exceeds {MAX_BYTES} bytes')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError(f'{what}: invalid UTF-8') from exc
    if text.startswith('﻿'):
        raise ValueError(f'{what}: byte-order mark')
    bound_depth(text, what)

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError(f'{what}: duplicate JSON member {key!r}')
            value[key] = item
        return value

    def reject(token):
        raise ValueError(f'{what}: non-integer number token {token!r}')
    def integer(token):
        if not re.fullmatch(r'0|[1-9][0-9]*', token):
            raise ValueError(f'{what}: signed integer token {token!r}')
        return int(token)

    def strings(value):
        if isinstance(value, str):
            if any(0xd800 <= ord(char) <= 0xdfff for char in value):
                raise ValueError(f'{what}: unpaired Unicode surrogate')
        elif isinstance(value, dict):
            for key, item in value.items():
                strings(key)
                strings(item)
        elif isinstance(value, list):
            for item in value:
                strings(item)

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=reject, parse_constant=reject)
        strings(value)
        return value
    except json.JSONDecodeError as exc:
        raise ValueError(f'{what}: invalid JSON: {exc.msg}') from exc


def load_validator(root, sha, module, what):
    oid, data = blob(root, sha, SCHEMA)
    schema = decode(data, what)
    if not isinstance(schema, dict):
        raise ValueError(f'{what}: schema root must be an object')
    try:
        return oid, module.validator(schema)
    except Exception as exc:  # jsonschema SchemaError, invalid regex, recursion: all fail closed.
        raise ValueError(f'{what}: invalid schema ({type(exc).__name__})') from exc


def uint(value, minimum):
    return type(value) is int and minimum <= value <= MAX_REVISION


def printable(value, limit):
    return isinstance(value, str) and 1 <= len(value) <= limit and PRINTABLE.fullmatch(value) is not None


def member(value, values):
    """Membership for decoded JSON: lists and objects are unhashable and never members."""
    return isinstance(value, str) and value in values


def invariants(cat):
    """Closed members, uint32 bounds, grammar, ASCII metadata and grant/owner/rule rules without a schema."""
    if not isinstance(cat, dict):
        return ['catalogue root must be an object']
    found = [f'unknown root member {key!r}' for key in sorted(set(cat) - ROOT_FIELDS)]
    if type(cat.get('format_version')) is not int or cat['format_version'] != 1:
        found.append(f'unsupported format_version {cat.get("format_version")!r}')
    if not uint(cat.get('revision'), 1):
        found.append(f'revision {cat.get("revision")!r} outside 1..{MAX_REVISION}')
    rows = cat.get('permissions')
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ENTRIES:
        found.append(f'permissions must hold 1..{MAX_ENTRIES} entries')
        return found
    names = []
    for index, p in enumerate(rows):
        if not isinstance(p, dict):
            found.append(f'permissions[{index}] must be an object')
            continue
        name = p.get('name')
        valid_name = isinstance(name, str) and NAME_LENGTH[0] <= len(name) <= NAME_LENGTH[1] and NAME.fullmatch(name) is not None
        label = name if valid_name else f'permissions[{index}]'
        if not valid_name:
            found.append(f'{label}: name grammar violated')
        if isinstance(name, str):
            names.append(name)
        expected = ENTRY_FIELDS | ({'retired_in'} if p.get('status') == 'retired' else set())
        found += [f'{label}: unknown member {key!r}' for key in sorted(set(p) - expected)]
        found += [f'{label}: missing member {key!r}' for key in sorted(expected - set(p))]
        for field, values in ENUMS.items():
            if not member(p.get(field), values):
                found.append(f'{label}: {field} must be one of {sorted(values)}')
        rule = p.get('rule')
        if member(rule, RULES) and (p.get('protection'), p.get('approval')) != RULES[rule]:
            found.append(f'{label}: protection/approval must be {RULES[rule]} for rule {rule!r}')
        if valid_name:
            owners = OWNERS.get(name.split('.')[0])
            if owners is None:
                found.append(f'{label}: namespace unknown')
            elif not member(p.get('owner'), owners):
                found.append(f'{label}: owner must be one of {sorted(owners)}')
            if p.get('grant') != GRANTS.get(name, 'role'):
                found.append(f'{label}: grant must be {GRANTS.get(name, "role")!r}')
        if not uint(p.get('introduced'), 1):
            found.append(f'{label}: introduced {p.get("introduced")!r} outside 1..{MAX_REVISION}')
        if 'retired_in' in p and not uint(p['retired_in'], 2):
            found.append(f'{label}: retired_in {p["retired_in"]!r} outside 2..{MAX_REVISION}')
        uses = p.get('uses')
        if not (isinstance(uses, list) and USES[0] <= len(uses) <= USES[1]
                and all(printable(u, USES[2]) for u in uses) and len(set(uses)) == len(uses)):
            found.append(f'{label}: uses must be {USES[0]}..{USES[1]} unique printable ASCII strings of 1..{USES[2]} bytes')
        for field, limit in TEXT_BYTES.items():
            if not printable(p.get(field), limit):
                found.append(f'{label}: {field} must be 1..{limit} printable ASCII bytes')
    if len(names) != len(rows) or names != sorted(set(names)):
        found.append('names must be unique and strictly ascending')
    return found


def validate(cat, validator, lifecycle, what):
    """Independent invariants, then the commit's own schema, then lifecycle relations."""
    found = invariants(cat)
    if found:
        raise ValueError('\n'.join(f'{what}: {defect}' for defect in found))
    errors = sorted(validator.iter_errors(cat), key=lambda e: e.json_path)
    if errors:
        raise ValueError(f'{what}: schema: {errors[0].json_path}: {errors[0].message}')
    try:
        lifecycle(cat)
    except ValueError as exc:
        raise ValueError(f'{what}: lifecycle: {exc}') from exc


def _comparison_digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(',', ':')).encode('ascii')).hexdigest()


def _recompose_migration(base, delta):
    """Append the reviewed selectors in order, preserving every existing row and field."""
    if (not isinstance(delta, dict)
            or set(delta) != {'base_revision', 'revision', 'add_permissions', 'add_uses'}
            or delta['base_revision'] != 3 or delta['revision'] != 4
            or len(delta['add_permissions']) != 2 or len(delta['add_uses']) != 32):
        raise ValueError('invalid embedded migration delta shape')
    result = copy.deepcopy(base)
    rows = {p['name']: p for p in result['permissions']}
    for row in delta['add_permissions']:
        if row['name'] in rows or row['introduced'] != 4 or row['status'] != 'active':
            raise ValueError('invalid embedded migration new name')
        added = copy.deepcopy(row)
        rows[added['name']] = added
        result['permissions'].append(added)
    targets = set()
    for item in delta['add_uses']:
        if set(item) != {'name', 'use'}:
            raise ValueError('invalid embedded migration selector shape')
        row = rows.get(item['name'])
        if row is None or row['status'] != 'active' or item['use'] in row['uses']:
            raise ValueError('invalid embedded migration selector target')
        targets.add(item['name'])
        row['uses'].append(item['use'])
    if len(targets) != 24:
        raise ValueError('invalid embedded migration target count')
    result['permissions'].sort(key=lambda p: p['name'])
    result['revision'] = 4
    return result


def _migration_pair(base, candidate, schema_changed):
    """Waive only uses differences in this complete pinned, independently recomposed pair."""
    if (schema_changed or _comparison_digest(base) != _MIGRATION_BASE_DIGEST
            or _comparison_digest(candidate) != _MIGRATION_RESULT_DIGEST):
        return False
    if not isinstance(_MIGRATION_DELTA_JSON, str):
        raise ValueError('missing embedded migration delta')
    delta = decode(_MIGRATION_DELTA_JSON.encode('utf-8'), 'embedded migration delta')
    if _comparison_digest(delta) != _MIGRATION_DELTA_DIGEST:
        raise ValueError('embedded migration delta digest mismatch')
    recomputed = _recompose_migration(base, delta)
    if recomputed != candidate or _comparison_digest(recomputed) != _MIGRATION_RESULT_DIGEST:
        raise ValueError('recomputed migration result differs from candidate or pinned digest')
    return True


def defects(base, cand, schema_changed=False):
    """Apply permission catalogue section 2 lifecycle rules between two validated catalogues."""
    found = []
    migration = _migration_pair(base, cand, schema_changed)
    rb, rc = base['revision'], cand['revision']
    if rc < rb:
        found.append(f'revision decreased from {rb} to {rc}')
    if base != cand and rc == rb:
        found.append(f'decoded content changed without a revision increase (revision {rb})')
    if schema_changed and rc == rb:
        found.append(f'schema changed without a revision increase (revision {rb}); a validation contract change must be explicit')
    base_rows = {p['name']: p for p in base['permissions']}
    cand_rows = {p['name']: p for p in cand['permissions']}
    for name, b in base_rows.items():
        c = cand_rows.get(name)
        if c is None:
            found.append(f'{name}: deleted; names are permanent')
            continue
        if b['status'] == 'retired':
            if c != b:
                found.append(f'{name}: tombstone changed; retired rows keep all metadata and retired_in')
            continue
        for field in IMMUTABLE:
            if b[field] != c[field]:
                found.append(f'{name}: {field} changed from {b[field]!r} to {c[field]!r}; introduce a new name')
        if sorted(b['uses']) != sorted(c['uses']) and not migration:
            found.append(f'{name}: uses changed; any uses change is semantic, introduce a new name')
        if c['status'] == 'retired' and not rb < c['retired_in'] <= rc:
            found.append(f'{name}: retired_in {c["retired_in"]} must exceed base revision {rb} and not exceed {rc}')
    for name, c in cand_rows.items():
        if name not in base_rows and not rb < c['introduced'] <= rc:
            found.append(f'{name}: new name introduced {c["introduced"]} must exceed base revision {rb} and not exceed {rc}')
    return found


def compare(root, base_sha, candidate_sha):
    """Read both catalogues from Git objects and return the report, or raise with every defect."""
    base_sha, candidate_sha = routing.sha(base_sha), routing.sha(candidate_sha)
    if base_sha == candidate_sha:
        raise ValueError(f'base and candidate name the same commit {base_sha}')
    module = schema_test()
    report = {'unchanged': False, 'schema_changed': False}
    data, validators, headers = {}, {}, []
    for what, sha in (('base', base_sha), ('candidate', candidate_sha)):
        try:
            # Log the commit and catalogue blob before the schema loads, so a schema failure still names them.
            headers.append(f'{what} commit {sha}')
            print(headers[-1], flush=True)
            oid, data[what] = blob(root, sha, CATALOGUE)
            headers[-1] += f' catalogue blob {oid}'
            print(f'{what} catalogue blob {oid}', flush=True)
            schema_oid, validators[what] = load_validator(root, sha, module, what + ' schema')
            headers[-1] += f' schema blob {schema_oid}'
            print(f'{what} schema blob {schema_oid}', flush=True)
            cat = decode(data[what], what)
            validate(cat, validators[what], module.lifecycle, what)
        except ValueError as exc:
            raise ValueError('\n'.join(headers + [str(exc)])) from None
        report[what] = {'sha': sha, 'blob': oid, 'schema': schema_oid, 'revision': cat['revision'], 'catalogue': cat}
        print(f'{what} revision {cat["revision"]}', flush=True)
    report['unchanged'] = data['base'] == data['candidate']
    report['schema_changed'] = report['base']['schema'] != report['candidate']['schema']
    if report['schema_changed']:
        rejected = sorted(validators['base'].iter_errors(report['candidate']['catalogue']), key=lambda e: e.json_path)
        print('candidate schema differs from the base schema; the reviewed base schema '
              + (f'rejects the candidate at {rejected[0].json_path}' if rejected else 'still accepts the candidate'),
              flush=True)
    if _migration_pair(report['base']['catalogue'], report['candidate']['catalogue'], report['schema_changed']):
        # ls-tree also detects a symlink, executable, tree or gitlink at this exact path.
        if routing.git(root, 'ls-tree', '-z', candidate_sha, '--', _ACTIVE_PROPOSAL):
            raise ValueError('candidate active proposal must be absent for the pinned migration')
    found = defects(report['base']['catalogue'], report['candidate']['catalogue'], report['schema_changed'])
    if found:
        raise ValueError('\n'.join(headers + [f'catalogue incompatible with reviewed base {base_sha}:']
                                   + ['- ' + d for d in found]))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--base-sha', required=True)
    parser.add_argument('--candidate-sha', required=True)
    args = parser.parse_args()
    env = os.environ
    try:
        base, candidate = routing.sha(args.base_sha), routing.sha(args.candidate_sha)
        event = required.load(Path(env['GITHUB_EVENT_PATH']))
        full = env['GITHUB_EVENT_NAME'] == 'push' and str(event.get('ref', '')).startswith('refs/tags/')
        admitted = routing.build_route(env['GITHUB_EVENT_NAME'], event, args.root, env, full=full)
        if (base, candidate) != (admitted['baseSha'], admitted['testedSha']):
            raise ValueError('base/candidate substitution: arguments must equal the validated event pair '
                             f"{admitted['baseSha']} and {admitted['testedSha']}")
        report = compare(args.root, base, candidate)
    except Exception as exc:  # Every failure is closed, structured and traceback-free.
        detail = str(exc) or type(exc).__name__
        if isinstance(exc, KeyError):
            detail = 'missing environment or event member ' + detail
        raise SystemExit(f'catalogue compatibility failed: {detail}') from None
    state = 'bytes unchanged' if report['unchanged'] else 'compatible with the reviewed base'
    print(f"Permission catalogue {state}: base revision {report['base']['revision']}, "
          f"candidate revision {report['candidate']['revision']}")


if __name__ == '__main__':
    main()
