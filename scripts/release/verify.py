"""Verify unsigned development records, files and embedded public identities.

Inventory v1 is closed JSON: {schemaVersion: 1, records: [{name, target,
image: bool, artifacts: [{name, component, format, identityPaths}]}], evidence:
[basename]}. Formats are tar.gz, tar, zip, identity and sbom. Archive identityPaths
name JSON documents inside the archive. Identity files use [""], SBOMs use [].
Every shipped component needs an identity-bearing artifact. Only artifact names
expand {version} once from the independently derived expected identity. SHA256SUMS covers all
record, artifact and evidence files and lives in the artifacts directory.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys

import tempfile

import archives
from snapshot import Snapshot
from release_common import (SCHEMA, RECORD_VALIDATOR, INVENTORY_VALIDATOR,
                            IDENTITY_LIMIT, CONTROL_LIMIT, basename, bounded_read,
                            check_identity, fail, load, member_name,
                            parents, regular, validate)

ROOT = Path(__file__).resolve().parents[2]
COMPONENT = r'[a-z][a-z0-9.-]{0,127}'
TARGETS = SCHEMA['properties']['target']['enum']


def closed(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(label, 'expected exactly ' + ', '.join(keys))


def distinct(names, label):
    seen = set()
    for name in names:
        folded = name.casefold()
        if folded in seen:
            fail(label, 'duplicate or case-colliding name ' + name)
        seen.add(folded)


def inventory(path, expected):
    data = load(path)
    label = 'inventory ' + str(path)
    validate(INVENTORY_VALIDATOR, data, label)
    closed(data, ('schemaVersion', 'records', 'evidence'), label)
    if type(data['schemaVersion']) is not int or data['schemaVersion'] != 1:
        fail(label, 'unsupported schemaVersion')
    if not isinstance(data['records'], list) or not data['records']:
        fail(label, 'records must be a nonempty list')
    if not isinstance(data['evidence'], list):
        fail(label, 'evidence must be a list')
    all_names = ['SHA256SUMS']
    for record in data['records']:
        closed(record, ('name', 'target', 'image', 'artifacts'), label)
        basename(record['name'], label)
        all_names.append(record['name'])
        if record['target'] not in TARGETS or type(record['image']) is not bool:
            fail(label, record['name'] + ': invalid target or image flag')
        if record['image'] and record['target'] not in ('linux-x64', 'linux-arm64'):
            fail(label, record['name'] + ': image requires a Linux server target')
        if not isinstance(record['artifacts'], list) or not record['artifacts']:
            fail(label, record['name'] + ': artifacts must be nonempty')
        components, identified = set(), set()
        for artifact in record['artifacts']:
            closed(artifact, ('name', 'component', 'format', 'identityPaths'), label)
            name = artifact['name']
            if '{version}' in name:
                name = name.replace('{version}', expected['version'], 1)
            basename(name, label)
            artifact['name'] = name
            all_names.append(artifact['name'])
            if not isinstance(artifact['component'], str) or not re.fullmatch(COMPONENT, artifact['component']):
                fail(label, artifact['name'] + ': invalid component')
            kind, paths = artifact['format'], artifact['identityPaths']
            if kind not in ('tar.gz', 'tar', 'zip', 'identity', 'sbom') or not isinstance(paths, list):
                fail(label, artifact['name'] + ': invalid format or identityPaths')
            components.add(artifact['component'])
            if kind == 'sbom':
                if paths:
                    fail(label, artifact['name'] + ': SBOM cannot supply identity')
            else:
                if kind == 'identity':
                    if paths != ['']:
                        fail(label, artifact['name'] + ': identity file requires [""]')
                else:
                    if not paths:
                        fail(label, artifact['name'] + ': archive requires identityPaths')
                    for name in paths:
                        member_name(name, label)
                    distinct(paths, label)
                identified.add(artifact['component'])
        if not components or components != identified:
            fail(label, record['name'] + ': missing component identity')
    for name in data['evidence']:
        basename(name, label)
        if not name.endswith(('.tar.gz', '.tar', '.zip')):
            fail(label, 'evidence must be an archive')
        all_names.append(name)
    distinct(all_names, label)
    return data


def directory(path, expected):
    parents(path)
    if not path.is_dir():
        fail(str(path), 'expected directory without symlink')
    files = {}
    for path in path.iterdir():
        basename(path.name, str(path))
        files[path.name] = regular(path)
    distinct(files, str(path))
    if set(files) != set(expected):
        fail(str(path), f'missing={sorted(set(expected) - files.keys())}, extra={sorted(files.keys() - set(expected))}')
    return files


def digest(path):
    value = hashlib.sha256()
    with regular(path).open('rb') as stream:
        while data := stream.read(65536):
            value.update(data)
    return value.hexdigest()


def archive_identities(path, recipe, expected):
    archives.check(path, recipe['format'], recipe['identityPaths'], expected)


def verify(records, artifacts, inventory_path, expected_path):
    """Candidate bytes never set the expected identity; no artifact is executed."""
    for candidate in (records, artifacts):
        if expected_path.resolve().is_relative_to(candidate.resolve()):
            fail('expected identity', 'must be outside candidate directories')
        if inventory_path.resolve().is_relative_to(candidate.resolve()):
            fail('inventory', 'must be outside candidate directories')
    expected = load(expected_path, IDENTITY_LIMIT)
    check_identity(expected, None, 'expected identity')
    recipes = inventory(inventory_path, expected)
    record_files = directory(records, [r['name'] for r in recipes['records']])
    artifact_names = [a['name'] for r in recipes['records'] for a in r['artifacts']]
    artifact_files = directory(artifacts, artifact_names + recipes['evidence'] + ['SHA256SUMS'])
    for recipe in recipes['records']:
        label = recipe['name']
        record = load(record_files[label])
        validate(RECORD_VALIDATOR, record, label)
        if type(record['schemaVersion']) is not int:
            fail(label, 'schemaVersion must be integer')
        if any(type(row['bytes']) is not int for row in record['artifacts']):
            fail(label, 'artifact bytes must be integer')
        check_identity(record['identity'], expected, label)
        if record['target'] != recipe['target'] or ('image' in record) != recipe['image']:
            fail(label, 'target or image metadata differs from inventory')
        names = [a['name'] for a in record['artifacts']]
        distinct(names, label)
        rows = {a['name']: a for a in record['artifacts']}
        required = {a['name'] for a in recipe['artifacts']}
        if set(rows) != required:
            fail(label, f'missing={sorted(required - rows.keys())}, extra={sorted(rows.keys() - required)}')
        for artifact in recipe['artifacts']:
            name = artifact['name']
            row, path = rows[name], artifact_files[name]
            if row['component'] != artifact['component']:
                fail(name, 'component differs from inventory')
            if path.stat().st_size != row['bytes'] or digest(path) != row['sha256']:
                fail(name, 'byte count or SHA-256 mismatch')
            try:
                if artifact['format'] == 'identity':
                    check_identity(load(path, IDENTITY_LIMIT), expected, name)
                elif artifact['format'] != 'sbom':
                    archive_identities(path, artifact, expected)
            except (OSError, ValueError, RuntimeError) as error:
                fail(name, str(error))
    for name in recipes['evidence']:
        kind = 'tar.gz' if name.endswith('.tar.gz') else ('tar' if name.endswith('.tar') else 'zip')
        archive_identities(artifact_files[name], {'format': kind, 'identityPaths': []}, expected)
    files = dict(record_files, **{k: v for k, v in artifact_files.items() if k != 'SHA256SUMS'})
    checksum = bounded_read(artifact_files['SHA256SUMS'], CONTROL_LIMIT)
    expected_sums = ''.join(f'{digest(files[name])}  {name}\n' for name in sorted(files)).encode('ascii')
    if checksum != expected_sums:
        fail('SHA256SUMS', 'expected complete sorted lowercase digest/basename entries with LF')
    print(f'Verified unsigned development files: {len(record_files)} records, {len(files)} files')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('records', 'artifacts', 'inventory', 'expected-identity'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    for candidate in (args.records, args.artifacts):
        for trusted in (args.inventory, args.expected_identity):
            if trusted.resolve().is_relative_to(candidate.resolve()):
                fail(trusted.name, 'trusted input must be outside candidate directories')
    # Inputs are the job-owned handoff, with producers already isolated. Copy
    # once more into private custody and retain those bytes through validation.
    with tempfile.TemporaryDirectory(prefix='ricevanta-verify-snapshot-') as temporary:
        snapshot = Snapshot(Path(temporary) / 'sealed')
        try:
            snapshot.copy(args.records, args.artifacts)
            snapshot.seal()
            snapshot.consume(lambda records, artifacts: verify(records, artifacts, args.inventory, args.expected_identity))
        finally:
            snapshot.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))
