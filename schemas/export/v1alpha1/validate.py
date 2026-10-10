"""Check export contracts, shared fixtures, profile classes and resource examples."""
import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import yaml

ADAPTERS = {'elasticsearch', 'opensearch', 'splunk_hec', 'syslog', 'otlp',
            'loki', 'sentinel', 'kafka', 's3', 'connector'}


def _refuse(uri):
    raise ValueError('Nonlocal schema reference')


def _references(value, resolver):
    if isinstance(value, dict):
        if '$id' in value:
            resolver = resolver.in_subresource(Resource.from_contents(value))
        # Lookup every reference, including definitions unused by fixtures.
        for keyword in ('$ref', '$dynamicRef'):
            if keyword in value:
                resolver.lookup(value[keyword])
        for child in value.values():
            _references(child, resolver)
    elif isinstance(value, list):
        for child in value:
            _references(child, resolver)


def _profile_classes(text):
    classes = set()
    section = 0
    for line in text.splitlines():
        match = re.match(r'## (\d+)\.', line)
        if match:
            section = int(match[1])
        if not line.startswith('|'):
            continue
        columns = [part.strip() for part in line.strip('|').split('|')]
        if section == 1 and len(columns) == 5:
            classes.update(re.findall(r'`([a-z][a-z0-9_/]*)`', columns[2]))
        elif section == 2 and len(columns) == 3 and columns[1].startswith('Class'):
            classes.update('ricevanta/' + name for name in re.findall(r'`([a-z][a-z0-9_]*)`', columns[0]))
    return classes


def _check(root):
    directory = root / 'schemas/export/v1alpha1'
    failures = []
    try:
        schemas = [json.loads((directory / name).read_text()) for name in
                   ('export-destination.json', 'fixtures.schema.json')]
        for schema in schemas:
            Draft202012Validator.check_schema(schema)
        registry = Registry(retrieve=_refuse).with_resources(
            (schema['$id'], Resource.from_contents(schema)) for schema in schemas)
        for schema in schemas:
            _references(schema, registry.resolver(schema['$id']))
        resource_validator, manifest_validator = [Draft202012Validator(s, registry=registry) for s in schemas]
    except Exception:
        return ['Export schema loading or reference check failed'], 0, 0
    try:
        manifest = json.loads((directory / 'fixtures.json').read_text())
        if not manifest_validator.is_valid(manifest):
            return ['Export fixture manifest shape failed'], 0, 0
        cases = manifest['cases']
        if len({case['id'] for case in cases}) != len(cases):
            failures.append('Export fixture IDs are duplicated')
        coverage = set()
        for index, case in enumerate(cases):
            accepted = resource_validator.is_valid(case['resource'])
            if accepted != case['valid']:
                failures.append(f'Export fixture outcome failed at case {index + 1}')
            if accepted and case['valid']:
                coverage.add(case['resource']['spec']['type'])
        if coverage != ADAPTERS:
            failures.append('Export positive adapter coverage failed')
        classes = schemas[0]['$defs']['class']['enum']
        profile = (root / 'docs/specs/ocsf-profile.md').read_text()
        if len(set(classes)) != len(classes) or set(classes) != _profile_classes(profile):
            failures.append('Export profile class enum differs')
        selections = [c for c in cases if c['id'] == 'valid-selection']
        if len(selections) != 1 or set(selections[0]['resource']['spec']['filter']['classes']) != set(classes):
            failures.append('Export all-classes fixture differs')
        examples = 0
        for name in ('export-destination-schema.md', 'event-export.md'):
            text = (root / 'docs/specs' / name).read_text()
            for language, block in re.findall(r'```(json|yaml)\n(.*?)\n```', text, re.S):
                documents = [json.loads(block)] if language == 'json' else yaml.safe_load_all(block)
                for document in documents:
                    # Field fragments have no resource envelope and are not examples.
                    if not isinstance(document, dict) or not ({'apiVersion', 'kind'} <= document.keys()):
                        continue
                    if document['kind'] != 'ExportDestination':
                        failures.append('Export example has an unknown resource kind')
                        continue
                    examples += 1
                    if not resource_validator.is_valid(document):
                        failures.append('Export resource example failed')
        if not examples:
            failures.append('No ExportDestination example validated')
        return failures, len(cases), examples
    except Exception:
        return failures + ['Export fixtures, profile or examples could not be checked'], 0, 0


def validate(root: Path) -> list[str]:
    """Return safe failure labels without exposing resource content."""
    return _check(root)[0]


def main() -> int:
    failures, cases, examples = _check(Path(__file__).resolve().parents[3])
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'Validated 2 schemas, {cases} fixtures and {examples} resource examples')
    return 0


if __name__ == '__main__':
    sys.exit(main())
