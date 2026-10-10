"""Validate policy contracts and fixtures: python3 schemas/policy/v1alpha1/validate.py."""

import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from rfc3339_validator import validate_rfc3339
import yaml


def main():
    root = Path(__file__).resolve().parents[3]
    directory = Path(__file__).resolve().parent
    required = {"policy.schema.json": "Policy", "exception.schema.json": "Exception"}
    missing = [name for name in required if not (directory / name).is_file()]
    if missing:
        print("\n".join(f"Missing required schema: {name}" for name in missing), file=sys.stderr)
        return 1
    formats = FormatChecker(formats=[])
    formats.checks("date-time")(lambda value: not isinstance(value, str) or (value == value.strip() and validate_rfc3339(value.upper())))
    validators = {}
    schemas = []
    for path in sorted(directory.glob('*.schema.json')):
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        schemas.append(schema)
    registry = Registry().with_resources((schema['$id'], Resource.from_contents(schema)) for schema in schemas)
    for schema in schemas:
        validators[schema['title']] = Draft202012Validator(schema, registry=registry, format_checker=formats)
    failures = []
    for name, kind in required.items():
        if json.loads((directory / name).read_text()).get("title") != kind:
            failures.append(f"Required schema {name} must have title {kind}")
    expected_errors = json.loads((directory / "fixtures/expected-errors.json").read_text())
    invalid_names = {path.name for path in (directory / "fixtures/invalid").glob("*.json")}
    if invalid_names != set(expected_errors):
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
    spec = root / 'docs/specs/policy-envelope.md'
    examples = {kind: 0 for kind in required.values()}
    for block in re.findall(r'```yaml\n(.*?)\n```', spec.read_text(), re.S):
        for document in yaml.safe_load_all(block):
            if not isinstance(document, dict) or 'apiVersion' not in document or 'kind' not in document:
                failures.append(f'{spec.relative_to(root)}: Resource example requires apiVersion and kind')
                continue
            kind = document['kind']
            if kind not in examples:
                failures.append(f'{spec.relative_to(root)}: Unknown resource kind: {kind}')
                continue
            examples[kind] += 1
            for error in validators[document['kind']].iter_errors(document):
                failures.append(f'{spec.relative_to(root)} {document["kind"]} example: {error.message}')
    for kind, count_for_kind in examples.items():
        if not count_for_kind:
            failures.append(f'No {kind} example validated')
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'Validated {len(validators)} schemas, {count} fixtures and {sum(examples.values())} YAML examples')
    return 0


if __name__ == '__main__':
    sys.exit(main())
