"""Validate fixture contracts with Draft 2020-12; format annotations stay off."""

import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
DIRECTORIES = (
    "schemas/dsse/v1",
    "schemas/events/v1",
    "schemas/cel/v1",
    "schemas/agent/spool/v1",
    "schemas/extension/v1alpha1",
)
# These files describe the event protocol rather than fixture instances.
NON_FIXTURES = {
    "schemas/events/v1/contract.json",
    "schemas/events/v1/header.abnf",
}
# Each pair names a complete document or a fixture suite with embedded instances.
CONTRACTS = (
    ("schemas/dsse/v1/vectors.schema.json", "schemas/dsse/v1/vectors.json"),
    ("schemas/dsse/v1/envelope.schema.json", "schemas/dsse/v1/vectors.json"),
    ("schemas/events/v1/fixture.schema.json", "schemas/events/v1/fixtures/header.json"),
    ("schemas/events/v1/fixture.schema.json", "schemas/events/v1/fixtures/descriptor.json"),
    ("schemas/events/v1/fixture.schema.json", "schemas/events/v1/fixtures/response.json"),
    ("schemas/events/v1/body-fixture.schema.json", "schemas/events/v1/fixtures/body.json"),
    ("schemas/events/v1/response.schema.json", "schemas/events/v1/fixtures/response.json"),
    ("schemas/cel/v1/declarations.schema.json", "schemas/cel/v1/variables.json"),
    ("schemas/cel/v1/declarations.schema.json", "schemas/cel/v1/fixtures.json"),
    ("schemas/agent/spool/v1/fixture.schema.json", "schemas/agent/spool/v1/fixtures.json"),
    ("schemas/agent/spool/v1/fixture.schema.json", "schemas/agent/spool/v1/schema-cases.json"),
    ("schemas/extension/v1alpha1/manifest.schema.json", "schemas/extension/v1alpha1/fixtures.json"),
    ("schemas/extension/v1alpha1/fixtures.schema.json", "schemas/extension/v1alpha1/fixtures.json"),
    ("schemas/extension/v1alpha1/loader-vectors.schema.json", "schemas/extension/v1alpha1/loader-vectors.json"),
)


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_path(fixture, reference):
    directory = (ROOT / Path(fixture).parent / "fixtures").resolve()
    path = (ROOT / Path(fixture).parent / reference).resolve()
    if not path.is_relative_to(directory):
        raise ValueError(f"{fixture}: path outside fixture directory: {reference}")
    return path


def instances(schema, fixture, data):
    """Yield label, instance and expected schema validity, not semantic validity."""
    if schema == "schemas/extension/v1alpha1/manifest.schema.json":
        for case in data["cases"]:
            yield case["name"], case["manifest"], case["schema_valid"]
    elif schema.endswith("/envelope.schema.json"):
        # Negative DSSE vectors include parse and cryptographic failures. Their
        # semantic expectations belong to Go tests, not JSON Schema validation.
        for case in data["positive"]:
            for field in ("envelope_hex", "canonical_envelope_hex"):
                yield f'{case["name"]}/{field}', json.loads(bytes.fromhex(case[field])), True
    elif schema.endswith("/response.schema.json"):
        for case in data["cases"]:
            yield case["name"], case["body"], case["schema_valid"]
    elif fixture.endswith("/cel/v1/fixtures.json"):
        if data["schema"] != Path(schema).name:
            raise ValueError(f"{fixture}: unexpected schema name")
        for case in data["cases"]:
            path = manifest_path(fixture, case["file"])
            yield case["file"], load(path), case["schema_valid"]
    elif fixture.endswith("/schema-cases.json"):
        if data["schema"] != Path(schema).name:
            raise ValueError(f"{fixture}: unexpected schema name")
        for case in data["cases"]:
            yield case["id"], case["instance"], case["valid"]
    else:
        yield fixture, data, True


def main():
    listed = {schema for schema, _ in CONTRACTS}
    discovered = {
        str(path.relative_to(ROOT))
        for directory in DIRECTORIES
        for path in (ROOT / directory).rglob("*.schema.json")
    }
    if discovered != listed:
        raise ValueError(
            f"Schema inventory mismatch: unlisted={sorted(discovered - listed)}, "
            f"missing={sorted(listed - discovered)}"
        )
    fixtures = {fixture for _, fixture in CONTRACTS}
    for fixture in sorted(fixtures):
        if fixture.endswith("/cel/v1/fixtures.json"):
            for case in load(ROOT / fixture)["cases"]:
                path = manifest_path(fixture, case["file"])
                fixtures.add(str(path.relative_to(ROOT)))
    discovered_fixtures = {
        str(path.relative_to(ROOT))
        for directory in DIRECTORIES
        for path in (ROOT / directory).rglob("*")
        if path.is_file() and not path.name.endswith(".schema.json")
    } - NON_FIXTURES
    if discovered_fixtures != fixtures:
        raise ValueError(
            f"Fixture inventory mismatch: unlisted={sorted(discovered_fixtures - fixtures)}, "
            f"missing={sorted(fixtures - discovered_fixtures)}"
        )
    count = 0
    for schema, fixture in CONTRACTS:
        definition = load(ROOT / schema)
        if definition.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ValueError(f"{schema}: expected Draft 2020-12")
        Draft202012Validator.check_schema(definition)
        validator = Draft202012Validator(definition)
        cases = list(instances(schema, fixture, load(ROOT / fixture)))
        if not cases:
            raise ValueError(f"{fixture}: empty fixture suite")
        for label, instance, expected in cases:
            if type(expected) is not bool:
                raise ValueError(f"{fixture}/{label}: validity flag must be boolean")
            errors = list(validator.iter_errors(instance))
            if (not errors) != expected:
                detail = errors[0].message if errors else "expected an invalid instance"
                raise ValueError(f"{schema} <- {fixture}/{label}: {detail}")
            count += 1
    print(f"Contract validation passed: {len(listed)} schemas, {len(CONTRACTS)} pairs, {count} instances")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))
