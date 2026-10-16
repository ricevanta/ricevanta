"""Rebuild admission-vectors.json from reviewed recipes, without Git or Go.

Run with the design validator's pinned Python environment. Only the vectors
are generated; schemas and schema cases are reviewed inputs and are validated.
The digest projection follows extension-admission-contracts.md section 3.
"""

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from admission_vector_recipes import RECIPES


HERE = Path(__file__).resolve().parent


def canonical(value):
    """JCS for the contract's ASCII strings and exact integer subset only."""
    if isinstance(value, str):
        if not value.isascii():
            raise ValueError("non-ASCII digest input")
        # JCS leaves DEL literal; ensure_ascii=True would escape it.
        return json.dumps(value, ensure_ascii=False)
    if value is None or type(value) is bool:
        return json.dumps(value)
    if type(value) is int and abs(value) <= 2**53:
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            canonical(key) + ":" + canonical(value[key]) for key in sorted(value)
        ) + "}"
    raise ValueError("value outside the closed digest types")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def canonical_sets(value):
    """All arrays inside grant values are sets, including nested slot maps."""
    if isinstance(value, dict):
        return {key: canonical_sets(item) for key, item in value.items()}
    if isinstance(value, list):
        items = [canonical_sets(item) for item in value]
        return sorted(items, key=lambda item: item if isinstance(item, str) else canonical(item))
    return value


def select(value, fields):
    return {field: value[field] for field in fields.split()}


def covers(entry, package_id):
    return any(package_id == prefix or package_id.startswith(prefix + ".") for prefix in entry["prefixes"])


def digests(case):
    evidence, snapshot, request = (case[key] for key in ("evidence", "snapshot", "request"))
    document = evidence["document"]
    metadata = document["metadata"]
    package_id, version, publisher = metadata["id"], metadata["version"], metadata["publisher"]["key"]
    entry = next(item for item in snapshot["trust_list"] if item["fingerprint"] == publisher)
    trust = select(entry, "fingerprint generation prefixes project_publisher revoked retired")
    trust["prefixes"] = sorted(trust["prefixes"])
    ownership = deepcopy(snapshot["ownership"])
    if ownership is not None:
        ownership["prior_owners"] = sorted(ownership["prior_owners"])
    install = snapshot["install"]
    if install is not None:
        install = select(install, "version package_sha256 state enabled generation targets grants")
        install["targets"] = canonical_sets(install["targets"])
        install["grants"] = sorted([
            dict(select(record["grant"], "component"),
                 **select(record, "recovery_epoch grant_generation"),
                 values=canonical_sets(record["grant"]["values"]))
            for record in install["grants"]
        ], key=lambda item: item["component"])
    registration_ids = {
        component["capabilities"]["registration"]
        for component in document["spec"]["components"] if component["kind"] == "browser-adapter"
    }
    registrations = []
    for record in snapshot["registrations"]:
        if record["id"] in registration_ids:
            projected = select(record, "id recovery_epoch registration_generation os")
            projected["os"] = canonical_sets(projected["os"])
            projected["bound"] = record.get("bound")
            registrations.append(projected)
    closure = dict(
        profile="ricevanta-extension-admission-closure-v1",
        **select(snapshot, "recovery_epoch approval_policy_disabled approval_policy_generation"),
        release=select(snapshot, "first_start release_version") if request["source"] == "server-image" else None,
        automatic_release_floor=snapshot["automatic_release_floor"] if covers({"prefixes": ["io.ricevanta"]}, package_id) else None,
        id=package_id, version=version, trust_entry=trust,
        covering=sorted(item["fingerprint"] for item in snapshot["trust_list"] if not item["retired"] and covers(item, package_id)),
        revocations=sorted(snapshot["revocations"], key=canonical),
        revocation_generation=snapshot["revocation_generation"], ownership=ownership,
        tombstone=next((item for item in snapshot["tombstones"] if item["version"] == version), None),
        install=install, registrations=sorted(registrations, key=lambda item: item["id"]),
        served_interfaces=sorted({interface for interfaces in document["spec"]["requires"].values() for interface in interfaces}),
        disclosure_profiles=sorted({grant["values"]["disclosure_profile"] for grant in request["grants"] if "disclosure_profile" in grant["values"]}),
        device_groups=sorted(request["targets"]["device_groups"]),
    )
    closure_digest = digest(closure)
    frozen = dict(
        profile="ricevanta-extension-admission-request-v1", id=package_id, version=version, publisher=publisher,
        **select(evidence, "package_sha256 manifest_sha256 envelope_sha256"),
        recovery_epoch=snapshot["recovery_epoch"], operation=case["expected"]["operation"],
        **select(request, "source requester"),
        grants=sorted((canonical_sets(grant) for grant in request["grants"]), key=lambda item: item["component"]),
        targets=canonical_sets(request["targets"]), closure=closure_digest,
    )
    return closure_digest, digest(frozen)


def build():
    cases = {}
    for name, parent, replacements in RECIPES:
        if name in cases:
            raise ValueError(f"duplicate recipe: {name}")
        case = deepcopy(cases[parent]) if parent else None
        for path, value in replacements:
            if not path:
                case = deepcopy(value)
            else:
                target = case
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = deepcopy(value)
        if case["name"] != name:
            raise ValueError(f"recipe name mismatch: {name}")
        cases[name] = case
    # Expand every recipe before deriving anything: inheritance uses inputs only.
    for case in cases.values():
        expected = case["expected"]
        if "closure_digest" in expected:
            expected["closure_digest"], expected["request_digest"] = digests(case)
    for case in cases.values():
        approval = case["request"]["approval"]
        if approval and isinstance(approval.get("request_digest"), dict):
            reference = approval["request_digest"]
            if set(reference) != {"request_of"}:
                raise ValueError("invalid approval reference")
            approval["request_digest"] = cases[reference["request_of"]]["expected"]["request_digest"]
    return {"profile": "extension-admission-v1alpha1", "cases": list(cases.values())}


def validator(name):
    schema = json.loads((HERE / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate(corpus):
    vectors = validator("admission-vectors.schema.json")
    vectors.validate(corpus)
    manifest = validator("manifest.schema.json")
    grant_record = validator("capability-grant.schema.json")
    grant = Draft202012Validator({"$ref": "#/$defs/grant", "$defs": grant_record.schema["$defs"]})
    reasons = set()
    for case in corpus["cases"]:
        valid = manifest.is_valid(case["evidence"]["document"])
        if valid != (case["name"] != "input-evidence-invalid-document"):
            raise ValueError(f"embedded manifest validity: {case['name']}")
        for proposed in case["request"]["grants"]:
            grant.validate(proposed)
        install = case["snapshot"]["install"]
        for record in install["grants"] if install else []:
            grant_record.validate(record)
        expected = case["expected"]
        reasons.update(reason["code"] for reason in expected["reasons"])
        if expected["outcome"] in ("reject", "identical_retry"):
            if {"operation", "closure_digest", "request_digest", "intent"} & expected.keys():
                raise ValueError(f"nonzero nonmutating result: {case['name']}")
    expected_schema = vectors.schema["properties"]["cases"]["items"]["properties"]["expected"]
    codes = set(expected_schema["properties"]["reasons"]["items"]["properties"]["code"]["enum"])
    if reasons != codes:
        raise ValueError(f"reason coverage differs: {reasons ^ codes}")
    approval_kinds = {
        case["expected"]["intent"]["approval_kind"]
        for case in corpus["cases"] if case["expected"]["outcome"] == "admit"
    }
    if approval_kinds != {"operator", "single-administrator", "release-fixed"}:
        raise ValueError("missing admitted approval kind")
    check_floor_boundary(corpus)
    schema_cases = 0
    for stem in ("extension-resource", "capability-grant", "admission-vectors"):
        check = validator(stem + ".schema.json")
        suite = json.loads((HERE / stem / "schema-cases.json").read_text(encoding="utf-8"))
        for case in suite["cases"]:
            if check.is_valid(case["instance"]) != case["valid"]:
                raise ValueError(f"schema validity: {stem}/{case['id']}")
            schema_cases += 1
    return len(codes), schema_cases


def check_floor_boundary(corpus):
    """Keep S-04's below-floor and equality witnesses distinct."""
    cases = {case["name"]: case for case in corpus["cases"]}
    for name, floor, reason in (
        ("global-floor-covers-new-id", "0.3.0", "approval.release_rollback"),
        ("global-floor-equality-new-id-needs-operator", "0.2.0", "approval.release_operation"),
    ):
        case = cases[name]
        snapshot, request, expected = (case[key] for key in ("snapshot", "request", "expected"))
        if not (
            case["evidence"]["document"]["metadata"]["version"] == "0.2.0"
            and snapshot["automatic_release_floor"] == floor
            and snapshot["release_version"] == "0.2.0"
            and not snapshot["first_start"]
            and snapshot["install"] is None and snapshot["ownership"] is None
            and not snapshot["tombstones"]
            and request["source"] == "server-image"
            and request["approval"] == {"kind": "release-fixed", "release_version": "0.2.0"}
            and expected["outcome"] == "approval_required" and expected["operation"] == "install"
            and expected["reasons"] == [{"code": reason, "subject": ""}]
            and "intent" not in expected
        ):
            raise ValueError(f"S-04 floor boundary: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check the generated bytes without writing")
    args = parser.parse_args()
    corpus = build()
    codes, schema_cases = validate(corpus)
    data = (json.dumps(corpus, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    output = HERE / "admission-vectors.json"
    if args.check:
        if output.read_bytes() != data:
            raise SystemExit("admission-vectors.json differs from generated bytes")
    else:
        output.write_bytes(data)
    pairs = sum("closure_digest" in case["expected"] for case in corpus["cases"])
    print(f"Validated {len(corpus['cases'])} vectors, {pairs} digest pairs, {codes} reason codes, {schema_cases} schema cases")
    print(dict(Counter(case["expected"]["outcome"] for case in corpus["cases"])))


if __name__ == "__main__":
    main()
