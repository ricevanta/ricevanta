#!/usr/bin/env python3
"""Translate approved spool fixture expectations to Rust; never infer results."""

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "schemas/agent/spool/v1/fixtures.json"
DESTINATION = ROOT / "agent/crates/spool/tests/support/fixture_data.rs"
MAX_BYTES = 2 * 1024 * 1024
CLASSES = ["Raw", "Context", "Lineage", "Findings", "Audit"]


def fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError(f"expected exactly these fields: {', '.join(names)}")


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"integer outside {low}..{high}")
    return str(value)


def u64(value):
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None:
        raise ValueError("u64 must be a canonical decimal string")
    return integer(int(value), 0, 2**64 - 1)


def optional_u64(value):
    return "None" if value is None else f"Some({u64(value)})"


def byte_slice(value, cap=MAX_BYTES):
    if (not isinstance(value, str) or len(value) > cap * 2
            or re.fullmatch(r"(?:[0-9a-f]{2})*", value) is None):
        raise ValueError("hex must be bounded, lowercase and even-length")
    return "&[" + ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(value)) + "]"


def header(value):
    fields(value, ["class_id", "stream_epoch", "segment_id", "first_sequence"])
    class_id = int(integer(value["class_id"], 1, 5))
    epoch = u64(value["stream_epoch"])
    if epoch == "0":
        raise ValueError("successful header epoch must be nonzero")
    return (f"Header {{ class: SpoolClass::{CLASSES[class_id - 1]}, stream_epoch: {epoch}, "
            f"segment_id: {u64(value['segment_id'])}, first_sequence: {u64(value['first_sequence'])} }}")


def error(value):
    if not isinstance(value, dict):
        raise ValueError("error must be an object")
    kind = value.get("kind")
    bounds = {
        "HeaderTooShort": ("actual", 0, 31),
        "Version": ("found", 0, 65535),
        "Class": ("found", 0, 255),
        "Reserved": ("found", 0, 255),
        "PayloadTooLarge": ("length", 1048577, 2**32 - 1),
    }
    if kind in ("Magic", "StreamEpoch"):
        fields(value, ["kind"])
        return f"Error::{kind}"
    if kind in bounds:
        name, low, high = bounds[kind]
        fields(value, ["kind", name])
        return f"Error::{kind} {{ {name}: {integer(value[name], low, high)} }}"
    if kind == "Sequence":
        fields(value, ["kind", "offset", "expected", "found"])
        return (f"Error::Sequence {{ offset: {integer(value['offset'], 0, MAX_BYTES)}, "
                f"expected: {optional_u64(value['expected'])}, found: {u64(value['found'])} }}")
    raise ValueError("unsupported error kind")


def expected(value):
    if isinstance(value, dict) and "error" in value:
        fields(value, ["error"])
        return f"Expected::Error({error(value['error'])})"
    fields(value, ["header", "records", "valid_len", "next_sequence", "tail"])
    if not isinstance(value["records"], list):
        raise ValueError("records must be an array")
    records = []
    for record in value["records"]:
        fields(record, ["sequence", "payload_hex"])
        records.append(f"Record {{ sequence: {u64(record['sequence'])}, payload: {byte_slice(record['payload_hex'], 1048576)} }}")
    tail = value["tail"]
    if tail is None:
        tail_expr = "None"
    else:
        fields(tail, ["offset", "kind"])
        if tail["kind"] not in ("Incomplete", "Checksum"):
            raise ValueError("unsupported tail kind")
        tail_expr = f"Some(TailIssue {{ offset: {integer(tail['offset'], 0, MAX_BYTES)}, kind: TailKind::{tail['kind']} }})"
    return (f"Expected::Success {{ header: {header(value['header'])}, records: &[{', '.join(records)}], "
            f"valid_len: {integer(value['valid_len'], 32, MAX_BYTES)}, "
            f"next_sequence: {optional_u64(value['next_sequence'])}, tail: {tail_expr} }}")


def render(container):
    fields(container, ["format", "fixtures"])
    if container["format"] != "ricevanta-spool-v1":
        raise ValueError("unsupported fixture format")
    if not isinstance(container["fixtures"], list) or not container["fixtures"]:
        raise ValueError("fixtures must be a nonempty array")
    lines = [
        "// Generated from schemas/agent/spool/v1/fixtures.json.",
        "// Regenerate: python agent/tools/generate-spool-fixtures.py",
        "use super::{Expected, Fixture};",
        "use ricevanta_spool::{Error, Header, Record, SpoolClass, TailIssue, TailKind};",
        "", "#[rustfmt::skip]", "pub static FIXTURES: &[Fixture] = &[",
    ]
    ids = set()
    for fixture in container["fixtures"]:
        fields(fixture, ["id", "segment_hex", "expected"])
        identifier = fixture["id"]
        if not isinstance(identifier, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]*", identifier) is None:
            raise ValueError("invalid fixture ID")
        if identifier in ids:
            raise ValueError("duplicate fixture ID")
        ids.add(identifier)
        lines.append(f'    Fixture {{ id: "{identifier}", input: {byte_slice(fixture["segment_hex"])}, expected: {expected(fixture["expected"])} }},')
    lines += ["];", ""]
    return "\n".join(lines).encode("utf-8")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        data = json.loads(SOURCE.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        output = render(data)
        if args.check:
            if not DESTINATION.exists() or DESTINATION.read_bytes() != output:
                print("spool fixture data differs; regenerate with the documented command", file=sys.stderr)
                return 1
        else:
            DESTINATION.write_bytes(output)
        print(f"spool fixtures: {len(data['fixtures'])} translated; {'checked' if args.check else 'written'}")
        return 0
    except (OSError, ValueError) as error_value:
        print(f"spool fixture generation failed: {error_value}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
