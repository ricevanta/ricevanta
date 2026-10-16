"""Footprint checks, baseline protocol and verdicts (docs/specs/footprint-harness.md sections 4 and 6).

check.py --evidence PATH --budgets PATH --baseline PATH [--out PATH]

Every limit and tolerance comes from the budgets file or, for shutdown_ms,
from the committed run profile named in the evidence; nothing is read from
the agent, the environment or the baseline. The evidence schema is applied by
a small standard-library interpreter of the JSON Schema keywords it uses, so
the schema file stays the single definition. Exit 0 on pass, 1 on fail, 2 on
usage or schema error.
"""

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA_PATH = ROOT / "schemas" / "agent" / "footprint" / "v1" / "evidence.schema.json"
PROFILES_DIR = HERE / "profiles"
CANDIDATE_NAME = "baseline-candidate.json"

MAX_JSON_BYTES = 1 << 24
# Kernel ABI constant, not a budget: USER_HZ in include/uapi/asm-generic/param.h (spec section 2).
USER_HZ = 100
# Spec section 2 fixes the failed-sample rule at 1 %; the v1 budgets definition has no field for it.
FAILED_SAMPLE_PERCENT = 1
IDENTITY_FIELDS = ("version", "commit", "channel", "sourceEpoch")
BASELINE_CHANNELS = {"master": "initial", "prerelease": "release"}
ENVIRONMENT_KEYS = ("runner_os", "runner_arch", "runner_label", "os_version")
CORE_NAMES = ("ricevanta-agent", "ricevanta-agent.exe")


class InputError(Exception):
    """Usage or schema error: exit 2."""


# ---------------------------------------------------------------- strict JSON


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise InputError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_constants(name):
    raise InputError(f"non-JSON number {name}")


def loads_strict(raw, limit=MAX_JSON_BYTES):
    """RFC 8259 JSON as UTF-8 without BOM, unique keys, no NaN or Infinity, no trailing value."""
    if len(raw) > limit:
        raise InputError(f"document larger than {limit} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InputError("byte-order mark")
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except InputError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InputError(f"invalid JSON: {exc}") from exc


def load_json_file(path, limit=MAX_JSON_BYTES):
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except OSError as exc:
        raise InputError(f"{path}: {exc.strerror or exc}") from exc
    try:
        return loads_strict(raw, limit)
    except InputError as exc:
        raise InputError(f"{path}: {exc}") from exc


def dumps_canonical(doc):
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


# ------------------------------------------------------- JSON Schema subset

_ANNOTATIONS = {"$schema", "$id", "$defs", "title", "description", "$comment", "examples", "default"}
_KEYWORDS = {
    "type", "enum", "const", "required", "properties", "additionalProperties", "items", "minItems",
    "maxItems", "uniqueItems", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength",
    "maxLength", "pattern", "oneOf", "anyOf", "allOf", "not", "if", "then", "else", "$ref",
}


def _is_type(value, name):
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    raise InputError(f"unsupported schema type {name}")


def json_equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


class Validator:
    """Draft 2020-12 for the keywords the footprint schema uses; any other keyword is refused."""

    def __init__(self, schema):
        self.schema = schema
        self._patterns = {}

    def _resolve(self, ref):
        if not ref.startswith("#"):
            raise InputError(f"unsupported $ref {ref}")
        node = self.schema
        for part in ref[1:].split("/")[1:] if ref != "#" else []:
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise InputError(f"unresolvable $ref {ref}")
            node = node[part]
        return node

    def errors(self, instance, ref="#"):
        errs = []
        self._check(self._resolve(ref), instance, "", errs)
        return errs

    def _check(self, schema, value, where, errs):
        if schema is True:
            return
        if schema is False:
            errs.append(f"{where or '/'}: not allowed")
            return
        unknown = set(schema) - _KEYWORDS - _ANNOTATIONS
        if unknown:
            raise InputError(f"unsupported schema keywords {sorted(unknown)}")
        at = where or "/"
        if "$ref" in schema:
            self._check(self._resolve(schema["$ref"]), value, where, errs)
        if "type" in schema:
            names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_is_type(value, n) for n in names):
                errs.append(f"{at}: expected {schema['type']}")
                return
        if "enum" in schema and not any(json_equal(value, v) for v in schema["enum"]):
            errs.append(f"{at}: not one of {schema['enum']}")
        if "const" in schema and not json_equal(value, schema["const"]):
            errs.append(f"{at}: not {schema['const']!r}")
        if _is_type(value, "number"):
            if "minimum" in schema and value < schema["minimum"]:
                errs.append(f"{at}: below {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                errs.append(f"{at}: above {schema['maximum']}")
            if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
                errs.append(f"{at}: not above {schema['exclusiveMinimum']}")
            if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
                errs.append(f"{at}: not below {schema['exclusiveMaximum']}")
        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                errs.append(f"{at}: shorter than {schema['minLength']}")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                errs.append(f"{at}: longer than {schema['maxLength']}")
            if "pattern" in schema:
                pattern = self._patterns.get(schema["pattern"])
                if pattern is None:
                    pattern = self._patterns[schema["pattern"]] = re.compile(schema["pattern"])
                if not pattern.search(value):
                    errs.append(f"{at}: does not match {schema['pattern']}")
        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                errs.append(f"{at}: fewer than {schema['minItems']} items")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                errs.append(f"{at}: more than {schema['maxItems']} items")
            if schema.get("uniqueItems"):
                for i, item in enumerate(value):
                    if any(json_equal(item, other) for other in value[:i]):
                        errs.append(f"{at}: duplicate items")
                        break
            if "items" in schema:
                for i, item in enumerate(value):
                    self._check(schema["items"], item, f"{where}/{i}", errs)
        if isinstance(value, dict):
            for key in schema.get("required", []):
                if key not in value:
                    errs.append(f"{at}: missing {key}")
            props = schema.get("properties", {})
            for key, item in value.items():
                if key in props:
                    self._check(props[key], item, f"{where}/{key}", errs)
                elif "additionalProperties" in schema:
                    self._check(schema["additionalProperties"], item, f"{where}/{key}", errs)
        for sub in schema.get("allOf", []):
            self._check(sub, value, where, errs)
        if "anyOf" in schema and not any(self._passes(s, value) for s in schema["anyOf"]):
            errs.append(f"{at}: matches no anyOf branch")
        if "oneOf" in schema:
            count = sum(1 for s in schema["oneOf"] if self._passes(s, value))
            if count != 1:
                errs.append(f"{at}: matches {count} oneOf branches")
        if "not" in schema and self._passes(schema["not"], value):
            errs.append(f"{at}: matches a forbidden shape")
        if "if" in schema:
            branch = "then" if self._passes(schema["if"], value) else "else"
            if branch in schema:
                self._check(schema[branch], value, where, errs)

    def _passes(self, schema, value):
        errs = []
        self._check(schema, value, "", errs)
        return not errs


def load_evidence_validator():
    return Validator(load_json_file(SCHEMA_PATH))


def load_budgets(path, validator=None):
    validator = validator or load_evidence_validator()
    budgets = load_json_file(path)
    errs = validator.errors(budgets, "#/$defs/budgets")
    if errs:
        raise InputError(f"{path}: budgets do not match the schema: {'; '.join(errs[:5])}")
    return budgets


def profile_shutdown_timeout(raw, name):
    doc = loads_strict(raw)
    timeout = doc.get("shutdown", {}).get("timeout_ms") if isinstance(doc, dict) else None
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        raise InputError(f"profile {name} must state shutdown.timeout_ms")
    return timeout


def load_shutdown_limits(phases, profiles_dir=PROFILES_DIR):
    """shutdown.timeout_ms per profile, from the committed profile whose SHA-256 the evidence names."""
    limits = {}
    for p in phases:
        name, sha = p["profile"]["name"], p["profile"]["sha256"]
        path = Path(profiles_dir) / f"{name}.json"
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise InputError(f"profile {name}: {exc.strerror or exc}") from exc
        if hashlib.sha256(raw).hexdigest() != sha:
            raise InputError(f"profile {name}: evidence SHA-256 {sha} is not the committed profile")
        limits[name] = profile_shutdown_timeout(raw, name)
    return limits


# ------------------------------------------------------------------ verdicts


def _row(check, phase, observed, limit, baseline, outcome):
    return {"check": check, "phase": phase, "observed": observed, "limit": limit, "baseline": baseline, "outcome": outcome}


def _num(value):
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


class Baseline:
    """What check.py found at --baseline: skipped (measure.py), missing, invalid or valid."""

    def __init__(self, status, doc=None, problem=None):
        self.status, self.doc, self.problem = status, doc, problem


SKIP = Baseline("skip")


def read_baseline(path, validator):
    path = Path(path)
    if not path.exists():
        return Baseline("missing")
    try:
        doc = load_json_file(path)
    except InputError:
        return Baseline("invalid", problem="unparseable")
    if validator.errors(doc):
        return Baseline("invalid", problem="schema")
    if doc["outcome"] != "pass":
        return Baseline("invalid", problem="outcome_fail")
    if doc["smoke"] is not False:
        return Baseline("invalid", problem="smoke")
    if doc["identity"] is None:
        return Baseline("invalid", problem="identity_null")
    if doc["identity"]["channel"] not in BASELINE_CHANNELS:
        return Baseline("invalid", problem=f"channel_{doc['identity']['channel']}")
    try:
        check_protocol(doc, require_full_duration=True)
    except InputError as exc:
        return Baseline("invalid", problem=f"protocol: {exc}")
    return Baseline("valid", doc=doc)


def _check_processes(evidence):
    procs = evidence["processes"]
    name = evidence["binary"]["name"]
    if len(procs) != 1 or procs[0]["role"] != "core" or procs[0]["name"] != name or name not in CORE_NAMES:
        raise InputError("the v1 evidence carries metrics for the core process only; processes must list exactly it")


# Protocol rules from spec section 3.1, shared by measurement and checking.
COUNTERS = ('samples', 'sample_failures', 'log_errors', 'health_write_failures', 'log_rotations')
PHASE_PROFILES = {'idle': ('idle', 120000), 'load': ('health-burst', 60000)}
WARMUP_MS = 10000
SAMPLE_INTERVAL_MS = 1000


def check_protocol(evidence, *, require_full_duration=False):
    """Admit complete full runs; smoke may use a unique subset and reduced windows."""
    phases = evidence['phases']
    names = [p['name'] for p in phases]
    if len(names) != len(set(names)):
        raise InputError('duplicate phase')
    if evidence['smoke']:
        return
    if set(names) != set(PHASE_PROFILES):
        raise InputError('full evidence requires exactly one idle phase and one load phase')
    for p in phases:
        profile, duration = PHASE_PROFILES[p['name']]
        if p['profile']['name'] != profile:
            raise InputError(f"phase {p['name']}: wrong profile")
        if p['sample_interval_ms'] != SAMPLE_INTERVAL_MS:
            raise InputError(f"phase {p['name']}: external sample interval must be {SAMPLE_INTERVAL_MS} ms")
        if p['warmup_ms'] != WARMUP_MS:
            raise InputError(f"phase {p['name']}: full warm-up must be {WARMUP_MS} ms")
        if p['samples'] != p['duration_ms'] // SAMPLE_INTERVAL_MS:
            raise InputError(f"phase {p['name']}: external sample count does not cover the measured window")
        if require_full_duration and p['duration_ms'] < duration:
            raise InputError(f"phase {p['name']}: shortened full run")


def phase_profile(p):
    name, duration = PHASE_PROFILES[p['name']]
    if p['profile']['name'] != name:
        raise InputError(f"phase {p['name']}: wrong profile")
    return load_json_file(PROFILES_DIR / (name + '.json')), duration


def snapshot_valid(s, pid, interval):
    return (s is not None and s['pid'] == pid and s['state'] == 'ready'
            and s['interval_ms'] == interval
            and s['sampled_unix_ms'] <= s['written_unix_ms'] <= s['observed_unix_ms']
            and s['sampled_uptime_ms'] <= s['uptime_ms'])


def snapshot_ages(s, first):
    elapsed = s['observed_elapsed_ms'] - first['observed_elapsed_ms']
    return tuple(max(0, s['observed_unix_ms'] - s[wall],
                     elapsed - (s[uptime] - first[uptime]))
                 for wall, uptime in (('written_unix_ms', 'uptime_ms'),
                                      ('sampled_unix_ms', 'sampled_uptime_ms')))


def snapshots_consistent(a, b):
    elapsed = b['observed_elapsed_ms'] - a['observed_elapsed_ms']
    wall = b['observed_unix_ms'] - a['observed_unix_ms']
    if elapsed < 0 or wall < 0 or abs(wall - elapsed) > 2000:
        return False
    for key in ('written_unix_ms', 'uptime_ms', 'sampled_unix_ms', 'sampled_uptime_ms'):
        if b[key] < a[key]:
            return False
    if b['samples'] > a['samples']:
        if b['sampled_unix_ms'] <= a['sampled_unix_ms'] or b['sampled_uptime_ms'] <= a['sampled_uptime_ms']:
            return False
    return True


def cadence(p, interval):
    g = p['health_progress']
    a, b = g['start'], g['end']
    d = b['observed_elapsed_ms'] - a['observed_elapsed_ms'] if a and b else p['duration_ms']
    n = d // interval
    return max(1, n - n // 100), (d + interval - 1) // interval + 1


def freshness_valid(p, smoke, interval, full_duration):
    g = p['health_progress']
    a, b = g['start'], g['end']
    d = p['duration_ms']
    if not (snapshot_valid(a, g['pid'], interval) and snapshot_valid(b, g['pid'], interval)):
        return False
    if g['invalid_observations'] or not snapshots_consistent(a, b):
        return False
    if (p['finished_unix_ms'] < p['started_unix_ms']
            or abs(p['finished_unix_ms'] - p['started_unix_ms'] - d) > 2000
            or (not smoke and d < full_duration)):
        return False
    for s, left in ((a, True), (b, False)):
        wall = s['observed_unix_ms'] - p['started_unix_ms']
        mono = s['observed_elapsed_ms']
        if not (0 <= wall <= p['finished_unix_ms'] - p['started_unix_ms'] and 0 <= mono <= d):
            return False
        if (left and (wall > 1000 or mono > 1000)) or (not left and
                (p['finished_unix_ms'] - s['observed_unix_ms'] > 1000 or d - mono > 1000)):
            return False
        if abs(wall - mono) > 2000:
            return False
        ages = snapshot_ages(s, a)
        if g['max_write_age_ms'] < ages[0] or g['max_sample_age_ms'] < ages[1]:
            return False
    return (g['max_write_age_ms'] <= interval + 2000
            and g['max_sample_age_ms'] <= interval + 2000
            and g['max_observation_gap_ms'] <= 2000
            and g['observations'] >= d // 1000 + 2)


def final_in_phase(p):
    b = p['health_progress']['end']
    return (b is not None
            and p['started_unix_ms'] <= b['sampled_unix_ms'] <= p['finished_unix_ms']
            and 0 <= b['observed_elapsed_ms'] - (b['uptime_ms'] - b['sampled_uptime_ms']) <= p['duration_ms'])


def progress_outcome(p, smoke, interval):
    g = p['health_progress']
    a, b = g['start'], g['end']
    if not (snapshot_valid(a, g['pid'], interval) and snapshot_valid(b, g['pid'], interval)):
        return 'fail'
    if (g['counter_regressions'] or not snapshots_consistent(a, b)
            or any(b[k] < a[k] for k in COUNTERS)
            or any(b[k] != a[k] for k in ('sample_failures', 'health_write_failures'))):
        return 'fail'
    if smoke and p['duration_ms'] < interval:
        return 'recorded'
    low, high = cadence(p, interval)
    return 'pass' if final_in_phase(p) and low <= b['samples'] - a['samples'] <= high else 'fail'


def workload_rows(evidence, p):
    profile, duration = phase_profile(p)
    interval = profile['health']['interval_ms']
    smoke = evidence['smoke']
    fresh = freshness_valid(p, smoke, interval, duration)
    rows = [_row('health_freshness', p['name'], 'valid' if fresh else 'invalid', interval + 2000,
                 None, 'pass' if fresh else 'fail'),
            _row('sampler_progress', p['name'],
                 p['health_progress']['end']['samples'] - p['health_progress']['start']['samples']
                 if p['health_progress']['end'] and p['health_progress']['start'] else None,
                 cadence(p, interval)[0], None, progress_outcome(p, smoke, interval))]
    if p['name'] == 'load':
        g, log = p['health_progress'], p['log_activity']
        a, b = g['start'], g['end']
        rotations = b['log_rotations'] - a['log_rotations'] if a and b else -1
        delta = b['samples'] - a['samples'] if a and b else -1
        valid = (a and b and log['sample_events'] >= cadence(p, interval)[0]
                 and log['sample_events'] <= delta and log['rotations_observed'] >= 1
                 and rotations == log['rotations_observed'] and not log['invalid_lines']
                 and b['log_errors'] == a['log_errors'])
        outcome = 'recorded' if smoke and p['duration_ms'] < duration else ('pass' if valid else 'fail')
        rows.append(_row('load_log_activity', 'load', log['sample_events'], cadence(p, interval)[0], None, outcome))
    return rows


def _self_sample_row(evidence, p, budgets):
    own, pair = p['self_sample'], p['self_sample_external']
    profile, duration = phase_profile(p)
    interval = profile['health']['interval_ms']
    b = p['health_progress']['end']
    valid = (own is not None and b is not None
             and own['footprint_metric'] == p['metrics']['footprint_bytes']['metric']
             and freshness_valid(p, evidence['smoke'], interval, duration)
             and all(own[k] == b[k] for k in ('written_unix_ms', 'sampled_unix_ms', 'sampled_uptime_ms')))
    if valid and evidence['smoke'] and p['duration_ms'] < interval and not final_in_phase(p):
        return _row('self_sample_agreement', p['name'], 'short_smoke', None, None, 'recorded')
    valid = (valid and final_in_phase(p) and pair is not None and pair['footprint_bytes'] > 0
             and own['footprint_metric'] == pair['footprint_metric'] == p['metrics']['footprint_bytes']['metric']
             and p['started_unix_ms'] <= pair['unix_ms'] <= p['finished_unix_ms']
             and abs(pair['unix_ms'] - own['sampled_unix_ms']) <= 2000)
    if not valid:
        return _row('self_sample_agreement', p['name'], 'invalid_pair', None, None, 'fail')
    diff = own['footprint_bytes'] - pair['footprint_bytes']
    tolerance = budgets['self_sample_tolerance']
    limit = max(tolerance['ratio'] * pair['footprint_bytes'], tolerance['bytes'])
    return _row('self_sample_agreement', p['name'], diff, _num(limit), None,
                'fail' if abs(diff) > limit else 'pass')

def _absolute(evidence, budgets, shutdown_limits):
    rows = []
    env = evidence["environment"]
    if evidence["target"] == "linux-x64":
        tick = env["clk_tck"]
        rows.append(_row("clk_tck_agreement", None, tick, USER_HZ, None, "pass" if tick == USER_HZ else "fail"))
    else:
        rows.append(_row("clk_tck_agreement", None, None, None, None, "recorded"))

    if evidence["smoke"]:
        rows.append(_row("identity_mismatch", None, None, None, None, "recorded"))
    else:
        claimed, reported = evidence["identity"], evidence["binary"]["reported_identity"]
        differ = [f for f in IDENTITY_FIELDS if not json_equal(claimed[f], reported[f])]
        observed = "match" if not differ else "mismatch:" + ",".join(differ)
        rows.append(_row("identity_mismatch", None, observed, None, None, "fail" if differ else "pass"))

    _check_processes(evidence)
    phases = evidence["phases"]
    for p in phases:
        p95 = p["metrics"]["footprint_bytes"]["p95"]
        rows.append(_row("footprint_nonzero", p["name"], _num(p95), 0, None, "fail" if p95 <= 0 else "pass"))
    for p in phases:
        p95 = p["metrics"]["footprint_bytes"]["p95"]
        limit = budgets["footprint_p95_bytes"][p["name"]]
        rows.append(_row("footprint_p95", p["name"], _num(p95), limit, None, "fail" if p95 > limit else "pass"))
    for p in phases:
        if p["name"] == "idle":
            total = p["metrics"]["footprint_bytes"]["p95"]
            limit = budgets["aggregate_footprint_p95_bytes"]
            rows.append(_row("aggregate_footprint_p95", "idle", _num(total), limit, None, "fail" if total > limit else "pass"))
    cpu_budget = budgets["cpu_core_pct_mean"]
    for p in phases:
        mean = p["metrics"]["cpu_core_pct"]["mean"]
        if p["name"] == "idle":
            gate = cpu_budget["idle_hosted_gate"]
            rows.append(_row("cpu_mean", "idle", mean, gate, None, "fail" if mean > gate else "recorded"))
            rows.append(_row("cpu_mean", "idle", mean, cpu_budget["idle_target"], None, "recorded"))
        else:
            rows.append(_row("cpu_mean", p["name"], mean, None, None, "recorded"))
    for p in phases:
        top = p["metrics"]["threads"]["max"]
        limit = budgets["threads_max"]
        rows.append(_row("threads_max", p["name"], top, limit, None, "fail" if top > limit else "pass"))
    expected_kind = "handle" if evidence["target"] == "windows-x64" else "fd"
    for p in phases:
        desc = p["metrics"]["descriptors"]
        if desc["kind"] != expected_kind:
            raise InputError(f"phase {p['name']}: descriptor kind {desc['kind']} on {evidence['target']}")
        limit = budgets["descriptors_max"][desc["kind"]]
        rows.append(_row("descriptors_max", p["name"], desc["max"], limit, None, "fail" if desc["max"] > limit else "pass"))
    for p in phases:
        limit = shutdown_limits[p["profile"]["name"]]
        rows.append(_row("shutdown_ms", p["name"], p["shutdown_ms"], limit, None, "fail" if p["shutdown_ms"] > limit else "pass"))
    for p in phases:
        rows.append(_row("exit_code", p["name"], p["exit_code"], 0, None, "fail" if p["exit_code"] != 0 else "pass"))
    for p in phases:
        if p["failed_samples"] > p["samples"]:
            raise InputError(f"phase {p['name']}: more failed samples than samples")
        limit = p["samples"] * FAILED_SAMPLE_PERCENT // 100
        rows.append(_row("failed_samples", p["name"], p["failed_samples"], limit, None,
                         "fail" if p["failed_samples"] > limit else "pass"))
    for p in phases:
        rows.extend(workload_rows(evidence, p))
        rows.append(_self_sample_row(evidence, p, budgets))
    return rows


def _regression(evidence, base_doc, budgets):
    rows = []
    tol = budgets["regression"]
    base_phases = {p["name"]: p for p in base_doc["phases"]}

    def judge(observed, base_value, exceeded):
        if exceeded:
            return "fail"
        return "recorded" if observed < base_value else "pass"

    pairs = [(p, base_phases.get(p["name"])) for p in evidence["phases"]]
    if any(b is None for _, b in pairs):
        raise InputError('baseline is missing a measured phase')
    for p, b in pairs:
        o = p["metrics"]["footprint_bytes"]["p95"]
        base = b["metrics"]["footprint_bytes"]["p95"]
        delta = o - base
        exceeded = delta > tol["footprint_ratio"] * base and delta > tol["footprint_bytes"]
        limit = _num(base + max(tol["footprint_ratio"] * base, tol["footprint_bytes"]))
        rows.append(_row("regression_footprint_p95", p["name"], _num(o), limit, _num(base), judge(o, base, exceeded)))
    for p, b in pairs:
        o = p["metrics"]["threads"]["max"]
        base = b["metrics"]["threads"]["max"]
        limit = base + tol["threads"]
        rows.append(_row("regression_threads_max", p["name"], o, limit, base, judge(o, base, o > limit)))
    for p, b in pairs:
        desc = p["metrics"]["descriptors"]
        o = desc["max"]
        base = b["metrics"]["descriptors"]["max"]
        limit = base + tol["descriptors_" + desc["kind"]]
        rows.append(_row("regression_descriptors_max", p["name"], o, limit, base, judge(o, base, o > limit)))
    for p, b in pairs:
        base = b["metrics"]["cpu_core_pct"]["mean"] if b else None
        rows.append(_row("regression_cpu_mean", p["name"], p["metrics"]["cpu_core_pct"]["mean"], None, base, "recorded"))
    for p, b in pairs:
        base = b["shutdown_ms"] if b else None
        rows.append(_row("regression_shutdown_ms", p["name"], p["shutdown_ms"], None, base, "recorded"))
    return rows


def _baseline_rows(evidence, budgets, baseline):
    """Rows and the evidence `baseline` object for spec section 6."""
    none = {"kind": "none", "identity": None, "environment_match": None}
    smoke = evidence["smoke"]
    channel = None if evidence["identity"] is None else evidence["identity"]["channel"]
    if baseline.status == "missing":
        outcome = "fail" if (not smoke and channel == "prerelease") else "recorded"
        return [_row("baseline_present", None, "none", None, None, outcome)], none
    rows = [_row("baseline_present", None, "present", None, None, "pass")]
    if baseline.status == "invalid":
        rows.append(_row("baseline_invalid", None, baseline.problem, None, None, "fail"))
        return rows, none
    doc = baseline.doc
    kind = BASELINE_CHANNELS[doc["identity"]["channel"]]
    rows[0]["observed"] = kind
    rows.append(_row("baseline_invalid", None, "valid", None, None, "pass"))
    differ = [] if doc["target"] == evidence["target"] else ["target"]
    differ += [k for k in ENVIRONMENT_KEYS if doc["environment"][k] != evidence["environment"][k]]
    obj = {"kind": kind, "identity": doc["identity"], "environment_match": not differ}
    if differ:
        rows.append(_row("baseline_environment", None, "mismatch:" + ",".join(differ), None, None, "fail"))
        return rows, obj
    rows.append(_row("baseline_environment", None, "match", None, None, "pass"))
    rows += _regression(evidence, doc, budgets)
    return rows, obj


def evaluate(evidence, budgets, shutdown_limits, baseline=SKIP):
    """Return (results, baseline object, outcome) for a schema-valid evidence document."""
    check_protocol(evidence)
    rows = _absolute(evidence, budgets, shutdown_limits)
    base_obj = {"kind": "none", "identity": None, "environment_match": None}
    if baseline.status != "skip":
        extra, base_obj = _baseline_rows(evidence, budgets, baseline)
        if evidence["smoke"]:
            # A smoke run is never a gate result: baseline verdicts are reported, not enforced.
            for r in extra:
                r["outcome"] = "recorded"
        rows += extra
    outcome = "fail" if any(r["outcome"] == "fail" for r in rows) else "pass"
    return rows, base_obj, outcome


def complete(evidence, budgets, shutdown_limits, baseline=SKIP):
    doc = dict(evidence)
    doc["budgets"] = budgets
    doc["results"], doc["baseline"], doc["outcome"] = evaluate(evidence, budgets, shutdown_limits, baseline)
    return doc


def qualifies_as_candidate(doc):
    eligible = (
        doc["outcome"] == "pass"
        and doc["smoke"] is False
        and doc["identity"] is not None
        and doc["identity"]["channel"] in BASELINE_CHANNELS
    )
    if not eligible:
        return False
    try:
        check_protocol(doc, require_full_duration=True)
    except InputError:
        return False
    return True


def _fmt(value):
    if value is None:
        return "null"
    if isinstance(value, float) and not math.isfinite(value):
        return "invalid"
    return str(value)


def result_lines(doc):
    ident = doc["baseline"]["identity"]
    base_id = ident["version"] if ident else "none"
    for r in doc["results"]:
        yield (f"check={r['check']} phase={r['phase'] or '-'} observed={_fmt(r['observed'])} limit={_fmt(r['limit'])} "
               f"baseline={_fmt(r['baseline'])} baseline_identity={base_id} outcome={r['outcome']}")
    yield f"outcome={doc['outcome']}"


# ----------------------------------------------------------------------- CLI


def _parser():
    parser = argparse.ArgumentParser(description="Judge footprint evidence against budgets and a baseline.")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--budgets", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--out")
    return parser


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        validator = load_evidence_validator()
        budgets = load_budgets(args.budgets, validator)
        evidence = load_json_file(args.evidence)
        errs = validator.errors(evidence)
        if errs:
            raise InputError(f"evidence does not match the schema: {'; '.join(errs[:5])}")
        limits = load_shutdown_limits(evidence["phases"])
        doc = complete(evidence, budgets, limits, read_baseline(args.baseline, validator))
        errs = validator.errors(doc)
        if errs:
            raise InputError(f"completed evidence does not match the schema: {'; '.join(errs[:5])}")
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for line in result_lines(doc):
        print(line)
    if args.out:
        out = Path(args.out)
        data = dumps_canonical(doc)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            candidate = out.parent / CANDIDATE_NAME
            if qualifies_as_candidate(doc):
                candidate.write_bytes(data)
            elif candidate.exists():
                candidate.unlink()
        except OSError as exc:
            print(f"error: cannot write {out}: {exc.strerror or exc}", file=sys.stderr)
            return 2
    return 0 if doc["outcome"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
