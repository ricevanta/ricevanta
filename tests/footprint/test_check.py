"""Task 3 tests for check.py with synthetic evidence (docs/specs/footprint-harness.md sections 4 and 6).

Standard library only. One test group per row of the section 4 table, the
baseline protocol of section 6, exit codes and the baseline candidate.
"""

import ast
import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
import tokenize
import unittest
from pathlib import Path

import check

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA_DIR = ROOT / "schemas/agent/footprint/v1"
EXAMPLE = json.loads((SCHEMA_DIR / "example.json").read_text(encoding="utf-8"))
CASES = json.loads((SCHEMA_DIR / "schema-cases.json").read_text(encoding="utf-8"))
BUDGETS = json.loads((HERE / "budgets.json").read_text(encoding="utf-8"))
MIB = 1024 * 1024
MISSING = object()


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


PROFILE_SHA = {name: sha256(HERE / "profiles" / f"{name}.json") for name in ("idle", "health-burst")}


def make_evidence(channel="master", smoke=False, target="linux-x64"):
    """A passing run before regression checks: example values, committed profile hashes."""
    ev = copy.deepcopy(EXAMPLE)
    for p in ev["phases"]:
        p["profile"]["sha256"] = PROFILE_SHA[p["profile"]["name"]]
    ev["results"] = [r for r in ev["results"] if r["check"] == "self_sample_agreement"]
    ev["baseline"] = {"kind": "none", "identity": None, "environment_match": None}
    ev["identity"]["channel"] = channel
    ev["binary"]["reported_identity"]["channel"] = channel
    if channel == "prerelease":
        for doc in (ev["identity"], ev["binary"]["reported_identity"]):
            doc["version"] = "0.1.0-alpha.1"
    if smoke:
        ev["smoke"] = True
        ev["identity"] = None
    if target == "windows-x64":
        windows = next(c["instance"] for c in CASES["cases"] if c["id"] == "windows-record")
        ev["target"] = target
        ev["environment"] = copy.deepcopy(windows["environment"])
        for p, wp in zip(ev["phases"], windows["phases"]):
            p["metrics"] = copy.deepcopy(wp["metrics"])
            p["self_sample"] = copy.deepcopy(wp["self_sample"])
            p["self_sample_external"] = copy.deepcopy(wp["self_sample_external"])
    return ev


def make_baseline(channel="master"):
    base = make_evidence(channel=channel)
    base["identity"]["commit"] = "f" * 40
    base["identity"]["version"] = "0.1.0-dev.0+g" + "f" * 40 if channel == "master" else "0.1.0-alpha.1"
    base["results"] = list(EXAMPLE["results"])
    base["outcome"] = "pass"
    return base


def phase(ev, name):
    return next(p for p in ev["phases"] if p["name"] == name)


def set_self(ev, name, self_bytes, external_bytes):
    phase(ev, name)["self_sample"]["footprint_bytes"] = self_bytes
    phase(ev, name)["self_sample_external"]["footprint_bytes"] = external_bytes
    for r in ev["results"]:
        if r["check"] == "self_sample_agreement" and r["phase"] == name:
            r["observed"] = self_bytes - external_bytes


class Run:
    def __init__(self, code, doc, stdout, out_dir):
        self.code, self.doc, self.stdout, self.out_dir = code, doc, stdout, out_dir

    def rows(self, name, phase_name=None):
        return [r for r in self.doc["results"] if r["check"] == name and r["phase"] == phase_name]

    def row(self, name, phase_name=None):
        rows = self.rows(name, phase_name)
        assert len(rows) == 1, (name, phase_name, rows)
        return rows[0]

    def outcome(self, name, phase_name=None):
        return self.row(name, phase_name)["outcome"]


class CheckTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rv-check-test-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def run_check(self, evidence, baseline=MISSING, budgets=None, out=True, raw_evidence=None, extra=()):
        ev_path = self.dir / "in" / "evidence.json"
        ev_path.parent.mkdir(parents=True, exist_ok=True)
        if raw_evidence is not None:
            ev_path.write_bytes(raw_evidence)
        else:
            ev_path.write_text(json.dumps(evidence), encoding="utf-8")
        budgets_path = self.dir / "in" / "budgets.json"
        budgets_path.write_text(json.dumps(BUDGETS if budgets is None else budgets), encoding="utf-8")
        base_path = self.dir / "in" / "baseline.json"
        if base_path.exists():
            base_path.unlink()
        if isinstance(baseline, bytes):
            base_path.write_bytes(baseline)
        elif baseline is not MISSING:
            base_path.write_text(json.dumps(baseline), encoding="utf-8")
        out_dir = self.dir / "out"
        result = out_dir / 'result.json'
        if result.exists():
            result.unlink()
        argv = ["--evidence", str(ev_path), "--budgets", str(budgets_path), "--baseline", str(base_path)]
        if out:
            argv += ["--out", str(out_dir / "result.json")]
        argv += list(extra)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            code = check.main(argv)
        doc = None
        if out and (out_dir / "result.json").exists():
            doc = json.loads((out_dir / "result.json").read_text(encoding="utf-8"))
        return Run(code, doc, buf.getvalue(), out_dir)


class ValidatorTests(unittest.TestCase):
    def test_validator_agrees_with_schema_cases(self):
        validator = check.load_evidence_validator()
        self.assertEqual(validator.errors(EXAMPLE), [])
        for case in CASES["cases"]:
            with self.subTest(case=case["id"]):
                errors = validator.errors(case["instance"])
                self.assertEqual(not errors, case["valid"], errors)

    def test_bool_is_not_integer(self):
        ev = copy.deepcopy(EXAMPLE)
        ev["phases"][0]["samples"] = True
        self.assertTrue(check.load_evidence_validator().errors(ev))
        ev = copy.deepcopy(EXAMPLE)
        ev["smoke"] = 0
        self.assertTrue(check.load_evidence_validator().errors(ev))

    def test_strict_json(self):
        for raw in (b'{"a": 1, "a": 2}', b'{"a": NaN}', b'\xef\xbb\xbf{}', b'{"a": 1} x', b'{"a": Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(check.InputError):
                    check.loads_strict(raw)


class BudgetFileTests(unittest.TestCase):
    def test_budgets_is_the_example_copy(self):
        self.assertEqual(BUDGETS, EXAMPLE["budgets"])
        self.assertEqual(check.load_evidence_validator().errors(BUDGETS, "#/$defs/budgets"), [])

    def test_check_holds_no_budget_constant(self):
        # Distinctive seed values of budgets.json, compared with their literal type.
        distinctive = {(int, 44_000_000), (int, 80_000_000), (int, 4_194_304), (int, 2_097_152),
                       (float, 0.2), (float, 0.1), (float, 5.0), (float, 1.0), (int, 12)}
        with open(HERE / "check.py", "rb") as f:
            numbers = {(type(v), v) for v in (ast.literal_eval(tok.string) for tok in tokenize.tokenize(f.readline)
                                              if tok.type == tokenize.NUMBER)}
        self.assertFalse(numbers & distinctive, numbers & distinctive)


class AbsoluteCheckTests(CheckTestCase):
    def test_example_passes_without_baseline(self):
        run = self.run_check(make_evidence())
        self.assertEqual(run.code, 0, run.stdout)
        self.assertEqual(run.doc["outcome"], "pass")
        self.assertEqual(check.load_evidence_validator().errors(run.doc), [])

    def test_clk_tck(self):
        ev = make_evidence()
        self.assertEqual(self.run_check(ev).outcome("clk_tck_agreement"), "pass")
        ev["environment"]["clk_tck"] = 250
        run = self.run_check(ev)
        self.assertEqual(run.outcome("clk_tck_agreement"), "fail")
        self.assertEqual(run.code, 1)
        win = self.run_check(make_evidence(target="windows-x64"))
        self.assertEqual(win.outcome("clk_tck_agreement"), "recorded")

    def test_identity_mismatch_each_field(self):
        self.assertEqual(self.run_check(make_evidence()).outcome("identity_mismatch"), "pass")
        for field, value in (("version", "0.1.0-dev.0+g" + "e" * 40), ("commit", "e" * 40),
                             ("channel", "pr"), ("sourceEpoch", 1)):
            with self.subTest(field=field):
                ev = make_evidence()
                ev["binary"]["reported_identity"][field] = value
                run = self.run_check(ev)
                self.assertEqual(run.outcome("identity_mismatch"), "fail")
                self.assertIn(field, run.row("identity_mismatch")["observed"])
                self.assertEqual(run.code, 1)

    def test_identity_recorded_on_smoke(self):
        ev = make_evidence(smoke=True)
        ev["binary"]["reported_identity"]["commit"] = "e" * 40
        run = self.run_check(ev)
        self.assertEqual(run.outcome("identity_mismatch"), "recorded")
        self.assertEqual(run.code, 0)

    def test_footprint_nonzero(self):
        ev = make_evidence()
        phase(ev, "load")["metrics"]["footprint_bytes"]["p95"] = 0
        run = self.run_check(ev)
        self.assertEqual(run.outcome("footprint_nonzero", "load"), "fail")
        self.assertEqual(run.outcome("footprint_nonzero", "idle"), "pass")

    def test_footprint_p95_boundary(self):
        for name in ("idle", "load"):
            for value, expected in ((44_000_000, "pass"), (44_000_001, "fail")):
                with self.subTest(phase=name, value=value):
                    ev = make_evidence()
                    phase(ev, name)["metrics"]["footprint_bytes"]["p95"] = value
                    set_self(ev, name, value, value)
                    run = self.run_check(ev)
                    self.assertEqual(run.outcome("footprint_p95", name), expected)
                    self.assertEqual(run.row("footprint_p95", name)["limit"], 44_000_000)

    def test_aggregate_boundary(self):
        budgets = copy.deepcopy(BUDGETS)
        budgets["footprint_p95_bytes"]["idle"] = 100_000_000
        for value, expected in ((80_000_000, "pass"), (80_000_001, "fail")):
            ev = make_evidence()
            phase(ev, "idle")["metrics"]["footprint_bytes"]["p95"] = value
            set_self(ev, "idle", value, value)
            run = self.run_check(ev, budgets=budgets)
            self.assertEqual(run.outcome("footprint_p95", "idle"), "pass")
            self.assertEqual(run.outcome("aggregate_footprint_p95", "idle"), expected)

    def test_aggregate_rejects_unmeasured_process(self):
        ev = make_evidence()
        ev["processes"].append({"name": "ricevanta-updater", "role": "helper"})
        self.assertEqual(self.run_check(ev).code, 2)

    def test_cpu_idle_gate_and_target(self):
        for value, expected in ((5.0, "recorded"), (5.01, "fail")):
            ev = make_evidence()
            phase(ev, "idle")["metrics"]["cpu_core_pct"]["mean"] = value
            run = self.run_check(ev)
            rows = run.rows("cpu_mean", "idle")
            gate = [r for r in rows if r["limit"] == BUDGETS["cpu_core_pct_mean"]["idle_hosted_gate"]]
            target = [r for r in rows if r["limit"] == BUDGETS["cpu_core_pct_mean"]["idle_target"]]
            self.assertEqual([r["outcome"] for r in gate], [expected])
            self.assertEqual([r["outcome"] for r in target], ["recorded"])
            self.assertEqual(target[0]["observed"], value)

    def test_cpu_load_recorded(self):
        ev = make_evidence()
        phase(ev, "load")["metrics"]["cpu_core_pct"]["mean"] = 99.0
        run = self.run_check(ev)
        self.assertEqual(run.outcome("cpu_mean", "load"), "recorded")
        self.assertEqual(run.code, 0)

    def test_threads_max_boundary(self):
        for value, expected in ((12, "pass"), (13, "fail")):
            ev = make_evidence()
            phase(ev, "load")["metrics"]["threads"]["max"] = value
            self.assertEqual(self.run_check(ev).outcome("threads_max", "load"), expected)

    def test_descriptors_fd_boundary(self):
        for value, expected in ((64, "pass"), (65, "fail")):
            ev = make_evidence()
            phase(ev, "idle")["metrics"]["descriptors"]["max"] = value
            self.assertEqual(self.run_check(ev).outcome("descriptors_max", "idle"), expected)

    def test_descriptors_handle_boundary(self):
        for value, expected in ((256, "pass"), (257, "fail")):
            ev = make_evidence(target="windows-x64")
            phase(ev, "idle")["metrics"]["descriptors"]["max"] = value
            run = self.run_check(ev)
            self.assertEqual(run.outcome("descriptors_max", "idle"), expected)
            self.assertEqual(run.row("descriptors_max", "idle")["limit"], 256)

    def test_shutdown_boundary_from_profile(self):
        timeout = json.loads((HERE / "profiles/idle.json").read_text(encoding="utf-8"))["shutdown"]["timeout_ms"]
        for value, expected in ((timeout, "pass"), (timeout + 1, "fail")):
            ev = make_evidence()
            phase(ev, "idle")["shutdown_ms"] = value
            run = self.run_check(ev)
            self.assertEqual(run.outcome("shutdown_ms", "idle"), expected)
            self.assertEqual(run.row("shutdown_ms", "idle")["limit"], timeout)

    def test_profile_hash_must_match_committed_profile(self):
        ev = make_evidence()
        phase(ev, "idle")["profile"]["sha256"] = "0" * 64
        self.assertEqual(self.run_check(ev).code, 2)

    def test_exit_code(self):
        ev = make_evidence()
        phase(ev, "idle")["exit_code"] = 1
        run = self.run_check(ev)
        self.assertEqual(run.outcome("exit_code", "idle"), "fail")
        self.assertEqual(run.outcome("exit_code", "load"), "pass")

    def test_failed_samples_one_percent(self):
        for failed, expected in ((1, "pass"), (2, "fail")):
            ev = make_evidence()
            phase(ev, "idle")["failed_samples"] = failed
            run = self.run_check(ev)
            self.assertEqual(run.outcome("failed_samples", "idle"), expected)
            self.assertEqual(run.row("failed_samples", "idle")["limit"], 1)
        ev = make_evidence()
        phase(ev, "load")["failed_samples"] = 1
        self.assertEqual(self.run_check(ev).outcome("failed_samples", "load"), "fail")

    def test_self_sample_needs_both_tolerances_exceeded(self):
        cases = (
            (35 * MIB, 30 * MIB, "pass"),   # 5 MiB > 4 MiB, but below 20 % of 30 MiB
            (13 * MIB, 10 * MIB, "pass"),   # 30 % > 20 %, but 3 MiB below 4 MiB
            (15 * MIB, 10 * MIB, "fail"),   # 50 % and 5 MiB
            (5 * MIB, 10 * MIB, "fail"),    # a self-sampler reading low fails the same way
        )
        for self_bytes, external, expected in cases:
            with self.subTest(self_bytes=self_bytes, external=external):
                ev = make_evidence()
                set_self(ev, "idle", self_bytes, external)
                run = self.run_check(ev)
                row = run.row("self_sample_agreement", "idle")
                self.assertEqual(row["outcome"], expected)
                self.assertEqual(row["observed"], self_bytes - external)

    def test_self_sample_tolerance_from_budgets(self):
        ev = make_evidence()
        set_self(ev, "idle", 15 * MIB, 10 * MIB)
        budgets = copy.deepcopy(BUDGETS)
        budgets["self_sample_tolerance"]["bytes"] = 6 * MIB
        self.assertEqual(self.run_check(ev, budgets=budgets).outcome("self_sample_agreement", "idle"), "pass")

    def test_self_sample_missing_or_wrong_metric_fails(self):
        ev = make_evidence()
        phase(ev, "idle")["self_sample"] = None
        self.assertEqual(self.run_check(ev).outcome("self_sample_agreement", "idle"), "fail")
        ev = make_evidence()
        phase(ev, "idle")["self_sample"]["footprint_metric"] = "phys_footprint"
        self.assertEqual(self.run_check(ev).outcome("self_sample_agreement", "idle"), "fail")
        ev = make_evidence()
        phase(ev, "idle")["self_sample_external"] = None
        self.assertEqual(self.run_check(ev).outcome("self_sample_agreement", "idle"), "fail")

    def test_prior_results_are_recomputed(self):
        ev = make_evidence()
        phase(ev, "idle")["metrics"]["threads"]["max"] = 50
        ev["results"].append({"check": "threads_max", "phase": "idle", "observed": 6, "limit": 12,
                              "baseline": None, "outcome": "pass"})
        ev["outcome"] = "pass"
        run = self.run_check(ev)
        self.assertEqual(run.outcome("threads_max", "idle"), "fail")
        self.assertEqual(run.doc["outcome"], "fail")


class BaselineTests(CheckTestCase):
    def test_missing_baseline_outside_tag_builds(self):
        for channel in ("master", "pr"):
            with self.subTest(channel=channel):
                run = self.run_check(make_evidence(channel=channel))
                row = run.row("baseline_present")
                self.assertEqual((row["observed"], row["outcome"]), ("none", "recorded"))
                self.assertEqual(run.doc["baseline"], {"kind": "none", "identity": None, "environment_match": None})
                self.assertEqual(run.code, 0)
                self.assertFalse(run.rows("regression_footprint_p95", "idle"))

    def test_missing_baseline_still_enforces_absolute_budgets(self):
        ev = make_evidence(channel="pr")
        phase(ev, "idle")["metrics"]["threads"]["max"] = 13
        self.assertEqual(self.run_check(ev).code, 1)

    def test_missing_baseline_fails_on_tag_build(self):
        run = self.run_check(make_evidence(channel="prerelease"))
        self.assertEqual(run.outcome("baseline_present"), "fail")
        self.assertEqual(run.code, 1)

    def test_missing_baseline_on_smoke_is_recorded(self):
        run = self.run_check(make_evidence(smoke=True))
        self.assertEqual(run.outcome("baseline_present"), "recorded")
        self.assertEqual(run.code, 0)

    def test_invalid_baselines(self):
        pr = make_baseline()
        pr["identity"]["channel"] = "pr"
        smoke = make_baseline()
        smoke["smoke"] = True
        smoke["identity"] = None
        failed = make_baseline()
        failed["outcome"] = "fail"
        schema_bad = make_baseline()
        schema_bad["extra"] = 1
        for label, baseline in (("pr", pr), ("smoke", smoke), ("failed", failed), ("schema", schema_bad),
                                ("unparseable", b"{not json"), ("duplicate", b'{"a": 1, "a": 1}')):
            for channel in ("pr", "master", "prerelease"):
                with self.subTest(baseline=label, channel=channel):
                    run = self.run_check(make_evidence(channel=channel), baseline=baseline)
                    self.assertEqual(run.outcome("baseline_invalid"), "fail")
                    self.assertEqual(run.doc["baseline"]["kind"], "none")
                    self.assertEqual(run.code, 1)
                    self.assertFalse(run.rows("regression_footprint_p95", "idle"))

    def test_valid_baseline_kinds(self):
        run = self.run_check(make_evidence(), baseline=make_baseline("master"))
        self.assertEqual(run.code, 0, run.stdout)
        self.assertEqual(run.doc["baseline"]["kind"], "initial")
        self.assertEqual(run.doc["baseline"]["identity"]["commit"], "f" * 40)
        self.assertIs(run.doc["baseline"]["environment_match"], True)
        self.assertEqual(run.outcome("baseline_present"), "pass")
        self.assertEqual(run.outcome("baseline_invalid"), "pass")
        self.assertEqual(run.outcome("baseline_environment"), "pass")
        run = self.run_check(make_evidence(channel="prerelease"), baseline=make_baseline("prerelease"))
        self.assertEqual(run.doc["baseline"]["kind"], "release")
        self.assertEqual(run.code, 0, run.stdout)
        self.assertEqual(check.load_evidence_validator().errors(run.doc), [])

    def test_environment_mismatch_fails(self):
        for field, value in (("runner_label", "ubuntu-24.04"), ("os_version", "24.04"),
                             ("runner_os", "Windows"), ("runner_arch", "ARM64")):
            for channel in ("pr", "master", "prerelease"):
                with self.subTest(field=field, channel=channel):
                    base = make_baseline("prerelease" if channel == "prerelease" else "master")
                    base["environment"][field] = value
                    run = self.run_check(make_evidence(channel=channel), baseline=base)
                    self.assertEqual(run.outcome("baseline_environment"), "fail")
                    self.assertIn(field, run.row("baseline_environment")["observed"])
                    self.assertIs(run.doc["baseline"]["environment_match"], False)
                    self.assertFalse(run.rows("regression_footprint_p95", "idle"))
                    self.assertEqual(run.code, 1)

    def test_target_mismatch_fails(self):
        base = make_baseline()
        base["target"] = "macos-arm64"
        base["environment"]["clk_tck"] = None
        base["environment"]["mach_timebase"] = {"numer": 125, "denom": 3}
        run = self.run_check(make_evidence(), baseline=base)
        self.assertEqual(run.outcome("baseline_environment"), "fail")
        self.assertIn("target", run.row("baseline_environment")["observed"])

    def test_smoke_run_never_fails_on_baseline(self):
        base = make_baseline()
        base["environment"]["runner_label"] = "ubuntu-24.04"
        run = self.run_check(make_evidence(smoke=True), baseline=base)
        self.assertEqual(run.outcome("baseline_environment"), "recorded")
        self.assertEqual(run.code, 0)


class RegressionTests(CheckTestCase):
    def compare(self, observed_p95, baseline_p95, budgets=None):
        ev = make_evidence()
        phase(ev, "idle")["metrics"]["footprint_bytes"]["p95"] = observed_p95
        set_self(ev, "idle", observed_p95, observed_p95)
        base = make_baseline()
        phase(base, "idle")["metrics"]["footprint_bytes"]["p95"] = baseline_p95
        return self.run_check(ev, baseline=base, budgets=budgets)

    def test_footprint_requires_both_tolerances(self):
        # 2 MiB dominates below 20,971,520 bytes; 10 % dominates above.
        self.assertEqual(self.compare(20_000_000 + 2_097_152, 20_000_000).outcome("regression_footprint_p95", "idle"), "pass")
        self.assertEqual(self.compare(20_000_000 + 2_097_153, 20_000_000).outcome("regression_footprint_p95", "idle"), "fail")
        self.assertEqual(self.compare(33_000_000, 30_000_000).outcome("regression_footprint_p95", "idle"), "pass")
        self.assertEqual(self.compare(33_000_001, 30_000_000).outcome("regression_footprint_p95", "idle"), "fail")
        # Only the ratio exceeded, then only the byte tolerance exceeded: both pass.
        self.assertEqual(self.compare(22_050_000, 20_000_000).outcome("regression_footprint_p95", "idle"), "pass")
        self.assertEqual(self.compare(32_500_000, 30_000_000).outcome("regression_footprint_p95", "idle"), "pass")
        run = self.compare(33_000_001, 30_000_000)
        row = run.row("regression_footprint_p95", "idle")
        self.assertEqual((row["baseline"], row["limit"]), (30_000_000, 33_000_000))
        self.assertEqual(run.code, 1)
        self.assertIn("baseline_identity=0.1.0-dev.0+g" + "f" * 40, run.stdout)

    def test_footprint_improvement_is_recorded(self):
        run = self.compare(9_000_000, 9_500_000)
        self.assertEqual(run.outcome("regression_footprint_p95", "idle"), "recorded")
        self.assertEqual(run.code, 0)

    def test_footprint_tolerance_from_budgets(self):
        budgets = copy.deepcopy(BUDGETS)
        budgets["regression"]["footprint_ratio"] = 0.2
        self.assertEqual(self.compare(33_000_001, 30_000_000, budgets).outcome("regression_footprint_p95", "idle"), "pass")

    def threads(self, observed, base_value, budgets=None):
        ev = make_evidence()
        phase(ev, "load")["metrics"]["threads"]["max"] = observed
        base = make_baseline()
        phase(base, "load")["metrics"]["threads"]["max"] = base_value
        return self.run_check(ev, baseline=base, budgets=budgets).outcome("regression_threads_max", "load")

    def test_threads_tolerance(self):
        self.assertEqual(self.threads(8, 6), "pass")
        self.assertEqual(self.threads(9, 6), "fail")
        budgets = copy.deepcopy(BUDGETS)
        budgets["regression"]["threads"] = 3
        self.assertEqual(self.threads(9, 6, budgets), "pass")
        budgets["regression"]["threads"] = 0
        self.assertEqual(self.threads(7, 6, budgets), "fail")

    def descriptors(self, observed, base_value, target="linux-x64", budgets=None):
        ev = make_evidence(target=target)
        phase(ev, "idle")["metrics"]["descriptors"]["max"] = observed
        base = make_evidence(target=target)
        base["identity"]["commit"] = "f" * 40
        base["results"] = list(EXAMPLE["results"])
        phase(base, "idle")["metrics"]["descriptors"]["max"] = base_value
        return self.run_check(ev, baseline=base, budgets=budgets).outcome("regression_descriptors_max", "idle")

    def test_descriptor_tolerances(self):
        self.assertEqual(self.descriptors(19, 15), "pass")
        self.assertEqual(self.descriptors(20, 15), "fail")
        self.assertEqual(self.descriptors(146, 130, "windows-x64"), "pass")
        self.assertEqual(self.descriptors(147, 130, "windows-x64"), "fail")
        budgets = copy.deepcopy(BUDGETS)
        budgets["regression"]["descriptors_fd"] = 5
        budgets["regression"]["descriptors_handle"] = 17
        self.assertEqual(self.descriptors(20, 15, budgets=budgets), "pass")
        self.assertEqual(self.descriptors(147, 130, "windows-x64", budgets), "pass")

    def test_cpu_and_shutdown_regressions_recorded(self):
        ev = make_evidence()
        phase(ev, "idle")["metrics"]["cpu_core_pct"]["mean"] = 4.9
        phase(ev, "idle")["shutdown_ms"] = 9000
        run = self.run_check(ev, baseline=make_baseline())
        for name in ("regression_cpu_mean", "regression_shutdown_ms"):
            for p in ("idle", "load"):
                self.assertEqual(run.outcome(name, p), "recorded")
        self.assertEqual(run.row("regression_shutdown_ms", "idle")["baseline"], 42)
        self.assertEqual(run.code, 0)


class CandidateTests(CheckTestCase):
    def candidate(self, run):
        path = run.out_dir / "baseline-candidate.json"
        return path.read_bytes() if path.exists() else None

    def test_master_and_prerelease_write_identical_candidate(self):
        for channel in ("master", "prerelease"):
            for baseline in (MISSING, make_baseline("master" if channel == "master" else "prerelease")):
                with self.subTest(channel=channel, baseline=baseline is not MISSING):
                    run = self.run_check(make_evidence(channel=channel), baseline=baseline)
                    if channel == "prerelease" and baseline is MISSING:
                        self.assertEqual(run.code, 1)
                        self.assertIsNone(self.candidate(run))
                        continue
                    self.assertEqual(run.code, 0, run.stdout)
                    self.assertEqual(self.candidate(run), (run.out_dir / "result.json").read_bytes())
                    shutil.rmtree(run.out_dir)

    def test_no_candidate_for_pr_smoke_or_failed(self):
        failed = make_evidence()
        phase(failed, "idle")["exit_code"] = 3
        for label, ev in (("pr", make_evidence(channel="pr")), ("smoke", make_evidence(smoke=True)), ("failed", failed)):
            with self.subTest(run=label):
                stale = self.dir / "out" / "baseline-candidate.json"
                stale.parent.mkdir(parents=True, exist_ok=True)
                stale.write_text("stale", encoding="utf-8")
                run = self.run_check(ev)
                self.assertIsNone(self.candidate(run))
                self.assertTrue((run.out_dir / "result.json").exists())

    def test_output_is_canonical(self):
        run = self.run_check(make_evidence())
        raw = (run.out_dir / "result.json").read_text(encoding="utf-8")
        self.assertEqual(raw, json.dumps(json.loads(raw), indent=2, sort_keys=True) + "\n")


class ExitCodeTests(CheckTestCase):
    def test_exit_codes(self):
        self.assertEqual(self.run_check(make_evidence()).code, 0)
        bad = make_evidence()
        phase(bad, "idle")["exit_code"] = 1
        self.assertEqual(self.run_check(bad).code, 1)
        schema_bad = make_evidence()
        schema_bad["surprise"] = True
        self.assertEqual(self.run_check(schema_bad).code, 2)
        self.assertEqual(self.run_check(None, raw_evidence=b"{").code, 2)
        budgets = copy.deepcopy(BUDGETS)
        del budgets["regression"]["threads"]
        self.assertEqual(self.run_check(make_evidence(), budgets=budgets).code, 2)
        budgets = copy.deepcopy(BUDGETS)
        budgets["threads_max"] = "12"
        self.assertEqual(self.run_check(make_evidence(), budgets=budgets).code, 2)

    def test_usage_errors(self):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(check.main([]), 2)
            self.assertEqual(check.main(["--evidence", str(self.dir / "missing.json"), "--budgets",
                                         str(HERE / "budgets.json"), "--baseline", str(self.dir / "b.json")]), 2)

    def test_result_lines_name_every_field(self):
        run = self.run_check(make_evidence(), baseline=make_baseline())
        lines = [l for l in run.stdout.splitlines() if l.startswith("check=")]
        self.assertEqual(len(lines), len(run.doc["results"]))
        for line in lines:
            for key in ("check=", "phase=", "observed=", "limit=", "baseline=", "baseline_identity=", "outcome="):
                self.assertIn(key, line)
        self.assertTrue(any(l.startswith("outcome=") for l in run.stdout.splitlines()))


class ProtocolAdmissionTests(CheckTestCase):
    def malformed_runs(self):
        for name in ('idle', 'load'):
            ev = make_evidence()
            ev['phases'] = [phase(ev, name)]
            yield name + '-only', ev
        ev = make_evidence()
        ev['phases'].append(copy.deepcopy(ev['phases'][0]))
        yield 'duplicate-phase', ev
        for key, value in (('sample_interval_ms', 60000), ('warmup_ms', 0),
                           ('samples', 1), ('samples', 119), ('samples', 121)):
            ev = make_evidence()
            phase(ev, 'idle')[key] = value
            yield f'{key}-{value}', ev

    def test_full_evidence_rejects_incomplete_external_protocol(self):
        for label, ev in self.malformed_runs():
            with self.subTest(case=label):
                self.assertEqual(check.load_evidence_validator().errors(ev), [])
                run = self.run_check(ev)
                self.assertEqual(run.code, 2)
                self.assertFalse((run.out_dir / check.CANDIDATE_NAME).exists())

    def test_baseline_admission_rejects_claimed_pass_with_incomplete_protocol(self):
        for label, base in self.malformed_runs():
            with self.subTest(case=label):
                run = self.run_check(make_evidence(), baseline=base)
                self.assertEqual(run.code, 1)
                self.assertEqual(run.outcome('baseline_invalid'), 'fail')
                self.assertFalse(run.rows('regression_footprint_p95', 'idle'))

    def test_candidate_admission_rechecks_protocol_despite_claimed_pass(self):
        for label, ev in self.malformed_runs():
            with self.subTest(case=label):
                self.assertEqual(ev['outcome'], 'pass')
                self.assertFalse(check.qualifies_as_candidate(ev))
        ev = make_evidence()
        phase(ev, 'load')['duration_ms'] = 1000
        phase(ev, 'load')['samples'] = 1
        self.assertFalse(check.qualifies_as_candidate(ev))

    def test_baseline_admission_rejects_relabelled_short_smoke(self):
        base = make_evidence()
        phase(base, 'load').update(duration_ms=1000, samples=1)
        run = self.run_check(make_evidence(), baseline=base)
        self.assertEqual(run.code, 1)
        self.assertEqual(run.outcome('baseline_invalid'), 'fail')

    def test_missing_baseline_phase_cannot_record_regressions(self):
        base = make_evidence()
        base['phases'] = [phase(base, 'load')]
        with self.assertRaises(check.InputError):
            check._regression(make_evidence(), base, BUDGETS)

    def test_partial_smoke_remains_diagnostic_and_cannot_be_promoted(self):
        ev = make_evidence(smoke=True)
        ev['phases'] = [phase(ev, 'load')]
        phase(ev, 'load')['warmup_ms'] = 500
        run = self.run_check(ev)
        self.assertEqual(run.code, 0)
        self.assertFalse(check.qualifies_as_candidate(run.doc))
        self.assertFalse((run.out_dir / check.CANDIDATE_NAME).exists())


class WorkloadTests(CheckTestCase):
    def test_all_expected_checks(self):
        cases = [c for c in CASES['cases'] if 'expected_checks' in c]
        self.assertEqual(len(cases), 19)
        for case in cases:
            with self.subTest(case=case['id']):
                ev = copy.deepcopy(case['instance'])
                self.assertEqual(check.load_evidence_validator().errors(ev), [])
                for p in ev['phases']:
                    p['profile']['sha256'] = PROFILE_SHA[p['profile']['name']]
                run = self.run_check(ev)
                self.assertIn(run.code, (0, 1), run.stdout)
                for want in case['expected_checks']:
                    self.assertEqual(run.outcome(want['check'], want['phase']), want['outcome'])
                    if want['outcome'] == 'fail':
                        self.assertEqual(run.code, 1)

    def test_cadence_bounds(self):
        for delta, expected in ((593, 'fail'), (594, 'pass'), (601, 'pass'), (602, 'fail')):
            ev = make_evidence()
            p = phase(ev, 'load')
            p['health_progress']['end']['samples'] = p['health_progress']['start']['samples'] + delta
            self.assertEqual(self.run_check(ev).outcome('sampler_progress', 'load'), expected)

    def test_freshness_boundaries(self):
        for key, limit in (('max_write_age_ms', 2100), ('max_sample_age_ms', 2100),
                           ('max_observation_gap_ms', 2000)):
            for value, expected in ((limit, 'pass'), (limit + 1, 'fail')):
                ev = make_evidence()
                phase(ev, 'load')['health_progress'][key] = value
                self.assertEqual(self.run_check(ev).outcome('health_freshness', 'load'), expected)

    def test_untrusted_endpoint_and_summary(self):
        mutations = [lambda p: p['health_progress']['end'].update(pid=5),
                     lambda p: p['health_progress']['end'].update(state='stopped'),
                     lambda p: p['health_progress']['end'].update(interval_ms=200),
                     lambda p: p['health_progress']['end'].update(sampled_uptime_ms=999999),
                     lambda p: p['health_progress'].update(observations=61),
                     lambda p: p['health_progress'].update(max_sample_age_ms=0),
                     lambda p: p.update(duration_ms=59999, samples=59),
                     lambda p: p['health_progress']['end'].update(observed_elapsed_ms=58999)]
        for mutate in mutations:
            ev = make_evidence()
            p = phase(ev, 'load')
            # Make a nonzero endpoint age so an understated maximum is detectable.
            p['health_progress']['end']['sampled_unix_ms'] -= 1
            p['health_progress']['end']['sampled_uptime_ms'] -= 1
            mutate(p)
            self.assertEqual(self.run_check(ev).outcome('health_freshness', 'load'), 'fail')

    def test_pair_recomputed_despite_forged_verdict(self):
        ev = make_evidence()
        p = phase(ev, 'load')
        p['self_sample']['footprint_bytes'] = 20_000_000
        ev['results'] = [check._row('self_sample_agreement', 'load', 0, 1, None, 'pass')]
        self.assertEqual(self.run_check(ev).outcome('self_sample_agreement', 'load'), 'fail')

    def test_known_example_difference_is_recomputed(self):
        ev = make_evidence()
        run = self.run_check(ev)
        self.assertEqual(run.row('self_sample_agreement', 'idle')['observed'], 0)
        self.assertEqual(run.row('self_sample_agreement', 'load')['observed'], 0)

class AdditionalWorkloadTests(CheckTestCase):
    def test_short_smoke_is_recorded_but_stale_or_wrong_metric_fails(self):
        ev = make_evidence(smoke=True)
        p = phase(ev, 'idle')
        p['duration_ms'] = 1000
        p['finished_unix_ms'] = p['started_unix_ms'] + 1000
        g = p['health_progress']
        g['end'] = dict(g['start'], observed_unix_ms=p['finished_unix_ms'], observed_elapsed_ms=1000)
        g['observations'] = 3
        g['max_write_age_ms'] = g['max_sample_age_ms'] = 11000
        p['self_sample'].update({k: g['end'][k] for k in ('written_unix_ms', 'sampled_unix_ms', 'sampled_uptime_ms')})
        run = self.run_check(ev)
        self.assertEqual(run.outcome('sampler_progress', 'idle'), 'recorded')
        self.assertEqual(run.outcome('self_sample_agreement', 'idle'), 'recorded')
        p['self_sample']['footprint_metric'] = 'phys_footprint'
        self.assertEqual(self.run_check(ev).outcome('self_sample_agreement', 'idle'), 'fail')
        p['health_progress']['max_sample_age_ms'] = 62001
        self.assertEqual(self.run_check(ev).outcome('health_freshness', 'idle'), 'fail')

    def test_self_pair_exact_time_and_tolerance_boundaries(self):
        for delta, expected in ((2000, 'pass'), (2001, 'fail')):
            ev = make_evidence()
            p = phase(ev, 'load')
            p['self_sample_external']['unix_ms'] -= delta
            self.assertEqual(self.run_check(ev).outcome('self_sample_agreement', 'load'), expected)
        for self_bytes, external_bytes, expected in ((25_165_824, 20_971_520, 'pass'),
                                                     (25_165_825, 20_971_520, 'fail'),
                                                     (36_000_000, 30_000_000, 'pass'),
                                                     (36_000_001, 30_000_000, 'fail')):
            ev = make_evidence()
            set_self(ev, 'load', self_bytes, external_bytes)
            self.assertEqual(self.run_check(ev).outcome('self_sample_agreement', 'load'), expected)

    def test_all_counters_and_ordering_are_rechecked(self):
        for counter in check.COUNTERS:
            ev = make_evidence()
            p = phase(ev, 'load')
            p['health_progress']['start'][counter] = p['health_progress']['end'][counter] + 1
            self.assertEqual(self.run_check(ev).outcome('sampler_progress', 'load'), 'fail')
        for key in ('sample_failures', 'health_write_failures'):
            ev = make_evidence()
            phase(ev, 'load')['health_progress']['end'][key] += 1
            self.assertEqual(self.run_check(ev).outcome('sampler_progress', 'load'), 'fail')
        for key in ('written_unix_ms', 'sampled_unix_ms'):
            ev = make_evidence()
            p = phase(ev, 'load')
            p['health_progress']['end'][key] = p['finished_unix_ms'] + 1
            self.assertEqual(self.run_check(ev).outcome('health_freshness', 'load'), 'fail')

    def test_log_activity_boundaries(self):
        for key, values in (('sample_events', ((593, 'fail'), (594, 'pass'), (601, 'fail'))),
                            ('rotations_observed', ((0, 'fail'), (1, 'fail'), (2, 'pass'), (3, 'fail'))),
                            ('invalid_lines', ((0, 'pass'), (1, 'fail')))):
            for value, expected in values:
                ev = make_evidence()
                phase(ev, 'load')['log_activity'][key] = value
                self.assertEqual(self.run_check(ev).outcome('load_log_activity', 'load'), expected)
        ev = make_evidence()
        phase(ev, 'load')['health_progress']['end']['log_errors'] += 1
        self.assertEqual(self.run_check(ev).outcome('load_log_activity', 'load'), 'fail')

class DelayedBoundaryTests(CheckTestCase):
    def test_progress_uses_endpoint_monotonic_distance(self):
        for delta, expected in ((574, 'fail'), (575, 'pass'), (581, 'pass'), (582, 'fail')):
            ev = make_evidence()
            p = phase(ev, 'load')
            a, b = p['health_progress']['start'], p['health_progress']['end']
            a.update(observed_elapsed_ms=1000, observed_unix_ms=p['started_unix_ms'] + 1000)
            b.update(observed_elapsed_ms=59000, observed_unix_ms=p['finished_unix_ms'] - 1000,
                     written_unix_ms=p['finished_unix_ms'] - 1000,
                     sampled_unix_ms=p['finished_unix_ms'] - 1000, samples=a['samples'] + delta)
            self.assertEqual(self.run_check(ev).outcome('sampler_progress', 'load'), expected)

    def test_window_clock_discrepancy_and_boundary_positions(self):
        for delta, expected in ((2000, 'pass'), (2001, 'fail')):
            ev = make_evidence()
            p = phase(ev, 'load')
            p['finished_unix_ms'] += delta
            for key in ('observed_unix_ms', 'written_unix_ms', 'sampled_unix_ms'):
                p['health_progress']['end'][key] += delta
            self.assertEqual(self.run_check(ev).outcome('health_freshness', 'load'), expected)
        for elapsed, expected in ((1000, 'pass'), (1001, 'fail')):
            ev = make_evidence()
            p = phase(ev, 'load')
            p['health_progress']['start'].update(observed_elapsed_ms=elapsed,
                                                observed_unix_ms=p['started_unix_ms'] + elapsed)
            p['health_progress']['max_write_age_ms'] = p['health_progress']['max_sample_age_ms'] = elapsed
            self.assertEqual(self.run_check(ev).outcome('health_freshness', 'load'), expected)


if __name__ == "__main__":
    unittest.main()
