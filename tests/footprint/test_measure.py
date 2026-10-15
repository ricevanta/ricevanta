"""Task 2 tests for measure.py against fake_agent.py (docs/specs/footprint-harness.md sections 3 and 5).

Evidence is validated with jsonschema from the hash-locked validator closure;
everything else in the harness uses the standard library only.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import measure

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MEASURE = HERE / "measure.py"
FAKE = HERE / "fake_agent.py"
EVIDENCE_SCHEMA = json.loads((ROOT / "schemas/agent/footprint/v1/evidence.schema.json").read_text(encoding="utf-8"))
HEALTH_SCHEMA = json.loads((ROOT / "schemas/agent/health/v1/health.schema.json").read_text(encoding="utf-8"))
CONFIG_SCHEMA = json.loads((ROOT / "schemas/agent/config/v1/config.schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((ROOT / "schemas/agent/footprint/v1/example.json").read_text(encoding="utf-8"))
TARGET = {"linux": "linux-x64", "darwin": "macos-arm64", "win32": "windows-x64"}[sys.platform]
MIB = 1024 * 1024

CLAIMED = {
    "version": "0.1.0-dev.0+g0123456789abcdef0123456789abcdef01234567",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "channel": "master",
    "sourceEpoch": 1760000000,
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_measure(add_cleanup, *args, mode=None, identity_env=None, scale="0.05", phases="idle,load", timeout=120):
    """Run measure.py with a private TMPDIR and record directory; return (proc, evidence path, tmp, record)."""
    work = Path(tempfile.mkdtemp(prefix="rv-measure-test-"))
    add_cleanup(shutil.rmtree, work, ignore_errors=True)
    tmp = work / "tmp"
    record = work / "record"
    tmp.mkdir()
    record.mkdir()
    out = work / "out" / "evidence.json"
    env = dict(os.environ)
    env["TMPDIR"] = str(tmp)
    env["TEMP"] = str(tmp)
    env["TMP"] = str(tmp)
    env["RICEVANTA_FAKE_RECORD"] = str(record)
    env.pop("RICEVANTA_FAKE_MODE", None)
    env.pop("RICEVANTA_FAKE_IDENTITY", None)
    for name in ("GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_ARCH", "RICEVANTA_RUNNER_LABEL"):
        env.pop(name, None)
    if mode:
        env["RICEVANTA_FAKE_MODE"] = mode
    if identity_env is not None:
        env["RICEVANTA_FAKE_IDENTITY"] = json.dumps(identity_env)
    cmd = [sys.executable, "-B", str(MEASURE), "--binary", str(FAKE), "--target", TARGET,
           "--phases", phases, "--duration-scale", scale, "--out", str(out), *args]
    started = time.monotonic()
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    proc.elapsed = time.monotonic() - started
    return proc, out, tmp, record


def phase(evidence, name):
    return next(p for p in evidence["phases"] if p["name"] == name)


def results(evidence, check, phase_name=None):
    return [r for r in evidence["results"] if r["check"] == check and r["phase"] == phase_name]


class SmokeRunTests(unittest.TestCase):
    """One two-phase run with --identity under a scale below 1, shared by several assertions."""

    @classmethod
    def setUpClass(cls):
        work = Path(tempfile.mkdtemp(prefix="rv-identity-"))
        cls.addClassCleanup(shutil.rmtree, work, ignore_errors=True)
        cls.identity_path = work / "identity.json"
        cls.identity_path.write_text(json.dumps(CLAIMED, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        cls.proc, cls.out, cls.tmp, cls.record = run_measure(
            cls.addClassCleanup, "--identity", str(cls.identity_path), identity_env=CLAIMED
        )
        cls.evidence = json.loads(cls.out.read_text(encoding="utf-8")) if cls.out.exists() else None

    def test_exit_zero_and_evidence_validates(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        Draft202012Validator(EVIDENCE_SCHEMA).validate(self.evidence)

    def test_scale_below_one_is_smoke_without_identity(self):
        self.assertIs(self.evidence["smoke"], True)
        self.assertIsNone(self.evidence["identity"])
        self.assertEqual(results(self.evidence, "identity_mismatch")[0]["outcome"], "recorded")

    def test_reported_identity_is_the_binary_output(self):
        self.assertEqual(self.evidence["binary"]["reported_identity"], CLAIMED)
        self.assertEqual(self.evidence["binary"]["sha256"], sha256(FAKE))
        self.assertEqual(self.evidence["binary"]["size"], FAKE.stat().st_size)
        self.assertEqual(self.evidence["binary"]["name"], "ricevanta-agent.exe" if sys.platform == "win32" else "ricevanta-agent")

    def test_both_phases_with_committed_profile_hashes(self):
        names = [p["name"] for p in self.evidence["phases"]]
        self.assertEqual(names, ["idle", "load"])
        self.assertEqual(phase(self.evidence, "idle")["profile"], {"name": "idle", "sha256": sha256(HERE / "profiles/idle.json")})
        self.assertEqual(phase(self.evidence, "load")["profile"], {"name": "health-burst", "sha256": sha256(HERE / "profiles/health-burst.json")})

    def test_phase_timing_scaled(self):
        idle = phase(self.evidence, "idle")
        load = phase(self.evidence, "load")
        self.assertEqual(idle["warmup_ms"], 500)
        self.assertEqual(idle["duration_ms"], 6000)
        self.assertEqual(load["duration_ms"], 3000)
        self.assertEqual(idle["sample_interval_ms"], 1000)
        self.assertEqual(idle["samples"], 6)
        self.assertEqual(load["samples"], 3)
        self.assertEqual(idle["failed_samples"], 0)
        self.assertEqual(idle["exit_code"], 0)
        self.assertEqual(idle["metrics"]["footprint_bytes"]["metric"], measure.samplers.current().METRIC)
        self.assertGreater(idle["metrics"]["footprint_bytes"]["p95"], 0)

    def test_agent_got_profile_copy_in_temporary_tree(self):
        for profile in ("idle", "health-burst"):
            rec = json.loads((self.record / f"{sha256(HERE / 'profiles' / (profile + '.json'))}.json").read_text(encoding="utf-8"))
            self.assertEqual(rec["config_sha256"], sha256(HERE / "profiles" / f"{profile}.json"))
            self.assertEqual(Path(rec["config"]).name, "agent.json")
            self.assertEqual(Path(rec["config"]).parent, Path(rec["state_dir"]).parent)
            self.assertEqual(rec["log"], "file")
            if sys.platform != "win32":
                self.assertEqual(rec["config_mode"], 0o600)
            # The fake's own health document conforms to the health schema.
            Draft202012Validator(HEALTH_SCHEMA).validate(rec["last_health"])

    def test_self_sample_recorded(self):
        for p in self.evidence["phases"]:
            self.assertIsNotNone(p["self_sample"])
            self.assertEqual(p["self_sample"]["footprint_metric"], p["metrics"]["footprint_bytes"]["metric"])
            self.assertEqual(len(results(self.evidence, "self_sample_agreement", p["name"])), 1)

    def test_temporary_tree_removed(self):
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_baseline_not_evaluated_by_measure(self):
        self.assertEqual(self.evidence["baseline"], {"kind": "none", "identity": None, "environment_match": None})
        self.assertFalse([r for r in self.evidence["results"] if r["check"].startswith(("baseline_", "regression_"))])

    def test_environment_record(self):
        env = self.evidence["environment"]
        self.assertEqual(env["runner_label"], "local")
        self.assertNotIn("run_id", env)
        self.assertGreater(env["memory_bytes"], 0)
        self.assertEqual(env["clk_tck"], 100 if sys.platform == "linux" else None)

    def test_no_paths_in_evidence(self):
        text = self.out.read_text(encoding="utf-8")
        self.assertNotIn(str(self.tmp), text)
        self.assertNotIn(str(HERE), text)


class RunVariantTests(unittest.TestCase):
    def test_without_identity_is_smoke(self):
        proc, out, _, _ = run_measure(self.addCleanup, phases="load")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        evidence = json.loads(out.read_text(encoding="utf-8"))
        self.assertIs(evidence["smoke"], True)
        self.assertIsNone(evidence["identity"])
        self.assertEqual(evidence["binary"]["reported_identity"],
                         {"version": "0.0.0-local", "commit": "unknown", "channel": "local", "sourceEpoch": 0})
        Draft202012Validator(EVIDENCE_SCHEMA).validate(evidence)

    def test_warmup_is_excluded(self):
        # The fake holds 128 MiB for 200 ms after ready, inside the 500 ms scaled warm-up.
        proc, out, _, _ = run_measure(self.addCleanup, mode="warmup-spike", phases="idle")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        evidence = json.loads(out.read_text(encoding="utf-8"))
        self.assertLess(phase(evidence, "idle")["metrics"]["footprint_bytes"]["max"], 96 * MIB)

    def test_spinning_agent_is_near_one_core(self):
        proc, out, _, _ = run_measure(self.addCleanup, mode="spin", phases="idle")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        evidence = json.loads(out.read_text(encoding="utf-8"))
        cpu = phase(evidence, "idle")["metrics"]["cpu_core_pct"]
        self.assertGreater(cpu["mean"], 70)
        self.assertLess(cpu["mean"], 130)
        gate = [r for r in results(evidence, "cpu_mean", "idle") if r["outcome"] != "recorded"]
        self.assertEqual(gate[0]["outcome"], "fail")
        self.assertEqual(evidence["outcome"], "fail")

    def test_never_ready_exits_one_without_evidence(self):
        proc, out, tmp, record = run_measure(self.addCleanup, mode="never-ready", phases="idle")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not_ready", proc.stdout + proc.stderr)
        self.assertIn("idle", proc.stdout + proc.stderr)
        self.assertFalse(out.exists())
        # 30 s scaled by 0.05 is 1.5 s; allow interpreter start-up and cleanup.
        self.assertLess(proc.elapsed, 15)
        self.assertEqual(list(tmp.iterdir()), [])
        rec = json.loads(next(record.iterdir()).read_text(encoding="utf-8"))
        if sys.platform != "win32":
            with self.assertRaises(ProcessLookupError):
                os.kill(rec["pid"], 0)

    def test_ignored_stop_records_nonzero_exit_after_deadline(self):
        proc, out, tmp, _ = run_measure(self.addCleanup, mode="ignore-stop", phases="load", timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        evidence = json.loads(out.read_text(encoding="utf-8"))
        load = phase(evidence, "load")
        self.assertNotEqual(load["exit_code"], 0)
        # Deadline is shutdown.timeout_ms (10000) plus 5000 ms.
        self.assertGreaterEqual(load["shutdown_ms"], 15000)
        self.assertEqual(results(evidence, "exit_code", "load")[0]["outcome"], "fail")
        self.assertEqual(results(evidence, "shutdown_ms", "load")[0]["outcome"], "fail")
        self.assertEqual(evidence["outcome"], "fail")
        self.assertEqual(list(tmp.iterdir()), [])
        Draft202012Validator(EVIDENCE_SCHEMA).validate(evidence)

    def test_bad_version_output_exits_one(self):
        proc, out, _, _ = run_measure(self.addCleanup, mode="bad-version", phases="idle")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("version", proc.stdout + proc.stderr)
        self.assertFalse(out.exists())


class UsageTests(unittest.TestCase):
    def run_usage(self, *args):
        return subprocess.run([sys.executable, "-B", str(MEASURE), *args], capture_output=True, text=True, timeout=60)

    def base(self, out):
        return ["--binary", str(FAKE), "--target", TARGET, "--phases", "idle", "--out", str(out)]

    def test_usage_errors_exit_two(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "e.json"
            self.assertEqual(self.run_usage().returncode, 2)
            self.assertEqual(self.run_usage(*self.base(out), "--duration-scale", "0").returncode, 2)
            self.assertEqual(self.run_usage(*self.base(out), "--duration-scale", "1.5").returncode, 2)
            self.assertEqual(self.run_usage(*self.base(out), "--duration-scale", "nan").returncode, 2)
            self.assertEqual(self.run_usage("--binary", str(FAKE), "--target", "linux-arm64", "--phases", "idle", "--out", str(out)).returncode, 2)
            other = next(t for t in ("linux-x64", "macos-arm64", "windows-x64") if t != TARGET)
            self.assertEqual(self.run_usage("--binary", str(FAKE), "--target", other, "--phases", "idle", "--out", str(out)).returncode, 2)
            self.assertEqual(self.run_usage(*self.base(out)[:-4], "--phases", "idle,busy", "--out", str(out)).returncode, 2)
            self.assertEqual(self.run_usage("--binary", str(Path(d) / "missing"), "--target", TARGET, "--phases", "idle", "--out", str(out)).returncode, 2)
            bad = Path(d) / "identity.json"
            bad.write_text(json.dumps(dict(CLAIMED, channel="local")), encoding="utf-8")
            self.assertEqual(self.run_usage(*self.base(out), "--identity", str(bad)).returncode, 2)
            dup = Path(d) / "dup.json"
            dup.write_text('{"version": "a", "version": "b"}', encoding="utf-8")
            self.assertEqual(self.run_usage(*self.base(out), "--identity", str(dup)).returncode, 2)
            self.assertFalse(out.exists())


class PureTests(unittest.TestCase):
    def test_nearest_rank(self):
        self.assertEqual(measure.nearest_rank(list(range(1, 21)), 95), 19)
        self.assertEqual(measure.nearest_rank(list(range(1, 101)), 95), 95)
        self.assertEqual(measure.nearest_rank(list(range(1, 11)), 50), 5)
        self.assertEqual(measure.nearest_rank([7], 95), 7)
        self.assertEqual(measure.nearest_rank([5, 1, 4, 2, 3], 50), 3)

    def test_summary_over_given_samples(self):
        samples = [measure.TimedSample(mono_ns=i * 1_000_000_000, unix_ms=1_000 + i * 1000,
                                       sample=measure.samplers.Sample(
                                           footprint_bytes=(i + 1) * MIB, footprint_metric="pss",
                                           cpu_ns=i * 500_000_000, threads=4 + i % 2, descriptors=10 + i,
                                           descriptor_kind="fd"))
                   for i in range(20)]
        reference = measure.TimedSample(mono_ns=-1_000_000_000, unix_ms=0, sample=samples[0].sample)
        metrics = measure.summarize(samples, reference)
        fp = metrics["footprint_bytes"]
        self.assertEqual(fp["min"], MIB)
        self.assertEqual(fp["max"], 20 * MIB)
        self.assertEqual(fp["p95"], 19 * MIB)
        self.assertEqual(fp["p50"], 10 * MIB)
        self.assertEqual(metrics["threads"], {"min": 4, "max": 5})
        self.assertEqual(metrics["descriptors"], {"kind": "fd", "min": 10, "max": 29})
        # cpu from the reference at -1 s (cpu 0) to the last sample at 19 s (cpu 9.5 s).
        self.assertAlmostEqual(metrics["cpu_core_pct"]["mean"], 100 * 9.5 / 20, places=3)
        self.assertAlmostEqual(metrics["cpu_core_pct"]["max"], 50.0, places=3)

    def test_failed_samples_excluded_from_summary(self):
        ok = measure.TimedSample(mono_ns=1_000_000_000, unix_ms=1, sample=measure.samplers.Sample(
            footprint_bytes=MIB, footprint_metric="pss", cpu_ns=0, threads=1, descriptors=1, descriptor_kind="fd"))
        failed = measure.TimedSample(mono_ns=2_000_000_000, unix_ms=2, sample=None)
        metrics = measure.summarize([ok, failed], ok)
        self.assertEqual(metrics["footprint_bytes"]["max"], MIB)

    def test_self_sample_nearest_external_sample(self):
        def ts(unix_ms, value):
            return measure.TimedSample(mono_ns=unix_ms * 1_000_000, unix_ms=unix_ms, sample=measure.samplers.Sample(
                footprint_bytes=value, footprint_metric="pss", cpu_ns=0, threads=1, descriptors=1, descriptor_kind="fd"))
        samples = [ts(1000, 10 * MIB), ts(2000, 20 * MIB), ts(3000, 30 * MIB)]
        self_sample = {"footprint_bytes": 21 * MIB, "footprint_metric": "pss", "threads": 1, "written_unix_ms": 2100}
        self.assertEqual(measure.self_sample_difference(self_sample, samples), MIB)
        self_sample["written_unix_ms"] = 2900
        self.assertEqual(measure.self_sample_difference(self_sample, samples), -9 * MIB)
        self.assertIsNone(measure.self_sample_difference(None, samples))

    def _phase(self, name, p95):
        p = json.loads(json.dumps(phase(EXAMPLE, name)))
        p["profile"]["sha256"] = sha256(HERE / "profiles" / f"{p['profile']['name']}.json")
        p["metrics"]["footprint_bytes"]["p95"] = p95
        return p

    def _build(self, identity, smoke, reported, p95=9_500_000):
        phases = [self._phase("idle", p95), self._phase("load", 10_000_000)]
        diffs = {"idle": 100_000, "load": 100_000}
        return measure.build_evidence(
            identity=identity, smoke=smoke, target="linux-x64", environment=EXAMPLE["environment"],
            binary=dict(EXAMPLE["binary"], reported_identity=reported), phases=phases, self_diffs=diffs,
            budgets=measure.load_budgets(), started_unix_ms=1, finished_unix_ms=2,
        )

    def test_identity_file_fields_become_identity(self):
        evidence = self._build(CLAIMED, False, CLAIMED)
        Draft202012Validator(EVIDENCE_SCHEMA).validate(evidence)
        self.assertEqual(evidence["identity"], CLAIMED)
        self.assertIs(evidence["smoke"], False)
        self.assertEqual(results(evidence, "identity_mismatch")[0]["outcome"], "pass")
        self.assertEqual(evidence["outcome"], "pass")

    def test_identity_differing_from_binary_fails(self):
        reported = dict(CLAIMED, commit="f" * 40)
        evidence = self._build(CLAIMED, False, reported)
        self.assertEqual(results(evidence, "identity_mismatch")[0]["outcome"], "fail")
        self.assertEqual(evidence["outcome"], "fail")

    def test_zero_footprint_fails_footprint_nonzero(self):
        evidence = self._build(CLAIMED, False, CLAIMED, p95=0)
        self.assertEqual(results(evidence, "footprint_nonzero", "idle")[0]["outcome"], "fail")
        self.assertEqual(evidence["outcome"], "fail")

    def test_smoke_decision(self):
        self.assertTrue(measure.is_smoke(identity=None, scale=1.0, stand_in=False))
        self.assertTrue(measure.is_smoke(identity=CLAIMED, scale=0.5, stand_in=False))
        self.assertTrue(measure.is_smoke(identity=CLAIMED, scale=1.0, stand_in=True))
        self.assertFalse(measure.is_smoke(identity=CLAIMED, scale=1.0, stand_in=False))


class ProfileTests(unittest.TestCase):
    def test_profiles_validate_against_agent_config_schema(self):
        validator = Draft202012Validator(CONFIG_SCHEMA)
        for name in ("idle", "health-burst"):
            doc = json.loads((HERE / "profiles" / f"{name}.json").read_text(encoding="utf-8"))
            validator.validate(doc)
            self.assertIn("timeout_ms", doc["shutdown"])
            self.assertNotIn("paths", doc)

    def test_profile_values_match_spec_table(self):
        idle = json.loads((HERE / "profiles/idle.json").read_text(encoding="utf-8"))
        burst = json.loads((HERE / "profiles/health-burst.json").read_text(encoding="utf-8"))
        self.assertEqual((idle["health"]["interval_ms"], idle["log"]["level"]), (60000, "info"))
        self.assertEqual((burst["health"]["interval_ms"], burst["log"]["level"], burst["log"]["max_file_bytes"]),
                         (100, "debug", 65536))


if __name__ == "__main__":
    unittest.main()
