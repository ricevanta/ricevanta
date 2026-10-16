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
from unittest import mock

from jsonschema import Draft202012Validator

import measure
from windows_io import replace

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
        self.assertEqual(self.evidence['outcome'], 'pass', self.evidence['results'])

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
        self.assertGreaterEqual(idle["duration_ms"], 6000)
        self.assertLess(idle["duration_ms"], 7000)
        self.assertGreaterEqual(load["duration_ms"], 3000)
        self.assertLess(load["duration_ms"], 4000)
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


class VersionOutputTests(unittest.TestCase):
    def identity(self, script, timeout=5):
        children = []
        popen = subprocess.Popen

        def start(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        try:
            with mock.patch.object(measure.subprocess, 'Popen', side_effect=start), \
                    mock.patch.object(measure, 'VERSION_TIMEOUT_S', timeout):
                return measure.reported_identity([sys.executable, '-B', '-c', script],
                                                 measure.check.load_evidence_validator())
        finally:
            for child in children:
                self.assertIsNotNone(child.returncode, 'version child was not reaped')
                self.assertTrue(child.stdout.closed)
                self.assertTrue(child.stderr.closed)

    def test_version_overflow_stops_each_stream_before_child_can_finish_output(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / 'finished'
                script = (f'import sys; from pathlib import Path; '
                          f'sys.{stream}.buffer.write(b"x" * 10485760); sys.{stream}.flush(); '
                          f'Path({str(marker)!r}).write_text("finished"); '
                          f'print({json.dumps(CLAIMED)!r})')
                with self.assertRaisesRegex(measure.MeasureFailure, 'version_failed:'):
                    self.identity(script)
                self.assertFalse(marker.exists(), 'overflow was read to completion before rejection')

    def test_version_accepts_exact_stdout_limit_and_drains_exact_stderr_limit(self):
        script = (f'import sys; sys.stderr.buffer.write(b"x" * 65536); sys.stderr.flush(); '
                  f'sys.stdout.buffer.write({json.dumps(CLAIMED)!r}.encode().ljust(65536, b" "))')
        self.assertEqual(self.identity(script), CLAIMED)

    def test_version_rejects_one_byte_above_each_stream_limit(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream):
                script = (f'import sys; sys.{stream}.buffer.write('
                          f'{json.dumps(CLAIMED)!r}.encode().ljust(65537, b" "))')
                with self.assertRaisesRegex(measure.MeasureFailure, 'version_failed:.*' + stream):
                    self.identity(script)

    def test_version_timeout_reaps_child_without_waiting_for_eof(self):
        started = time.monotonic()
        with self.assertRaisesRegex(measure.MeasureFailure, 'version_failed:.*timed out'):
            self.identity('import time; time.sleep(60)', timeout=0.3)
        self.assertLess(time.monotonic() - started, 5)

    def test_version_timeout_after_both_pipes_close_still_reaps_child(self):
        started = time.monotonic()
        with self.assertRaisesRegex(measure.MeasureFailure, 'version_failed:.*timed out'):
            self.identity('import os, time; os.close(1); os.close(2); time.sleep(60)', timeout=0.3)
        self.assertLess(time.monotonic() - started, 5)

    def test_version_nonzero_exit_does_not_expose_stderr(self):
        with self.assertRaisesRegex(measure.MeasureFailure, 'version_failed: exit 7') as error:
            self.identity('import sys; print("private diagnostic", file=sys.stderr); sys.exit(7)')
        self.assertNotIn('private diagnostic', str(error.exception))


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
        self_sample = {"footprint_bytes": 21 * MIB, "footprint_metric": "pss", "threads": 1, "written_unix_ms": 3100, "sampled_unix_ms": 2100}
        self.assertEqual(measure.self_sample_difference(self_sample, samples), MIB)
        self_sample["sampled_unix_ms"] = 2900
        self.assertEqual(measure.self_sample_difference(self_sample, samples), -9 * MIB)
        self.assertIsNone(measure.self_sample_difference(None, samples))

    def _phase(self, name, p95):
        p = json.loads(json.dumps(phase(EXAMPLE, name)))
        p["profile"]["sha256"] = sha256(HERE / "profiles" / f"{p['profile']['name']}.json")
        p["metrics"]["footprint_bytes"]["p95"] = p95
        return p

    def _build(self, identity, smoke, reported, p95=9_500_000):
        phases = [self._phase("idle", p95), self._phase("load", 10_000_000)]
        return measure.build_evidence(
            identity=identity, smoke=smoke, target="linux-x64", environment=EXAMPLE["environment"],
            binary=dict(EXAMPLE["binary"], reported_identity=reported), phases=phases,
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

class WorkloadMeasurementTests(unittest.TestCase):
    def test_pair_uses_sample_time_and_earlier_tie(self):
        samples = [measure.TimedSample(i * 1000000, i, measure.samplers.Sample(
            i, 'pss', 0, 1, 1, 'fd')) for i in (1000, 2000, 3000)]
        own = {'sampled_unix_ms': 1500, 'written_unix_ms': 3000, 'footprint_bytes': 1001}
        self.assertEqual(measure.self_sample_difference(own, samples), 1)

    def test_progress_accumulates_intervening_failures(self):
        from test_check import make_evidence, phase
        p = phase(make_evidence(), 'load')
        start = p['health_progress']['start']
        end = p['health_progress']['end']
        tracker = measure.HealthProgress(4242, 100)
        tracker.observe_snapshot(start)
        bad = dict(start, observed_elapsed_ms=3000, observed_unix_ms=start['observed_unix_ms'] + 3000)
        tracker.observe_snapshot(bad)
        tracker.observe_snapshot(end)
        self.assertGreaterEqual(tracker.summary['max_sample_age_ms'], 3000)
        self.assertGreaterEqual(tracker.summary['max_observation_gap_ms'], 3000)

    def test_fake_failure_modes(self):
        cases = [('one-sample', 'sampler_progress'), ('frozen-sample', 'sampler_progress'),
                 ('frozen-counter', 'sampler_progress'), ('frozen-timestamps', 'sampler_progress'), ('old-samples', 'health_freshness'),
                 ('wrong-pid', 'health_freshness'), ('wrong-interval', 'health_freshness'),
                 ('null-process', 'health_freshness'), ('counter-reset', 'sampler_progress'),
                 ('catch-up', 'sampler_progress')]
        for mode, token in cases:
            with self.subTest(mode=mode):
                proc, out, _, _ = run_measure(self.addCleanup, mode=mode, phases='load', scale='0.02')
                self.assertEqual(proc.returncode, 0, proc.stderr)
                ev = json.loads(out.read_text())
                self.assertEqual(results(ev, token, 'load')[0]['outcome'], 'fail')

class ObserverTests(unittest.TestCase):
    def snapshots(self):
        from test_check import make_evidence, phase
        return phase(make_evidence(), 'load')['health_progress']

    def test_invalid_reads_are_not_reused(self):
        g = self.snapshots()
        tracker = measure.HealthProgress(g['pid'], 100)
        tracker.observe_snapshot(g['start'])
        tracker.observe(None, g['start']['observed_unix_ms'] + 1000, 1000)
        self.assertIsNone(tracker.summary['end'])
        self.assertEqual(tracker.summary['invalid_observations'], 1)
        tracker.observe_snapshot(g['end'])
        self.assertEqual(tracker.summary['observations'], 3)
        self.assertEqual(tracker.summary['invalid_observations'], 1)

    def test_reversal_ordering_and_counter_reset(self):
        for change in (dict(observed_unix_ms=1), dict(sampled_unix_ms=9999999999999),
                       dict(sampled_uptime_ms=999999), dict(samples=0),
                       dict(sampled_unix_ms=1760000150000, sampled_uptime_ms=10000)):
            g = self.snapshots()
            tracker = measure.HealthProgress(g['pid'], 100)
            tracker.observe_snapshot(g['start'])
            tracker.observe_snapshot(dict(g['end'], **change))
            self.assertTrue(tracker.summary['invalid_observations'] or tracker.summary['counter_regressions'])

    def test_log_deduplication_filter_and_marker_position(self):
        g = self.snapshots()
        profile = json.loads((HERE / 'profiles/health-burst.json').read_text())
        event = dict(ts='2026-01-01T00:00:00.000Z', level='debug', event='sample_completed', pid=g['pid'],
                     sample=102, sampled_uptime_ms=10100, footprint_bytes=1, cpu_user_ms=0,
                     cpu_system_ms=0, threads=1, descriptor_count=1, descriptor_kind='fd', footprint_metric='pss')
        marker = dict(ts=event['ts'], level='info', event='log_rotated', pid=g['pid'], rotation=1)
        encode = lambda x: json.dumps(x).encode() + b'\n'
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'agent.log'
            path.write_bytes(encode(marker) + encode(event) * 3 + b'{partial')
            observer = measure.LogActivity(profile, 60000, g['pid'])
            observer.read(Path(d))
            observer.read(Path(d))
            self.assertEqual(observer.finish(g), dict(sample_events=1, rotations_observed=1, invalid_lines=0))
            # A retained warm-up event and rotation cannot count in the phase.
            path.write_bytes(encode(dict(marker, rotation=0)) + encode(dict(event, sample=100, sampled_uptime_ms=9999)))
            observer.read(Path(d))
            self.assertEqual(observer.finish(g)['sample_events'], 1)
            path.write_bytes(encode(event) + encode(dict(marker, rotation=2)))
            observer.read(Path(d))
            self.assertGreater(observer.finish(g)['invalid_lines'], 0)

    @unittest.skipUnless(sys.platform == 'win32', 'native Windows delete-sharing and atomic replacement')
    def test_windows_readers_allow_atomic_replacement_and_rotation(self):
        import ctypes
        import threading
        errors = []
        with tempfile.TemporaryDirectory() as d:
            held, source = Path(d) / 'held-target', Path(d) / 'held-source'
            old, new = b'old-target\n', b'new-target\n'
            held.write_bytes(old)
            source.write_bytes(new)
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
            kernel.CreateFileW.restype = ctypes.c_void_p
            kernel.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
            kernel.ReadFile.restype = ctypes.c_int32
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel.CloseHandle.restype = ctypes.c_int32
            handle = kernel.CreateFileW(str(held), 0x80000000, 7, None, 3, 0, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                replace(source, held)
                buffer, count = ctypes.create_string_buffer(len(old)), ctypes.c_uint32()
                if not kernel.ReadFile(handle, buffer, len(old), ctypes.byref(count), None):
                    raise ctypes.WinError(ctypes.get_last_error())
                self.assertEqual(buffer.raw[:count.value], old)
                self.assertEqual(measure.read_shared(held, 65536), new)
                self.assertFalse(source.exists())
            finally:
                if not kernel.CloseHandle(handle):
                    raise ctypes.WinError(ctypes.get_last_error())
            path = Path(d) / 'agent.log'
            path.write_bytes(b'initial\n')
            def writer():
                try:
                    for i in range(500):
                        tmp = Path(d) / 'next'
                        tmp.write_bytes(str(i).encode() + b'\n')
                        replace(tmp, path)
                        replace(path, Path(d) / 'rotation')
                        path.write_bytes(b'active\n')
                except OSError as exc:
                    errors.append(exc)
            thread = threading.Thread(target=writer)
            thread.start()
            while thread.is_alive():
                for name in ('agent.log', 'rotation'):
                    try:
                        measure.read_shared(Path(d) / name, 65536)
                    except FileNotFoundError:
                        pass
            thread.join()
            self.assertEqual(errors, [])

class FailedSampleTests(unittest.TestCase):
    def test_all_failed_external_samples_keep_failure_evidence(self):
        t = measure.TimedSample(1, 1, None)
        metrics = measure.summarize([t], None, metric='pss', descriptor_kind='fd')
        self.assertEqual(metrics['footprint_bytes']['p95'], 0)

    def test_shutdown_does_not_replace_endpoint(self):
        proc, out, _, records = run_measure(self.addCleanup, phases='load', scale='0.02')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        ev = json.loads(out.read_text())
        p = phase(ev, 'load')
        self.assertEqual(p['health_progress']['end']['state'], 'ready')
        self.assertEqual(p['self_sample']['sampled_unix_ms'], p['health_progress']['end']['sampled_unix_ms'])
        rec = json.loads(next(records.iterdir()).read_text())
        self.assertEqual(rec['last_health']['state'], 'stopped')

    def test_debug_modes_have_observable_semantic_failures(self):
        import check
        from test_check import make_evidence, phase as fixture_phase
        for mode in ('debug-disabled', 'repeated-lines', 'warmup-rotations'):
            with self.subTest(mode=mode):
                proc, out, _, _ = run_measure(self.addCleanup, mode=mode, phases='load', scale='0.02')
                self.assertEqual(proc.returncode, 0, proc.stderr)
                measured = phase(json.loads(out.read_text()), 'load')
                # Judge the observed log counts against a full-window fixture.
                ev = make_evidence()
                fixture_phase(ev, 'load')['log_activity'] = measured['log_activity']
                rows = check.workload_rows(ev, fixture_phase(ev, 'load'))
                self.assertEqual(next(r for r in rows if r['check'] == 'load_log_activity')['outcome'], 'fail')
                if mode == 'debug-disabled':
                    self.assertEqual(measured['log_activity']['sample_events'], 0)
                if mode == 'repeated-lines':
                    self.assertLessEqual(measured['log_activity']['sample_events'], 1)
                if mode == 'warmup-rotations':
                    self.assertEqual(measured['log_activity']['rotations_observed'], 0)

class TimingAndStopTests(unittest.TestCase):
    def test_fractional_scale_retains_entire_window(self):
        proc, out, _, _ = run_measure(self.addCleanup, phases='load', scale='0.02')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertGreaterEqual(phase(json.loads(out.read_text()), 'load')['duration_ms'], 1200)

    def test_windows_stop_targets_child_group(self):
        import ctypes
        from unittest import mock
        calls = []
        class Fn:
            def __call__(self, event, group):
                calls.append((event, group))
                return 1
        class Kernel:
            GenerateConsoleCtrlEvent = Fn()
        with mock.patch.object(measure.sys, 'platform', 'win32'), mock.patch.object(
                ctypes, 'WinDLL', return_value=Kernel(), create=True):
            measure._send_stop(type('Child', (), {'pid': 4242})())
        self.assertEqual(calls, [(1, 4242)])

def _check_writer_contract(test):
    """Injected APIs and metadata only; native replacement is proved separately."""
    import ctypes
    import importlib.util
    import ntpath
    import stat
    from types import SimpleNamespace
    with mock.patch.object(ctypes, 'WinDLL', side_effect=AssertionError('eager DLL load'), create=True):
        spec = importlib.util.spec_from_file_location('fixture_windows_io_lazy', HERE / 'windows_io.py')
        fresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fresh)
        io = importlib.import_module('windows_io')

    source, destination = r'C:\fixture\source', r'C:\fixture\target'
    parent = ntpath.normcase(ntpath.dirname(source))
    def metadata(path):
        mode = stat.S_IFDIR if ntpath.normcase(path) == parent else stat.S_IFREG
        return SimpleNamespace(st_mode=mode, st_file_attributes=0)

    class Function:
        def __init__(self, owner, name): self.owner, self.name = owner, name
        def __call__(self, *args):
            owner = self.owner
            owner.calls.append((self.name, args))
            if self.name == 'rename':
                owner.buffer = ctypes.string_at(args[2], args[3])
                test.assertEqual(ctypes.cast(args[2], ctypes.c_void_p).value % 8, 0)
            value = owner.results[self.name]
            if isinstance(value, BaseException): raise value
            if not value or value in (-1, io.INVALID_HANDLE_VALUE):
                owner.code = owner.codes[self.name]
            return value

    class Kernel:
        def __init__(self, **results):
            self.calls, self.code, self.buffer = [], 0, None
            self.results = dict(open=73, rename=1, close=1) | results
            self.codes = dict(open=5, rename=87, close=6)
            self.CreateFileW = Function(self, 'open')
            self.SetFileInformationByHandle = Function(self, 'rename')
            self.CloseHandle = Function(self, 'close')
        def last_error(self): self.calls.append(('error', ())); return self.code
        def error(self, code):
            error = OSError(13, f'injected Windows error {code}')
            error.winerror = code
            return error
        def api(self): return io._WindowsAPI(self, self.last_error, self.error)

    def replace(kernel, src=source, dst=destination, stat_call=metadata):
        with mock.patch.object(io.os, 'lstat', side_effect=stat_call), mock.patch.object(
                io.os, 'replace', side_effect=AssertionError('legacy replacement')), mock.patch.object(
                io.os, 'unlink', side_effect=AssertionError('unlink fallback')), mock.patch.object(
                io.os, 'chmod', side_effect=AssertionError('attribute repair')):
            io._replace_windows(src, dst, api=kernel.api())

    for name in ('target', 'caf\u00e9', 'pair-\U0001f642'):
        with test.subTest(writer='buffer', name=name):
            dst = ntpath.join(r'C:\fixture', name)
            kernel = Kernel()
            replace(kernel, dst=dst)
            test.assertEqual([name for name, _ in kernel.calls], ['open', 'rename', 'close'])
            test.assertEqual(kernel.calls[0][1], (source, 0x10000, 7, None, 3, 0x200000, None))
            test.assertEqual(kernel.calls[1][1][:2], (73, 22))
            test.assertEqual(kernel.calls[2][1], (73,))
            encoded, raw = dst.encode('utf-16-le'), kernel.buffer
            test.assertEqual(int.from_bytes(raw[:4], 'little'), 3)
            test.assertEqual(raw[4:16], bytes(12))
            test.assertEqual(int.from_bytes(raw[16:20], 'little'), len(encoded))
            test.assertEqual(raw[20:20 + len(encoded)], encoded)
            test.assertEqual(raw[20 + len(encoded):], bytes(len(raw) - 20 - len(encoded)))
            test.assertEqual(len(raw), (20 + len(encoded) + 2 + 7) // 8 * 8)
            test.assertEqual(kernel.CreateFileW.restype, ctypes.c_void_p)
            test.assertEqual(kernel.CreateFileW.argtypes, [ctypes.c_wchar_p, ctypes.c_uint32,
                ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p])
            test.assertEqual(kernel.SetFileInformationByHandle.argtypes,
                             [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32])
            test.assertEqual(kernel.SetFileInformationByHandle.restype, ctypes.c_int32)
            test.assertEqual(kernel.CloseHandle.argtypes, [ctypes.c_void_p])
            test.assertEqual(kernel.CloseHandle.restype, ctypes.c_int32)

    test.assertEqual(io.MAX_NAME_UNITS, 32766)
    test.assertEqual(io.MAX_BUFFER_BYTES, 65560)
    test.assertEqual((io._RenameInfo.Flags.offset, io._RenameInfo.RootDirectory.offset,
        io._RenameInfo.FileNameLength.offset, io._RenameInfo.FileName.offset,
        ctypes.alignment(io._RenameInfo), ctypes.sizeof(io._RenameInfo)), (0, 8, 16, 20, 8, 24))
    for path, bound in ((r'C:\a', 4), ('C:\\' + 'a' * (32766 - 3), 32766)):
        with test.subTest(writer='allocation', bound=bound):
            storage = io._rename_buffer(path, max_units=bound)
            test.assertEqual(ctypes.addressof(storage) % 8, 0)
            test.assertEqual(ctypes.sizeof(storage), (20 + len(path.encode('utf-16-le')) + 2 + 7) // 8 * 8)
    test.assertEqual(ctypes.sizeof(io._rename_buffer('C:\\' + 'a' * 32763)), 65560)
    for path, bound in ((r'C:\ab', 4), ('C:\\' + 'a' * 32764, 32766), (r'C:\a', 2**32),
                        (r'C:\a', True), ('C:\\bad\ud800', 32766)):
        with test.subTest(writer='bounded refusal', bound=bound, path=path[:20]):
            with test.assertRaises(ValueError): io._rename_buffer(path, max_units=bound)

    paths = [('', destination), (source, ''), ('relative', destination), (r'C:relative', destination),
             (source, source.upper()), (source, r'C:\other\target'), ('C:\\bad\x00', destination),
             (source, 'C:\\fixture\\bad\ud800'), (source, r'C:\fixture\target:stream'),
             (source, r'\\server\share\target'), (source, r'\\?\C:\fixture\target'),
             (source, r'\\.\C:\fixture\target'), (source, r'C:\fixture\CON'),
             (source, 'C:\\fixture\\target\\'), (b'not-text', destination)]
    for src, dst in paths:
        with test.subTest(writer='path refusal', source=src, destination=dst):
            kernel = Kernel()
            with test.assertRaises((TypeError, ValueError)): replace(kernel, src, dst)
            test.assertEqual(kernel.calls, [])
    for bad_path, mode, attributes in ((source, stat.S_IFDIR, 0), (destination, stat.S_IFDIR, 0),
            (source, stat.S_IFLNK, 0), (destination, stat.S_IFREG, 0x400),
            (r'C:\fixture', stat.S_IFDIR, 0x400)):
        with test.subTest(writer='file type refusal', path=bad_path, mode=mode, attributes=attributes):
            def bad_metadata(path):
                return (SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                        if ntpath.normcase(path) == ntpath.normcase(bad_path) else metadata(path))
            kernel = Kernel()
            with test.assertRaises(ValueError): replace(kernel, stat_call=bad_metadata)
            test.assertEqual(kernel.calls, [])
    def missing_destination(path):
        if path == destination: raise FileNotFoundError(path)
        return metadata(path)
    kernel = Kernel()
    replace(kernel, stat_call=missing_destination)
    test.assertEqual([name for name, _ in kernel.calls], ['open', 'rename', 'close'])

    with mock.patch.object(ctypes, 'alignment', return_value=4):
        kernel = Kernel()
        with test.assertRaises(ValueError): replace(kernel)
        test.assertEqual(kernel.calls, [])
    with mock.patch.object(ctypes, 'sizeof', return_value=4):
        kernel = Kernel()
        with test.assertRaises(ValueError): replace(kernel)
        test.assertEqual(kernel.calls, [])
    class PackedRename(ctypes.Structure):
        _layout_ = 'ms'
        _pack_ = 1
        _anonymous_ = ('control',)
        _fields_ = io._RenameInfo._fields_
    with mock.patch.object(io, '_RenameInfo', PackedRename):
        kernel = Kernel()
        with test.assertRaises(ValueError): replace(kernel)
        test.assertEqual(kernel.calls, [])
    class MissingBinding(Kernel):
        def __getattribute__(self, name):
            if name == 'SetFileInformationByHandle': raise AttributeError('missing rename binding')
            return super().__getattribute__(name)
    kernel = MissingBinding()
    with test.assertRaises(AttributeError): replace(kernel)
    test.assertEqual(kernel.calls, [])

    for stage, value, code in (('open', io.INVALID_HANDLE_VALUE, 5), ('open', -1, 5), ('open', None, 5), ('open', 0, 5), ('rename', 0, 87),
            ('rename', 0, 50), ('rename', 0, 32), ('rename', 0, 5), ('close', 0, 6),
            ('open', RuntimeError('open binding'), None), ('rename', RuntimeError('rename binding'), None),
            ('close', RuntimeError('close binding'), None)):
        with test.subTest(writer='API failure', stage=stage, code=code):
            kernel = Kernel(**{stage: value})
            if code is not None: kernel.codes[stage] = code
            with test.assertRaises(OSError if code is not None else RuntimeError) as caught:
                replace(kernel)
            if code is not None: test.assertEqual(caught.exception.winerror, code)
            else: test.assertIs(caught.exception, value)
            calls = [name for name, _ in kernel.calls]
            expected = ['open'] if stage == 'open' else ['open', 'rename', 'close']
            if code is not None: expected.insert(expected.index(stage) + 1, 'error')
            test.assertEqual(calls, expected)
    for rename, close in ((0, 0), (RuntimeError('primary binding'), 0), (0, RuntimeError('secondary binding'))):
        with test.subTest(writer='primary error preserved', rename=rename, close=close):
            kernel = Kernel(rename=rename, close=close)
            with test.assertRaises(OSError if rename == 0 else RuntimeError) as caught: replace(kernel)
            if rename == 0: test.assertEqual(caught.exception.winerror, 87)
            else: test.assertIs(caught.exception, rename)
            if close == 0: test.assertEqual(caught.exception.close_error.winerror, 6)
            else: test.assertIs(caught.exception.close_error, close)
            test.assertTrue(caught.exception.__notes__)
            test.assertEqual([name for name, _ in kernel.calls],
                             ['open', 'rename'] + (['error'] if rename == 0 else []) + ['close']
                             + (['error'] if close == 0 else []))
    with mock.patch.object(io.sys, 'platform', 'linux'), mock.patch.object(
            io, '_load_api', side_effect=AssertionError('non-Windows DLL load')):
        src, dst = Path('unchanged-source'), Path('unchanged-target')
        with mock.patch.object(io.os, 'replace') as native:
            io.replace(src, dst)
            native.assert_called_once_with(src, dst)
        error = OSError('non-Windows replacement')
        with mock.patch.object(io.os, 'replace', side_effect=error) as native:
            with test.assertRaises(OSError) as caught: io.replace(src, dst)
            test.assertIs(caught.exception, error)
            native.assert_called_once_with(src, dst)


class CollectedWorkloadTests(unittest.TestCase):
    def test_healthy_full_workload_from_polled_logs(self):
        _check_writer_contract(self)
        import copy
        import check
        from test_check import make_evidence, phase as fixture_phase
        ev = make_evidence()
        p = fixture_phase(ev, 'load')
        profile = json.loads((HERE / 'profiles/health-burst.json').read_text())
        a, b = p['health_progress']['start'], p['health_progress']['end']
        progress = measure.HealthProgress(a['pid'], 100)
        logs = measure.LogActivity(profile, 60000, a['pid'])
        progress.observe_snapshot(a)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'agent.log'
            path.write_bytes(b'')
            for index in range(1, 601):
                rotation = (index - 1) // 200
                if index in (201, 401):
                    replace(path, Path(str(path) + f'.{rotation}'))
                    path.write_text(json.dumps(dict(ts='2026-01-01T00:00:00.000Z', level='info',
                                                   event='log_rotated', pid=a['pid'], rotation=rotation)) + '\n')
                event = dict(ts='2026-01-01T00:00:00.000Z', level='debug', event='sample_completed',
                             pid=a['pid'], sample=a['samples'] + index, sampled_uptime_ms=10000 + index * 100,
                             footprint_bytes=9900000, footprint_metric='pss', threads=7,
                             cpu_user_ms=0, cpu_system_ms=0, descriptor_count=16, descriptor_kind='fd')
                with path.open('a') as stream:
                    stream.write(json.dumps(event, separators=(',', ':')) + '\n')
                if index % 10 == 0:
                    s = copy.deepcopy(b)
                    elapsed = index * 100
                    s.update(observed_unix_ms=a['observed_unix_ms'] + elapsed,
                             observed_elapsed_ms=elapsed, written_unix_ms=a['written_unix_ms'] + elapsed,
                             uptime_ms=10000 + elapsed, sampled_unix_ms=a['sampled_unix_ms'] + elapsed,
                             sampled_uptime_ms=10000 + elapsed, samples=a['samples'] + index,
                             log_rotations=rotation)
                    progress.observe_snapshot(s)
                    logs.read(Path(directory))
            progress.observe_snapshot(b)
            p['health_progress'] = progress.summary
            p['log_activity'] = logs.finish(progress.summary)
        self.assertEqual(p['log_activity'], dict(sample_events=600, rotations_observed=2, invalid_lines=0))
        self.assertTrue(all(r['outcome'] == 'pass' for r in check.workload_rows(ev, p)))


if __name__ == "__main__":
    unittest.main()
