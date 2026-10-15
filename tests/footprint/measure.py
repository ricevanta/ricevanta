"""Footprint measurement (docs/specs/footprint-harness.md sections 2, 3 and 5).

measure.py --binary PATH --target T --phases idle,load [--identity PATH]
           [--duration-scale F] --out PATH

Starts the agent in run mode once per phase with a disposable configuration,
samples it externally once per second after the warm-up, reads the agent's own
health document for the cross-check and writes one evidence document. A
binary path ending in .py is a test stand-in run with the base interpreter; its
evidence is always a smoke record. Exit 0 after writing evidence, 1 on
not_ready or a preflight failure, 2 on usage error.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import check  # noqa: E402
import samplers  # noqa: E402

PROFILES_DIR = HERE / "profiles"
BUDGETS_PATH = HERE / "budgets.json"

# Phase name -> (profile, full duration in ms), spec section 3.
PHASES = {"idle": ("idle", 120_000), "load": ("health-burst", 60_000)}
WARMUP_MS = 10_000
SAMPLE_INTERVAL_MS = 1_000
READY_TIMEOUT_MS = 30_000
STOP_GRACE_MS = 5_000
VERSION_TIMEOUT_S = 30
HEALTH_POLL_S = 0.05
MAX_HEALTH_BYTES = 65_536
MAX_IDENTITY_BYTES = 65_536
MAX_BINARY_BYTES = 1 << 30

# Target -> (RUNNER_OS, RUNNER_ARCH, sys.platform), spec section 2.
TARGETS = {
    "linux-x64": ("Linux", "X64", "linux"),
    "macos-arm64": ("macOS", "ARM64", "darwin"),
    "windows-x64": ("Windows", "X64", "win32"),
}
HOST_OS = {"linux": "Linux", "darwin": "macOS", "win32": "Windows"}
ARCHES = {"x86_64": "X64", "amd64": "X64", "arm64": "ARM64", "aarch64": "ARM64"}
LABEL_PATTERN = re.compile(r"[a-z0-9.-]{1,64}")


class UsageError(Exception):
    """Exit 2."""


class MeasureFailure(Exception):
    """not_ready, preflight or another failure before evidence exists: exit 1."""


@dataclass(frozen=True)
class TimedSample:
    mono_ns: int
    unix_ms: int
    sample: object  # samplers.Sample, or None for a failed sample


def unix_ms():
    return time.time_ns() // 1_000_000


# ------------------------------------------------------------- summaries


def nearest_rank(values, pct):
    ordered = sorted(values)
    rank = max(1, -(-pct * len(ordered) // 100))
    return ordered[rank - 1]


def summarize(samples, reference):
    """Summaries over the given post-warm-up samples; failed samples are skipped.

    CPU is 100 x delta(cpu time) / delta(wall time) from the reference taken at
    the end of the warm-up to the last sample, so one busy core is 100.
    """
    ok = [t for t in samples if t.sample is not None]
    if not ok:
        raise MeasureFailure("no_samples")
    fp = [t.sample.footprint_bytes for t in ok]
    points = sorted(([reference] if reference is not None and reference.sample is not None else []) + ok,
                    key=lambda t: t.mono_ns)
    rates = []
    for a, b in zip(points, points[1:]):
        if b.mono_ns > a.mono_ns:
            rates.append(max(0.0, 100.0 * (b.sample.cpu_ns - a.sample.cpu_ns) / (b.mono_ns - a.mono_ns)))
    if len(points) >= 2 and points[-1].mono_ns > points[0].mono_ns:
        mean_cpu = max(0.0, 100.0 * (points[-1].sample.cpu_ns - points[0].sample.cpu_ns)
                       / (points[-1].mono_ns - points[0].mono_ns))
    else:
        mean_cpu = 0.0
    return {
        "footprint_bytes": {
            "metric": ok[0].sample.footprint_metric,
            "min": min(fp),
            "max": max(fp),
            "mean": round(sum(fp) / len(fp), 1),
            "p50": nearest_rank(fp, 50),
            "p95": nearest_rank(fp, 95),
        },
        "cpu_core_pct": {"mean": round(mean_cpu, 3), "max": round(max(rates, default=0.0), 3)},
        "threads": {"min": min(t.sample.threads for t in ok), "max": max(t.sample.threads for t in ok)},
        "descriptors": {
            "kind": ok[0].sample.descriptor_kind,
            "min": min(t.sample.descriptors for t in ok),
            "max": max(t.sample.descriptors for t in ok),
        },
    }


def self_sample_difference(self_sample, samples):
    """Signed difference between the agent's self sample and the external sample nearest in time."""
    ok = [t for t in samples if t.sample is not None]
    if self_sample is None or not ok:
        return None
    nearest = min(ok, key=lambda t: (abs(t.unix_ms - self_sample["written_unix_ms"]), t.unix_ms))
    return self_sample["footprint_bytes"] - nearest.sample.footprint_bytes


def is_smoke(identity, scale, stand_in):
    return identity is None or scale < 1 or stand_in


def load_budgets(path=BUDGETS_PATH):
    return check.load_budgets(path)


def build_evidence(*, identity, smoke, target, environment, binary, phases, self_diffs, budgets,
                   started_unix_ms, finished_unix_ms):
    """Assemble the evidence document and judge the absolute checks; check.py later adds the baseline."""
    doc = {
        "schema": "ricevanta-footprint-evidence-v1",
        "identity": None if smoke else identity,
        "smoke": bool(smoke),
        "target": target,
        "environment": environment,
        "binary": binary,
        "processes": [{"name": binary["name"], "role": "core"}],
        "phases": phases,
        "budgets": budgets,
        # The self-sample row carries the signed difference to the nearest external
        # sample; check.py re-judges it with the budget tolerance.
        "results": [check._row("self_sample_agreement", p["name"], self_diffs.get(p["name"]), None, None, "recorded")
                    for p in phases],
        "baseline": {"kind": "none", "identity": None, "environment_match": None},
        "outcome": "fail",
        "started_unix_ms": started_unix_ms,
        "finished_unix_ms": finished_unix_ms,
    }
    limits = check.load_shutdown_limits(phases)
    return check.complete(doc, budgets, limits)


# ------------------------------------------------------------ environment


def environment_record(target, sampler_mod):
    want_os, want_arch, want_platform = TARGETS[target]
    host_os = HOST_OS.get(sys.platform)
    host_arch = ARCHES.get(platform.machine().lower())
    if sys.platform != want_platform or host_arch != want_arch:
        raise UsageError(f"target {target} does not match this host ({host_os} {host_arch})")
    for var, value in (("RUNNER_OS", want_os), ("RUNNER_ARCH", want_arch)):
        given = os.environ.get(var)
        if given is not None and given != value:
            raise UsageError(f"{var}={given} does not match target {target}")
    label = os.environ.get("RICEVANTA_RUNNER_LABEL")
    if label is None:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            raise UsageError("RICEVANTA_RUNNER_LABEL must name the runner label from the workflow matrix")
        label = "local"
    if not LABEL_PATTERN.fullmatch(label):
        raise UsageError("RICEVANTA_RUNNER_LABEL is not a runner label")
    try:
        native = sampler_mod.environment()
    except samplers.SamplerError as exc:
        raise MeasureFailure(f"preflight_failed environment: {exc}") from exc
    env = {
        "runner_os": want_os,
        "runner_arch": want_arch,
        "os_version": native["os_version"],
        "runner_label": label,
        "cpu_count": native["cpu_count"],
        "memory_bytes": native["memory_bytes"],
        "python_version": platform.python_version(),
        "clk_tck": native["clk_tck"],
        "os_release": native["os_release"],
    }
    if "mach_timebase" in native:
        env["mach_timebase"] = native["mach_timebase"]
    run_id, attempt = os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT")
    if run_id is not None:
        if not run_id.isdigit():
            raise UsageError("GITHUB_RUN_ID is not a number")
        env["run_id"] = int(run_id)
    if attempt is not None:
        if not attempt.isdigit() or not 1 <= int(attempt) <= 1000:
            raise UsageError("GITHUB_RUN_ATTEMPT is not a run attempt")
        env["run_attempt"] = int(attempt)
    return env


# ----------------------------------------------------------------- binary


def base_python():
    """The real interpreter, not a virtual-environment redirector that would start a second process."""
    base = getattr(sys, "_base_executable", None)
    return base if base and os.path.isfile(base) else sys.executable


def binary_record(path):
    path = Path(path)
    if not path.is_file():
        raise UsageError(f"--binary {path} is not a file")
    stand_in = path.suffix == ".py"
    expected = "ricevanta-agent.exe" if sys.platform == "win32" else "ricevanta-agent"
    if not stand_in and path.name != expected:
        raise UsageError(f"--binary must be named {expected}")
    size = path.stat().st_size
    if not 1 <= size <= MAX_BINARY_BYTES:
        raise UsageError("--binary size out of range")
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    prefix = [base_python(), "-B", str(path.resolve())] if stand_in else [str(path.resolve())]
    return {"name": expected, "size": size, "sha256": digest.hexdigest()}, prefix, stand_in


def reported_identity(prefix, validator):
    try:
        proc = subprocess.run(prefix + ["version", "--json"], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=VERSION_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MeasureFailure(f"version_failed: {exc}") from exc
    if proc.returncode != 0:
        raise MeasureFailure(f"version_failed: exit {proc.returncode}")
    try:
        doc = check.loads_strict(proc.stdout, MAX_IDENTITY_BYTES)
    except check.InputError as exc:
        raise MeasureFailure(f"version_failed: {exc}") from exc
    errs = validator.errors(doc, "#/$defs/reportedIdentity")
    if errs:
        raise MeasureFailure(f"version_failed: {'; '.join(errs)}")
    return doc


def claimed_identity(path, validator):
    try:
        doc = check.load_json_file(path, MAX_IDENTITY_BYTES)
    except check.InputError as exc:
        raise UsageError(f"--identity: {exc}") from exc
    errs = validator.errors(doc, "#/$defs/identity")
    if errs:
        raise UsageError(f"--identity: {'; '.join(errs)}")
    return doc


# ----------------------------------------------------------------- phases


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.name == "posix":
        os.chmod(path, 0o600)


def _read_health(path):
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_HEALTH_BYTES + 1)
        doc = check.loads_strict(raw, MAX_HEALTH_BYTES)
    except (OSError, check.InputError):
        return None
    return doc if isinstance(doc, dict) else None


def _self_sample(doc, pid):
    if not doc or doc.get("pid") != pid or doc.get("state") != "ready":
        return None
    proc = doc.get("process")
    if not isinstance(proc, dict):
        return None
    fields = {
        "footprint_bytes": proc.get("footprint_bytes"),
        "footprint_metric": proc.get("footprint_metric"),
        "threads": proc.get("threads"),
        "written_unix_ms": doc.get("written_unix_ms"),
    }
    for key in ("footprint_bytes", "threads", "written_unix_ms"):
        if not isinstance(fields[key], int) or isinstance(fields[key], bool) or fields[key] < 0:
            return None
    if fields["footprint_metric"] not in ("phys_footprint", "private_working_set", "pss") or fields["threads"] < 1:
        return None
    return fields


def _exit_code(returncode):
    if returncode < 0:
        return min(128 - returncode, 255)
    return min(returncode, 255)


def _send_stop(proc):
    if sys.platform == "win32":
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.send_signal(signal.SIGTERM)


def _remove_tree(tree):
    for _ in range(25):
        try:
            shutil.rmtree(tree)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.2)
    raise MeasureFailure(f"cleanup_failed: cannot remove the temporary tree")


def _take(sampler, proc):
    """One external sample; never after the child was reaped, so its pid cannot have been reused."""
    now_mono, now_unix = time.monotonic_ns(), unix_ms()
    if sampler is None or proc.poll() is not None:
        return TimedSample(now_mono, now_unix, None)
    try:
        return TimedSample(now_mono, now_unix, sampler.sample())
    except samplers.SamplerError:
        return TimedSample(now_mono, now_unix, None)


def run_phase(name, prefix, scale, sampler_mod):
    profile_name, full_duration = PHASES[name]
    raw = (PROFILES_DIR / f"{profile_name}.json").read_bytes()
    timeout_ms = check.profile_shutdown_timeout(raw, profile_name)
    duration_ms = max(SAMPLE_INTERVAL_MS, round(full_duration * scale))
    warmup_ms = round(WARMUP_MS * scale)
    ready_ms = max(SAMPLE_INTERVAL_MS, round(READY_TIMEOUT_MS * scale))
    count = duration_ms // SAMPLE_INTERVAL_MS

    tree = Path(tempfile.mkdtemp(prefix="rv-footprint-"))
    try:
        config = tree / "agent.json"
        _write_private(config, raw)
        runtime = tree / "run"
        cmd = prefix + ["run", "--config", str(config), "--state-dir", str(tree / "state"),
                        "--runtime-dir", str(runtime), "--log-dir", str(tree / "logs"), "--log", "file"]
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        with open(tree / "agent.stderr", "wb") as stderr:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr, **kwargs)
        sampler = None
        try:
            deadline = time.monotonic() + ready_ms / 1000
            while True:
                if proc.poll() is None:
                    doc = _read_health(runtime / "health.json")
                    if doc and doc.get("pid") == proc.pid and doc.get("state") == "ready":
                        break
                if proc.poll() is not None or time.monotonic() >= deadline:
                    tail = (tree / "agent.stderr").read_bytes()[-2048:].decode("utf-8", "replace")
                    raise MeasureFailure(f"not_ready phase={name}" + (f"\n{tail}" if tail else ""))
                time.sleep(HEALTH_POLL_S)
            try:
                sampler = sampler_mod.Sampler(proc.pid)
            except samplers.SamplerError:
                sampler = None
            time.sleep(warmup_ms / 1000)
            reference = _take(sampler, proc)
            samples = []
            for k in range(1, count + 1):
                target = reference.mono_ns + k * SAMPLE_INTERVAL_MS * 1_000_000
                time.sleep(max(0, target - time.monotonic_ns()) / 1e9)
                samples.append(_take(sampler, proc))
            own = _self_sample(_read_health(runtime / "health.json"), proc.pid)
            metrics = summarize(samples, reference)
            diff = self_sample_difference(own, [reference] + samples)

            stop_started = time.monotonic_ns()
            if proc.poll() is None:
                _send_stop(proc)
            try:
                proc.wait(timeout=(timeout_ms + STOP_GRACE_MS) / 1000)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
            shutdown_ms = (time.monotonic_ns() - stop_started) // 1_000_000
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)
            if sampler is not None:
                sampler.close()
    finally:
        _remove_tree(tree)

    phase = {
        "name": name,
        "profile": {"name": profile_name, "sha256": hashlib.sha256(raw).hexdigest()},
        "warmup_ms": warmup_ms,
        "duration_ms": duration_ms,
        "sample_interval_ms": SAMPLE_INTERVAL_MS,
        "samples": count,
        "failed_samples": sum(1 for t in samples if t.sample is None),
        "shutdown_ms": shutdown_ms,
        "exit_code": _exit_code(proc.returncode),
        "metrics": metrics,
        "self_sample": own,
    }
    return phase, diff


# -------------------------------------------------------------------- CLI


def _scale(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number") from None
    if not math.isfinite(value) or not 0 < value <= 1:
        raise argparse.ArgumentTypeError("must be above 0 and at most 1")
    return value


def _phases(text):
    names = text.split(",")
    if not names or any(n not in PHASES for n in names) or len(set(names)) != len(names):
        raise argparse.ArgumentTypeError(f"phases are a comma list of {', '.join(PHASES)}")
    return names


def _parser():
    parser = argparse.ArgumentParser(description="Measure ricevanta-agent and write footprint evidence.")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--phases", required=True, type=_phases)
    parser.add_argument("--identity")
    parser.add_argument("--duration-scale", type=_scale, default=1.0)
    parser.add_argument("--out", required=True)
    return parser


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        validator = check.load_evidence_validator()
        budgets = check.load_budgets(BUDGETS_PATH, validator)
        sampler_mod = samplers.current()
        environment = environment_record(args.target, sampler_mod)
        binary, prefix, stand_in = binary_record(args.binary)
        identity = claimed_identity(args.identity, validator) if args.identity else None
        try:
            sampler_mod.preflight()
        except samplers.SamplerError as exc:
            raise MeasureFailure(f"preflight_failed: {exc}") from exc
        binary["reported_identity"] = reported_identity(prefix, validator)
        smoke = is_smoke(identity, args.duration_scale, stand_in)

        started = unix_ms()
        phases, diffs = [], {}
        for name in args.phases:
            phase, diff = run_phase(name, prefix, args.duration_scale, sampler_mod)
            phases.append(phase)
            diffs[name] = diff
            print(f"phase={name} samples={phase['samples']} failed={phase['failed_samples']} "
                  f"footprint_p95={phase['metrics']['footprint_bytes']['p95']} exit_code={phase['exit_code']}")
        doc = build_evidence(identity=identity, smoke=smoke, target=args.target, environment=environment,
                             binary=binary, phases=phases, self_diffs=diffs, budgets=budgets,
                             started_unix_ms=started, finished_unix_ms=unix_ms())
        errs = validator.errors(doc)
        if errs:
            raise MeasureFailure(f"evidence_invalid: {'; '.join(errs[:5])}")
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except check.InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except MeasureFailure as exc:
        print(str(exc), file=sys.stderr)
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(check.dumps_canonical(doc))
    print(f"evidence={out} smoke={str(doc['smoke']).lower()} outcome={doc['outcome']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
