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
import datetime
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


def summarize(samples, reference, *, metric=None, descriptor_kind=None):
    """Summaries over the given post-warm-up samples; failed samples are skipped.

    CPU is 100 x delta(cpu time) / delta(wall time) from the reference taken at
    the end of the warm-up to the last sample, so one busy core is 100.
    """
    ok = [t for t in samples if t.sample is not None]
    if not ok:
        if metric is None or descriptor_kind is None:
            raise MeasureFailure("no_samples")
        return {
            "footprint_bytes": dict(metric=metric, min=0, max=0, mean=0, p50=0, p95=0),
            "cpu_core_pct": dict(mean=0, max=0),
            "threads": dict(min=1, max=1),
            "descriptors": dict(kind=descriptor_kind, min=0, max=0),
        }
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
    nearest = min(ok, key=lambda t: (abs(t.unix_ms - self_sample["sampled_unix_ms"]), t.unix_ms))
    return self_sample["footprint_bytes"] - nearest.sample.footprint_bytes


def is_smoke(identity, scale, stand_in):
    return identity is None or scale < 1 or stand_in


def load_budgets(path=BUDGETS_PATH):
    return check.load_budgets(path)


def build_evidence(*, identity, smoke, target, environment, binary, phases, budgets,
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
        "results": [],
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


def read_shared(path, limit):
    """Copy bounded bytes, permitting concurrent rename and deletion on Windows."""
    if sys.platform != 'win32':
        with open(path, 'rb') as stream:
            return stream.read(limit + 1)
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k.ReadFile.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    handle = k.CreateFileW(str(path), 0x80000000, 1 | 2 | 4, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buf = ctypes.create_string_buffer(limit + 1)
        count = wintypes.DWORD()
        if not k.ReadFile(handle, buf, limit + 1, ctypes.byref(count), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return buf.raw[:count.value]
    finally:
        k.CloseHandle(handle)


def _read_health(path):
    try:
        doc = check.loads_strict(read_shared(path, MAX_HEALTH_BYTES), MAX_HEALTH_BYTES)
        validator = check.Validator(check.load_json_file(check.ROOT / 'schemas/agent/health/v1/health.schema.json'))
        return None if validator.errors(doc) else doc
    except (OSError, check.InputError):
        return None


def _self_sample(doc, pid):
    if not doc or not isinstance(doc.get('process'), dict):
        return None
    proc = doc['process']
    return {**{key: proc[key] for key in ('footprint_bytes', 'footprint_metric', 'threads',
                                          'sampled_unix_ms', 'sampled_uptime_ms')},
            'written_unix_ms': doc['written_unix_ms']}


class HealthProgress:
    """Accumulate all reads, including invalid reads, without retaining health text."""

    def __init__(self, pid, interval):
        self.interval = interval
        self.summary = dict(pid=pid, start=None, end=None, observations=0, invalid_observations=0,
                            counter_regressions=0, max_write_age_ms=0, max_sample_age_ms=0,
                            max_observation_gap_ms=0)
        self.first = self.previous = None
        self.previous_read = None

    def observe(self, doc, wall, elapsed):
        snapshot = None
        if doc and isinstance(doc.get('process'), dict):
            snapshot = {key: doc[key] for key in ('pid', 'state', 'interval_ms', 'written_unix_ms', 'uptime_ms')}
            snapshot.update({key: doc['process'][key] for key in ('sampled_unix_ms', 'sampled_uptime_ms')})
            snapshot.update({key: doc['counters'][key] for key in check.COUNTERS})
            snapshot.update(observed_unix_ms=wall, observed_elapsed_ms=elapsed)
        self.observe_snapshot(snapshot, wall, elapsed)
        return snapshot

    def observe_snapshot(self, s, wall=None, elapsed=None):
        g = self.summary
        if s is not None:
            wall, elapsed = s['observed_unix_ms'], s['observed_elapsed_ms']
        if self.previous_read is not None:
            old_wall, old_elapsed = self.previous_read
            gap = elapsed - old_elapsed
            g['max_observation_gap_ms'] = max(g['max_observation_gap_ms'], gap)
            clock_bad = wall < old_wall or gap < 0 or abs(wall - old_wall - gap) > 2000
        else:
            clock_bad = False
        self.previous_read = wall, elapsed
        if g['observations'] == 0:
            g['start'] = s
        g['end'] = s
        g['observations'] += 1
        invalid = clock_bad or not check.snapshot_valid(s, g['pid'], self.interval)
        if s:
            if self.first is None:
                self.first = s
            if self.previous:
                invalid |= not check.snapshots_consistent(self.previous, s)
                if any(s[k] < self.previous[k] for k in check.COUNTERS):
                    g['counter_regressions'] += 1
            for key, age in zip(('max_write_age_ms', 'max_sample_age_ms'), check.snapshot_ages(s, self.first)):
                g[key] = max(g[key], age)
            self.previous = s
        if invalid:
            g['invalid_observations'] += 1


class LogActivity:
    """Bounded event sets across active and retained files, filtered at the endpoints."""

    def __init__(self, profile, duration_ms, pid):
        self.profile, self.pid = profile, pid
        self.limit = (duration_ms + WARMUP_MS) // profile['health']['interval_ms'] + 10
        self.samples, self.rotations, self.invalid = {}, set(), set()

    def bad(self, raw):
        if len(self.invalid) < self.limit:
            self.invalid.add(hashlib.sha256(raw).digest())

    def read(self, directory):
        log = self.profile['log']
        paths = [directory / 'agent.log'] + [directory / f'agent.log.{i}' for i in range(1, log['max_files'])]
        for path in paths:
            try:
                raw = read_shared(path, log['max_file_bytes'])
            except FileNotFoundError:
                continue
            except OSError:
                self.bad(b'read_failed')
                continue
            if len(raw) > log['max_file_bytes']:
                self.bad(b'oversize_file')
                continue
            # A concurrent append can leave the last line incomplete. Revisit it on the next read.
            for index, line in enumerate(raw.split(b'\n')[:-1]):
                try:
                    item = check.loads_strict(line, 8192)
                    if (not isinstance(item, dict) or item.get('pid') != self.pid
                            or item.get('level') not in ('error', 'warn', 'info', 'debug')
                            or not isinstance(item.get('event'), str)
                            or not isinstance(item.get('ts'), str)):
                        raise ValueError()
                    if (not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', item['ts'])
                            or not re.fullmatch(r'[a-z][a-z0-9_]*', item['event'])):
                        raise ValueError()
                    datetime.datetime.fromisoformat(item['ts'].replace('Z', '+00:00'))
                    if 'detail' in item and (not isinstance(item['detail'], str) or len(item['detail'].encode()) > 2048):
                        raise ValueError()
                    event = item['event']
                    if event == 'sample_completed':
                        keys = ('sample', 'sampled_uptime_ms', 'footprint_bytes', 'cpu_user_ms',
                                'cpu_system_ms', 'threads', 'descriptor_count')
                        if (len(line) >= 1024 or 'detail' in item or item['level'] != 'debug'
                                or any(type(item.get(k)) is not int or not 0 <= item[k] <= 2**63-1 for k in keys)
                                or item.get('footprint_metric') not in ('pss', 'phys_footprint', 'private_working_set')
                                or item.get('descriptor_kind') not in ('fd', 'handle')):
                            raise ValueError()
                        seq, uptime = item['sample'], item['sampled_uptime_ms']
                        if seq in self.samples and self.samples[seq] != uptime:
                            raise ValueError()
                        if len(self.samples) >= self.limit and seq not in self.samples:
                            raise ValueError()
                        self.samples[seq] = uptime
                    elif event == 'log_rotated':
                        seq = item.get('rotation')
                        if index != 0 or type(seq) is not int or not 1 <= seq <= 2**63-1:
                            raise ValueError()
                        if len(self.rotations) >= self.limit and seq not in self.rotations:
                            raise ValueError()
                        self.rotations.add(seq)
                except (check.InputError, ValueError):
                    self.bad(line)

    def finish(self, progress):
        a, b = progress['start'], progress['end']
        if a and b:
            low = a['uptime_ms'] + (a['observed_unix_ms'] - a['written_unix_ms']) - a['observed_elapsed_ms']
            high = b['uptime_ms'] + (b['observed_unix_ms'] - b['written_unix_ms'])
            samples = sum(a['samples'] < seq <= b['samples'] and low <= uptime <= high
                          for seq, uptime in self.samples.items())
            rotations = sum(a['log_rotations'] < seq <= b['log_rotations'] for seq in self.rotations)
        else:
            samples = rotations = 0
        return dict(sample_events=samples, rotations_observed=rotations, invalid_lines=len(self.invalid))


def external_pair(own, samples):
    ok = [t for t in samples if t.sample is not None]
    if own is None or not ok:
        return None
    nearest = min(ok, key=lambda t: (abs(t.unix_ms - own['sampled_unix_ms']), t.unix_ms))
    return dict(unix_ms=nearest.unix_ms, footprint_bytes=nearest.sample.footprint_bytes,
                footprint_metric=nearest.sample.footprint_metric)

def _exit_code(returncode):
    if returncode < 0:
        return min(128 - returncode, 255)
    return min(returncode, 255)


def _send_stop(proc):
    if sys.platform == "win32":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GenerateConsoleCtrlEvent.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        kernel.GenerateConsoleCtrlEvent.restype = ctypes.c_int32
        if not kernel.GenerateConsoleCtrlEvent(1, proc.pid):  # CTRL_BREAK_EVENT, child process group
            raise MeasureFailure("stop_delivery_failed")
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
    profile = check.loads_strict(raw)

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
                    raise MeasureFailure(f"not_ready phase={name}")
                time.sleep(HEALTH_POLL_S)
            try:
                sampler = sampler_mod.Sampler(proc.pid)
            except samplers.SamplerError:
                sampler = None
            time.sleep(warmup_ms / 1000)
            window_mono = time.monotonic_ns()
            window_wall = unix_ms()
            progress = HealthProgress(proc.pid, profile['health']['interval_ms'])
            logs = LogActivity(profile, duration_ms, proc.pid)

            def observe():
                doc = _read_health(runtime / 'health.json')
                progress.observe(doc, unix_ms(), (time.monotonic_ns() - window_mono) // 1_000_000)
                logs.read(tree / 'logs')
                return doc

            observe()
            reference = _take(sampler, proc)
            samples = []
            for k in range(1, count + 1):
                target = window_mono + k * SAMPLE_INTERVAL_MS * 1_000_000
                time.sleep(max(0, target - time.monotonic_ns()) / 1e9)
                samples.append(_take(sampler, proc))
                observe()
            end_target = window_mono + duration_ms * 1_000_000
            time.sleep(max(0, end_target - time.monotonic_ns()) / 1e9)
            # A distinct final boundary read is required even if the last external
            # observation occurred at this boundary. Capture everything before stop.
            doc = observe()
            finished_wall = unix_ms()
            actual_duration = (time.monotonic_ns() - window_mono) // 1_000_000
            own = _self_sample(doc, proc.pid)
            metrics = summarize(samples, reference, metric=sampler_mod.METRIC,
                                descriptor_kind=sampler_mod.DESCRIPTOR_KIND)
            pair = external_pair(own, [reference] + samples)

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
        "duration_ms": actual_duration,
        "started_unix_ms": window_wall,
        "finished_unix_ms": finished_wall,
        "health_progress": progress.summary,
        "log_activity": logs.finish(progress.summary),
        "self_sample_external": pair,
        "sample_interval_ms": SAMPLE_INTERVAL_MS,
        "samples": count,
        "failed_samples": sum(1 for t in samples if t.sample is None),
        "shutdown_ms": shutdown_ms,
        "exit_code": _exit_code(proc.returncode),
        "metrics": metrics,
        "self_sample": own,
    }
    return phase


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
        phases = []
        for name in args.phases:
            phase = run_phase(name, prefix, args.duration_scale, sampler_mod)
            phases.append(phase)
            print(f"phase={name} samples={phase['samples']} failed={phase['failed_samples']} "
                  f"footprint_p95={phase['metrics']['footprint_bytes']['p95']} exit_code={phase['exit_code']}")
        doc = build_evidence(identity=identity, smoke=smoke, target=args.target, environment=environment,
                             binary=binary, phases=phases, budgets=budgets,
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
