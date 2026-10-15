"""Linux sampler: /proc reads only (docs/specs/footprint-harness.md section 2).

footprint_bytes is Pss from /proc/<pid>/smaps_rollup, CPU is utime + stime from
/proc/<pid>/stat in USER_HZ ticks, threads come from /proc/<pid>/status and
descriptors are the entries of /proc/<pid>/fd. A Sampler binds to the process
start time (stat field 22) so a reused pid is a failed sample, not a reading
of another process.
"""

import os
import platform
from dataclasses import dataclass
from pathlib import Path

from samplers import PreflightError, Sample, SamplerError

METRIC = "pss"
DESCRIPTOR_KIND = "fd"
# The kernel's fixed user-interface tick rate (include/uapi/asm-generic/param.h).
USER_HZ = 100
NS_PER_TICK = 1_000_000_000 // USER_HZ

_MAX_SMALL_FILE = 64 * 1024
_MAX_ROLLUP = 1024 * 1024
_MAX_FDS = 1_048_576


@dataclass(frozen=True)
class Stat:
    state: str
    utime: int
    stime: int
    starttime: int


def parse_stat(text):
    """Parse /proc/<pid>/stat; the command may contain spaces and parentheses."""
    head, sep, rest = text.rpartition(")")
    if not sep or "(" not in head:
        raise SamplerError("stat: no command field")
    fields = rest.split()
    # fields[0] is field 3 (state); field N is fields[N - 3].
    if len(fields) < 20:
        raise SamplerError("stat: too few fields")
    try:
        return Stat(state=fields[0], utime=int(fields[11]), stime=int(fields[12]), starttime=int(fields[19]))
    except ValueError as exc:
        raise SamplerError(f"stat: {exc}") from exc


def _read(path, limit):
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    except OSError as exc:
        raise SamplerError(f"{path}: {exc.strerror or exc}") from exc
    if len(data) > limit:
        raise SamplerError(f"{path}: larger than {limit} bytes")
    try:
        return data.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - replace never raises
        raise SamplerError(str(exc)) from exc


def _field_kb(text, name):
    for line in text.splitlines():
        if line.startswith(name + ":"):
            parts = line.split()
            if len(parts) == 3 and parts[2] == "kB" and parts[1].isdigit():
                return int(parts[1]) * 1024
            raise SamplerError(f"{name}: malformed line")
    raise SamplerError(f"{name}: missing")


def _field_int(text, name):
    for line in text.splitlines():
        if line.startswith(name + ":"):
            value = line.split(":", 1)[1].strip()
            if value.isdigit():
                return int(value)
            raise SamplerError(f"{name}: malformed line")
    raise SamplerError(f"{name}: missing")


class Sampler:
    def __init__(self, pid, proc_root="/proc"):
        self.pid = int(pid)
        self._dir = Path(proc_root) / str(self.pid)
        self._starttime = self._stat().starttime

    def _stat(self):
        stat = parse_stat(_read(self._dir / "stat", _MAX_SMALL_FILE))
        if stat.state in ("Z", "X", "x"):
            raise SamplerError(f"pid {self.pid} has exited (state {stat.state})")
        return stat

    def _check(self, stat):
        if stat.starttime != self._starttime:
            raise SamplerError(f"pid {self.pid} start time changed: process replaced")

    def sample(self):
        stat = self._stat()
        self._check(stat)
        pss = _field_kb(_read(self._dir / "smaps_rollup", _MAX_ROLLUP), "Pss")
        threads = _field_int(_read(self._dir / "status", _MAX_SMALL_FILE), "Threads")
        try:
            with os.scandir(self._dir / "fd") as entries:
                descriptors = 0
                for _ in entries:
                    descriptors += 1
                    if descriptors > _MAX_FDS:
                        raise SamplerError("fd: too many entries")
        except OSError as exc:
            raise SamplerError(f"fd: {exc.strerror or exc}") from exc
        # Re-read last: the values above belong to the bound process only if it is still the same one.
        self._check(self._stat())
        if threads < 1:
            raise SamplerError("Threads: zero")
        return Sample(
            footprint_bytes=pss,
            footprint_metric=METRIC,
            cpu_ns=(stat.utime + stat.stime) * NS_PER_TICK,
            threads=threads,
            descriptors=descriptors,
            descriptor_kind=DESCRIPTOR_KIND,
        )

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def sample(pid):
    with Sampler(pid) as sampler:
        return sampler.sample()


def os_version_key(os_release):
    value = os_release.get("VERSION_ID", "")
    if not value:
        raise SamplerError("os-release has no VERSION_ID")
    return value


def preflight(proc_root="/proc"):
    if not os.access(Path(proc_root) / "self" / "smaps_rollup", os.R_OK):
        raise PreflightError("smaps_rollup is not available (CONFIG_PROC_PAGE_MONITOR)")
    try:
        tick = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError) as exc:
        raise PreflightError(f"SC_CLK_TCK: {exc}") from exc
    if tick != USER_HZ:
        raise PreflightError(f"SC_CLK_TCK is {tick}, not USER_HZ {USER_HZ}")


def environment():
    try:
        release = platform.freedesktop_os_release()
    except OSError as exc:
        raise SamplerError(f"os-release: {exc}") from exc
    return {
        "os_version": os_version_key(release),
        "os_release": (release.get("PRETTY_NAME") or release.get("NAME") or "Linux")[:256],
        "cpu_count": os.cpu_count() or 0,
        "memory_bytes": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGESIZE"),
        "clk_tck": os.sysconf("SC_CLK_TCK"),
    }
