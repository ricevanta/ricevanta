"""macOS sampler through ctypes (docs/specs/footprint-harness.md section 2).

footprint_bytes is ri_phys_footprint from proc_pid_rusage(RUSAGE_INFO_V4), CPU
is ri_user_time + ri_system_time in Mach absolute time converted with
mach_timebase_info, threads are pti_threadnum from proc_pidinfo(PROC_PIDTASKINFO)
and descriptors come from proc_pidinfo(PROC_PIDLISTFDS). Libraries load by
absolute /usr/lib path only, and only when a sampler is used, so this module
imports on every OS. A Sampler binds to ri_proc_start_abstime so a reused pid
is a failed sample.

Layouts: xnu bsd/sys/resource.h (rusage_info_v4), bsd/sys/proc_info.h
(proc_taskinfo, proc_fdinfo), libsyscall/wrappers/libproc/libproc.h.
"""

import ctypes
import os
import platform

from samplers import PreflightError, Sample, SamplerError

METRIC = "phys_footprint"
DESCRIPTOR_KIND = "fd"

LIBPROC_PATH = "/usr/lib/libproc.dylib"
LIBSYSTEM_PATH = "/usr/lib/libSystem.B.dylib"

RUSAGE_INFO_V4 = 4
PROC_PIDLISTFDS = 1
PROC_PIDTASKINFO = 4
PROC_PIDLISTFD_SIZE = 8
_MAX_FD_ENTRIES = 65536

_RUSAGE_V4_U64_FIELDS = (
    "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups",
    "ri_pageins", "ri_wired_size", "ri_resident_size", "ri_phys_footprint",
    "ri_proc_start_abstime", "ri_proc_exit_abstime", "ri_child_user_time",
    "ri_child_system_time", "ri_child_pkg_idle_wkups", "ri_child_interrupt_wkups",
    "ri_child_pageins", "ri_child_elapsed_abstime", "ri_diskio_bytesread",
    "ri_diskio_byteswritten", "ri_cpu_time_qos_default", "ri_cpu_time_qos_maintenance",
    "ri_cpu_time_qos_background", "ri_cpu_time_qos_utility", "ri_cpu_time_qos_legacy",
    "ri_cpu_time_qos_user_initiated", "ri_cpu_time_qos_user_interactive",
    "ri_billed_system_time", "ri_serviced_system_time", "ri_logical_writes",
    "ri_lifetime_max_phys_footprint", "ri_instructions", "ri_cycles", "ri_billed_energy",
    "ri_serviced_energy", "ri_interval_max_phys_footprint", "ri_runnable_time",
)


class rusage_info_v4(ctypes.Structure):
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [(name, ctypes.c_uint64) for name in _RUSAGE_V4_U64_FIELDS]


class proc_taskinfo(ctypes.Structure):
    _fields_ = [
        ("pti_virtual_size", ctypes.c_uint64),
        ("pti_resident_size", ctypes.c_uint64),
        ("pti_total_user", ctypes.c_uint64),
        ("pti_total_system", ctypes.c_uint64),
        ("pti_threads_user", ctypes.c_uint64),
        ("pti_threads_system", ctypes.c_uint64),
        ("pti_policy", ctypes.c_int32),
        ("pti_faults", ctypes.c_int32),
        ("pti_pageins", ctypes.c_int32),
        ("pti_cow_faults", ctypes.c_int32),
        ("pti_messages_sent", ctypes.c_int32),
        ("pti_messages_received", ctypes.c_int32),
        ("pti_syscalls_mach", ctypes.c_int32),
        ("pti_syscalls_unix", ctypes.c_int32),
        ("pti_csw", ctypes.c_int32),
        ("pti_threadnum", ctypes.c_int32),
        ("pti_numrunning", ctypes.c_int32),
        ("pti_priority", ctypes.c_int32),
    ]


class proc_fdinfo(ctypes.Structure):
    _fields_ = [("proc_fd", ctypes.c_int32), ("proc_fdtype", ctypes.c_uint32)]


class mach_timebase_info_data(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


_SIZES = {
    rusage_info_v4: 296,
    proc_taskinfo: 96,
    proc_fdinfo: PROC_PIDLISTFD_SIZE,
    mach_timebase_info_data: 8,
}


def _check_sizes():
    for struct, size in _SIZES.items():
        if ctypes.sizeof(struct) != size:
            raise PreflightError(f"{struct.__name__} is {ctypes.sizeof(struct)} bytes, expected {size}")


def _load_libraries():
    """Load libproc and libSystem by absolute path and declare the used signatures."""
    _check_sizes()
    libproc = ctypes.CDLL(LIBPROC_PATH, use_errno=True)
    libsystem = ctypes.CDLL(LIBSYSTEM_PATH, use_errno=True)
    libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    libproc.proc_pid_rusage.restype = ctypes.c_int
    libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    libproc.proc_pidinfo.restype = ctypes.c_int
    libsystem.mach_timebase_info.argtypes = [ctypes.c_void_p]
    libsystem.mach_timebase_info.restype = ctypes.c_int
    return libproc, libsystem


def mach_to_ns(ticks, numer, denom):
    return ticks * numer // denom


def _errno_text():
    err = ctypes.get_errno()
    return os.strerror(err) if err else "call failed"


def timebase(libsystem):
    info = mach_timebase_info_data()
    if libsystem.mach_timebase_info(ctypes.byref(info)) != 0 or info.numer == 0 or info.denom == 0:
        raise SamplerError("mach_timebase_info failed")
    return info.numer, info.denom


class Sampler:
    def __init__(self, pid, libraries=None):
        self.pid = int(pid)
        _check_sizes()
        self._libproc, self._libsystem = libraries if libraries is not None else _load_libraries()
        self._numer, self._denom = timebase(self._libsystem)
        self._start = self._rusage().ri_proc_start_abstime

    def _rusage(self):
        info = rusage_info_v4()
        if self._libproc.proc_pid_rusage(self.pid, RUSAGE_INFO_V4, ctypes.byref(info)) != 0:
            raise SamplerError(f"proc_pid_rusage({self.pid}): {_errno_text()}")
        if info.ri_proc_exit_abstime != 0:
            raise SamplerError(f"pid {self.pid} has exited")
        return info

    def _threads(self):
        info = proc_taskinfo()
        size = ctypes.sizeof(info)
        got = self._libproc.proc_pidinfo(self.pid, PROC_PIDTASKINFO, 0, ctypes.byref(info), size)
        if got != size:
            raise SamplerError(f"proc_pidinfo(PROC_PIDTASKINFO): {_errno_text()}")
        if info.pti_threadnum < 1:
            raise SamplerError("pti_threadnum is not positive")
        return info.pti_threadnum

    def _descriptors(self):
        estimate = self._libproc.proc_pidinfo(self.pid, PROC_PIDLISTFDS, 0, None, 0)
        if estimate <= 0:
            raise SamplerError(f"proc_pidinfo(PROC_PIDLISTFDS) size: {_errno_text()}")
        entries = estimate // PROC_PIDLISTFD_SIZE + 32
        if entries > _MAX_FD_ENTRIES:
            raise SamplerError(f"PROC_PIDLISTFDS needs {entries} entries, above the bound {_MAX_FD_ENTRIES}")
        buf = (proc_fdinfo * entries)()
        got = self._libproc.proc_pidinfo(self.pid, PROC_PIDLISTFDS, 0, ctypes.byref(buf), ctypes.sizeof(buf))
        if got <= 0 or got > ctypes.sizeof(buf) or got % PROC_PIDLISTFD_SIZE:
            raise SamplerError(f"proc_pidinfo(PROC_PIDLISTFDS): {_errno_text()}")
        return got // PROC_PIDLISTFD_SIZE

    def sample(self):
        info = self._rusage()
        if info.ri_proc_start_abstime != self._start:
            raise SamplerError(f"pid {self.pid} start time changed: process replaced")
        threads = self._threads()
        descriptors = self._descriptors()
        if self._rusage().ri_proc_start_abstime != self._start:
            raise SamplerError(f"pid {self.pid} start time changed: process replaced")
        return Sample(
            footprint_bytes=info.ri_phys_footprint,
            footprint_metric=METRIC,
            cpu_ns=mach_to_ns(info.ri_user_time + info.ri_system_time, self._numer, self._denom),
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


def os_version_key(mac_version):
    major = mac_version.split(".")[0]
    if not major.isdigit():
        raise SamplerError(f"unrecognized macOS version {mac_version!r}")
    return major


def preflight():
    _check_sizes()
    try:
        _, libsystem = _load_libraries()
    except OSError as exc:
        raise PreflightError(f"cannot load system libraries: {exc}") from exc
    timebase(libsystem)


def environment():
    version = platform.mac_ver()[0]
    _, libsystem = _load_libraries()
    numer, denom = timebase(libsystem)
    return {
        "os_version": os_version_key(version),
        "os_release": version[:256],
        "cpu_count": os.cpu_count() or 0,
        "memory_bytes": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGESIZE"),
        "clk_tck": None,
        "mach_timebase": {"numer": numer, "denom": denom},
    }
