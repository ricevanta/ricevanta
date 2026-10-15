"""Windows sampler through ctypes (docs/specs/footprint-harness.md section 2).

footprint_bytes is PrivateWorkingSetSize from K32GetProcessMemoryInfo with
PROCESS_MEMORY_COUNTERS_EX2, CPU is GetProcessTimes kernel plus user time in
100 ns units, threads are cntThreads from a TH32CS_SNAPPROCESS snapshot and
descriptors are GetProcessHandleCount. The process handle is opened once with
PROCESS_QUERY_LIMITED_INFORMATION and held for the sampler's lifetime, which
keeps the pid from being reused; the creation time is also compared on every
sample. kernel32 loads only when a sampler is used, so this module imports on
every OS. Structures use fixed-width fields so their sizes match x64 Windows on
any host.
"""

import ctypes
import os
import platform

from samplers import PreflightError, Sample, SamplerError

METRIC = "private_working_set"
DESCRIPTOR_KIND = "handle"

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
STILL_ACTIVE = 259
INVALID_HANDLE_VALUE = (1 << 64) - 1
_MAX_SNAPSHOT_ENTRIES = 1 << 20

DWORD = ctypes.c_uint32
HANDLE = ctypes.c_void_p
BOOL = ctypes.c_int32


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", DWORD), ("dwHighDateTime", DWORD)]


class PROCESS_MEMORY_COUNTERS_EX2(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("PageFaultCount", DWORD),
        ("PeakWorkingSetSize", ctypes.c_uint64),
        ("WorkingSetSize", ctypes.c_uint64),
        ("QuotaPeakPagedPoolUsage", ctypes.c_uint64),
        ("QuotaPagedPoolUsage", ctypes.c_uint64),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_uint64),
        ("QuotaNonPagedPoolUsage", ctypes.c_uint64),
        ("PagefileUsage", ctypes.c_uint64),
        ("PeakPagefileUsage", ctypes.c_uint64),
        ("PrivateUsage", ctypes.c_uint64),
        ("PrivateWorkingSetSize", ctypes.c_uint64),
        ("SharedCommitUsage", ctypes.c_uint64),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ctypes.c_uint64),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", ctypes.c_int32),
        ("dwFlags", DWORD),
        ("szExeFile", ctypes.c_uint16 * 260),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", DWORD),
        ("dwMemoryLoad", DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


# Sizes on x64 Windows (psapi.h, tlhelp32.h, sysinfoapi.h), asserted before every call.
EX2_SIZE = 96
PROCESSENTRY32W_SIZE = 568
MEMORYSTATUSEX_SIZE = 64


def _require_size(struct, expected):
    actual = ctypes.sizeof(struct)
    if actual != expected:
        raise SamplerError(f"{struct.__name__} is {actual} bytes, expected {expected}")


def _load_kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sigs = {
        "OpenProcess": ([DWORD, BOOL, DWORD], HANDLE),
        "CloseHandle": ([HANDLE], BOOL),
        "GetProcessTimes": ([HANDLE] + [ctypes.c_void_p] * 4, BOOL),
        "GetExitCodeProcess": ([HANDLE, ctypes.c_void_p], BOOL),
        "K32GetProcessMemoryInfo": ([HANDLE, ctypes.c_void_p, DWORD], BOOL),
        "GetProcessHandleCount": ([HANDLE, ctypes.c_void_p], BOOL),
        "CreateToolhelp32Snapshot": ([DWORD, DWORD], HANDLE),
        "Process32FirstW": ([HANDLE, ctypes.c_void_p], BOOL),
        "Process32NextW": ([HANDLE, ctypes.c_void_p], BOOL),
        "GlobalMemoryStatusEx": ([ctypes.c_void_p], BOOL),
    }
    for name, (argtypes, restype) in sigs.items():
        fn = getattr(kernel32, name)
        fn.argtypes = argtypes
        fn.restype = restype
    return kernel32


def _last_error():
    get = getattr(ctypes, "get_last_error", None)
    return f"error {get()}" if get else "call failed"


def filetime_to_ns(ft):
    return ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) * 100


class Sampler:
    def __init__(self, pid, kernel32=None):
        self.pid = int(pid)
        self._k = kernel32 if kernel32 is not None else _load_kernel32()
        self._handle = None
        handle = self._k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, self.pid)
        if not handle:
            raise SamplerError(f"OpenProcess({self.pid}): {_last_error()}")
        self._handle = handle
        try:
            self._creation = self._times()[0]
        except SamplerError:
            self.close()
            raise

    def _times(self):
        creation, exit_, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        ok = self._k.GetProcessTimes(
            self._handle, ctypes.byref(creation), ctypes.byref(exit_), ctypes.byref(kernel), ctypes.byref(user)
        )
        if not ok:
            raise SamplerError(f"GetProcessTimes: {_last_error()}")
        return filetime_to_ns(creation), filetime_to_ns(kernel) + filetime_to_ns(user)

    def _alive(self):
        code = DWORD()
        if not self._k.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            raise SamplerError(f"GetExitCodeProcess: {_last_error()}")
        if code.value != STILL_ACTIVE:
            raise SamplerError(f"pid {self.pid} has exited")

    def _private_working_set(self):
        _require_size(PROCESS_MEMORY_COUNTERS_EX2, EX2_SIZE)
        counters = PROCESS_MEMORY_COUNTERS_EX2()
        counters.cb = EX2_SIZE
        if not self._k.K32GetProcessMemoryInfo(self._handle, ctypes.byref(counters), EX2_SIZE):
            raise SamplerError(f"K32GetProcessMemoryInfo: {_last_error()}")
        if counters.PrivateWorkingSetSize == 0:
            raise SamplerError("PrivateWorkingSetSize is 0")
        return counters.PrivateWorkingSetSize

    def _handles(self):
        count = DWORD()
        if not self._k.GetProcessHandleCount(self._handle, ctypes.byref(count)):
            raise SamplerError(f"GetProcessHandleCount: {_last_error()}")
        return count.value

    def _threads(self):
        _require_size(PROCESSENTRY32W, PROCESSENTRY32W_SIZE)
        snap = self._k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap or snap == INVALID_HANDLE_VALUE or snap == -1:
            raise SamplerError(f"CreateToolhelp32Snapshot: {_last_error()}")
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = PROCESSENTRY32W_SIZE
            more = self._k.Process32FirstW(snap, ctypes.byref(entry))
            for _ in range(_MAX_SNAPSHOT_ENTRIES):
                if not more:
                    break
                if entry.th32ProcessID == self.pid:
                    if entry.cntThreads < 1:
                        raise SamplerError("cntThreads is 0")
                    return entry.cntThreads
                more = self._k.Process32NextW(snap, ctypes.byref(entry))
            raise SamplerError(f"pid {self.pid} not in the process snapshot")
        finally:
            self._k.CloseHandle(snap)

    def sample(self):
        if self._handle is None:
            raise SamplerError("sampler is closed")
        self._alive()
        creation, cpu_ns = self._times()
        if creation != self._creation:
            raise SamplerError(f"pid {self.pid} start time changed: process replaced")
        footprint = self._private_working_set()
        handles = self._handles()
        threads = self._threads()
        return Sample(
            footprint_bytes=footprint,
            footprint_metric=METRIC,
            cpu_ns=cpu_ns,
            threads=threads,
            descriptors=handles,
            descriptor_kind=DESCRIPTOR_KIND,
        )

    def close(self):
        if self._handle is not None:
            self._k.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def sample(pid):
    with Sampler(pid) as sampler:
        return sampler.sample()


def os_version_key(win32_ver):
    version = win32_ver[1]
    if not version:
        raise SamplerError("platform.win32_ver() has no version")
    return version


def preflight():
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise PreflightError("the harness needs a 64-bit Python on Windows x64")
    for struct, size in (
        (PROCESS_MEMORY_COUNTERS_EX2, EX2_SIZE),
        (PROCESSENTRY32W, PROCESSENTRY32W_SIZE),
        (MEMORYSTATUSEX, MEMORYSTATUSEX_SIZE),
    ):
        if ctypes.sizeof(struct) != size:
            raise PreflightError(f"{struct.__name__} is {ctypes.sizeof(struct)} bytes, expected {size}")
    try:
        _load_kernel32()
    except (OSError, AttributeError) as exc:
        raise PreflightError(f"kernel32: {exc}") from exc


def _total_physical(kernel32):
    _require_size(MEMORYSTATUSEX, MEMORYSTATUSEX_SIZE)
    status = MEMORYSTATUSEX()
    status.dwLength = MEMORYSTATUSEX_SIZE
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise SamplerError(f"GlobalMemoryStatusEx: {_last_error()}")
    return status.ullTotalPhys


def environment():
    ver = platform.win32_ver()
    release = " ".join(part for part in (platform.system(), platform.release(), platform.win32_edition()) if part)
    return {
        "os_version": os_version_key(ver),
        "os_release": (release or "Windows")[:256],
        "cpu_count": os.cpu_count() or 0,
        "memory_bytes": _total_physical(_load_kernel32()),
        "clk_tck": None,
    }
