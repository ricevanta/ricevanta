"""Task 1 tests for the per-OS samplers (docs/specs/footprint-harness.md section 2).

Native tests run against the current OS's sampler. The macOS and Windows
modules are also imported on every OS and their pure parts (structure sizes,
library paths, unit conversions, error mapping) are tested with injected fakes;
the native macOS and Windows paths run on their CI hosts.
"""

import ctypes
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import samplers
from measure import base_python
from samplers import darwin, linux, windows
from samplers import Sample, SamplerError

MIB = 1024 * 1024

CHILD = r"""
import os, sys, threading, time
files_dir = sys.argv[1]
block = bytearray(64 * 1024 * 1024)
for offset in range(0, len(block), 4096):
    block[offset] = 1
handles = [open(f"{files_dir}/f{i}.txt", "w") for i in range(20)]
stop = threading.Event()
def spin():
    x = 0
    while not stop.is_set():
        x += 1
def rest():
    stop.wait()
threads = [threading.Thread(target=spin, daemon=True)] + [threading.Thread(target=rest, daemon=True) for _ in range(3)]
for t in threads:
    t.start()
sys.stdout.write(f"ready {os.getpid()}\n")
sys.stdout.flush()
sys.stdin.readline()
stop.set()
"""


def start_child(test):
    files = tempfile.TemporaryDirectory(prefix="rv-sampler-")
    test.addCleanup(files.cleanup)
    proc = subprocess.Popen(
        [base_python(), "-B", "-c", CHILD, files.name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    def stop():
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)
        proc.stdin.close()
        proc.stdout.close()

    test.addCleanup(stop)
    line = proc.stdout.readline()
    test.assertEqual(line.strip(), f"ready {proc.pid}")
    return proc


class NativeSamplerTests(unittest.TestCase):
    def setUp(self):
        self.mod = samplers.current()

    def test_child_footprint_threads_descriptors(self):
        proc = start_child(self)
        with self.mod.Sampler(proc.pid) as sampler:
            s = sampler.sample()
        self.assertIsInstance(s, Sample)
        self.assertGreaterEqual(s.footprint_bytes, 60 * MIB)
        self.assertEqual(s.footprint_metric, self.mod.METRIC)
        self.assertGreaterEqual(s.threads, 5)
        self.assertGreaterEqual(s.descriptors, 20)
        self.assertEqual(s.descriptor_kind, self.mod.DESCRIPTOR_KIND)

    def test_cpu_increases_while_child_spins(self):
        proc = start_child(self)
        with self.mod.Sampler(proc.pid) as sampler:
            first = sampler.sample()
            time.sleep(0.5)
            second = sampler.sample()
        self.assertGreater(second.cpu_ns, first.cpu_ns)
        # One spinning thread over 0.5 s accrues well over 0.1 s of CPU.
        self.assertGreater(second.cpu_ns - first.cpu_ns, 100_000_000)

    def test_module_level_sample(self):
        proc = start_child(self)
        s = self.mod.sample(proc.pid)
        self.assertGreaterEqual(s.footprint_bytes, 60 * MIB)

    def test_dead_pid_raises(self):
        proc = subprocess.Popen([base_python(), "-B", "-c", "pass"])
        proc.wait(timeout=30)
        with self.assertRaises(SamplerError):
            self.mod.sample(proc.pid)

    def test_bound_sampler_fails_after_exit(self):
        proc = subprocess.Popen(
            [base_python(), "-B", "-c", "import sys; sys.stdin.readline()"],
            stdin=subprocess.PIPE,
        )
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        sampler = self.mod.Sampler(proc.pid)
        self.addCleanup(sampler.close)
        sampler.sample()
        proc.stdin.close()
        # Not reaped yet: a Unix child stays a zombie, a Windows handle stays
        # open, so the pid cannot be reused while it is sampled.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            time.sleep(0.05)
            try:
                sampler.sample()
            except SamplerError:
                break
        else:
            self.fail("sampler kept returning samples for an exited process")
        proc.wait(timeout=30)

    def test_environment(self):
        env = self.mod.environment()
        self.assertGreater(env["memory_bytes"], 0)
        self.assertGreaterEqual(env["cpu_count"], 1)
        self.assertTrue(env["os_version"])
        self.assertTrue(env["os_release"])
        if sys.platform == "linux":
            self.assertEqual(env["os_version"], platform.freedesktop_os_release()["VERSION_ID"])
            self.assertEqual(env["clk_tck"], 100)
            self.assertNotIn("mach_timebase", env)
        elif sys.platform == "darwin":
            self.assertEqual(env["os_version"], platform.mac_ver()[0].split(".")[0])
            self.assertIsNone(env["clk_tck"])
            self.assertGreaterEqual(env["mach_timebase"]["numer"], 1)
            self.assertGreaterEqual(env["mach_timebase"]["denom"], 1)
        elif sys.platform == "win32":
            self.assertEqual(env["os_version"], platform.win32_ver()[1])
            self.assertIsNone(env["clk_tck"])
            self.assertNotIn("mach_timebase", env)

    def test_preflight_passes(self):
        self.mod.preflight()


def write_proc(root, pid, *, comm="ricevanta-agent", state="S", utime=250, stime=50,
               starttime=777, pss_kb=9216, threads=6, fds=3):
    base = Path(root) / str(pid)
    (base / "fd").mkdir(parents=True, exist_ok=True)
    for name in os.listdir(base / "fd"):
        os.unlink(base / "fd" / name)
    # Fields 3..52 after the command; utime, stime and starttime are fields 14, 15 and 22.
    fields = [state, "1", str(pid), str(pid), "0", "-1", "4194560", "100", "0", "0", "0",
              str(utime), str(stime), "0", "0", "20", "0", str(threads), "0", str(starttime)]
    fields += ["0"] * (52 - 2 - len(fields))
    (base / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields) + "\n")
    (base / "status").write_text(f"Name:\t{comm[:15]}\nState:\t{state}\nThreads:\t{threads}\n")
    (base / "smaps_rollup").write_text(
        "55d0-7fff ---p 00000000 00:00 0 [rollup]\n"
        f"Rss:               12000 kB\nPss:               {pss_kb} kB\nPss_Anon:           1 kB\n"
    )
    for i in range(fds):
        (base / "fd" / str(i)).write_text("")


@unittest.skipUnless(sys.platform == "linux", "Linux /proc parsing")
class LinuxSamplerTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="rv-proc-")
        self.addCleanup(shutil.rmtree, self.root)

    def test_clk_tck_is_user_hz(self):
        self.assertEqual(os.sysconf("SC_CLK_TCK"), 100)
        self.assertEqual(linux.USER_HZ, 100)

    def test_stat_with_parenthesis_in_comm(self):
        line = "4242 (a) (b) c) S 1 4242 4242 0 -1 0 0 0 0 0 123 45 0 0 20 0 7 0 999 0 0\n"
        stat = linux.parse_stat(line)
        self.assertEqual(stat.utime, 123)
        self.assertEqual(stat.stime, 45)
        self.assertEqual(stat.starttime, 999)
        self.assertEqual(stat.state, "S")

    def test_synthetic_proc_sample(self):
        write_proc(self.root, 4242, comm="evil) (name", utime=250, stime=50, pss_kb=9216, threads=6, fds=5)
        with linux.Sampler(4242, proc_root=self.root) as sampler:
            s = sampler.sample()
        self.assertEqual(s.footprint_bytes, 9216 * 1024)
        self.assertEqual(s.footprint_metric, "pss")
        self.assertEqual(s.cpu_ns, 300 * 10_000_000)
        self.assertEqual(s.threads, 6)
        self.assertEqual(s.descriptors, 5)
        self.assertEqual(s.descriptor_kind, "fd")

    def test_pid_reuse_is_detected(self):
        write_proc(self.root, 4242, starttime=777)
        sampler = linux.Sampler(4242, proc_root=self.root)
        sampler.sample()
        write_proc(self.root, 4242, starttime=778)
        with self.assertRaisesRegex(SamplerError, "start time"):
            sampler.sample()

    def test_zombie_is_a_failed_sample(self):
        write_proc(self.root, 4242)
        sampler = linux.Sampler(4242, proc_root=self.root)
        write_proc(self.root, 4242, state="Z")
        with self.assertRaises(SamplerError):
            sampler.sample()

    def test_missing_pss_is_a_failed_sample(self):
        write_proc(self.root, 4242)
        sampler = linux.Sampler(4242, proc_root=self.root)
        (Path(self.root) / "4242" / "smaps_rollup").write_text("")
        with self.assertRaises(SamplerError):
            sampler.sample()

    def test_preflight_requires_smaps_rollup(self):
        os.makedirs(Path(self.root) / "self")
        with self.assertRaises(samplers.PreflightError):
            linux.preflight(proc_root=self.root)

    def test_preflight_requires_user_hz(self):
        with mock.patch.object(linux.os, "sysconf", return_value=250):
            with self.assertRaises(samplers.PreflightError):
                linux.preflight()


def _target(arg):
    """The object behind a ctypes.byref argument."""
    return arg._obj


class FakeLibproc:
    def __init__(self, start=111, exit_abstime=0, footprint=50 * MIB, user=1000, system=500, threads=7, fds=9):
        self.start, self.exit_abstime, self.footprint = start, exit_abstime, footprint
        self.user, self.system, self.threads, self.fds = user, system, threads, fds
        self.calls = []

    def proc_pid_rusage(self, pid, flavor, buf):
        self.calls.append(("rusage", pid, flavor))
        info = _target(buf)
        info.ri_phys_footprint = self.footprint
        info.ri_user_time = self.user
        info.ri_system_time = self.system
        info.ri_proc_start_abstime = self.start
        info.ri_proc_exit_abstime = self.exit_abstime
        return 0

    def proc_pidinfo(self, pid, flavor, arg, buf, size):
        self.calls.append(("pidinfo", pid, flavor, size))
        if flavor == darwin.PROC_PIDTASKINFO:
            _target(buf).pti_threadnum = self.threads
            return ctypes.sizeof(darwin.proc_taskinfo)
        if flavor == darwin.PROC_PIDLISTFDS:
            if buf is None:
                return (self.fds + 20) * darwin.PROC_PIDLISTFD_SIZE
            return self.fds * darwin.PROC_PIDLISTFD_SIZE
        return 0


class FakeLibSystem:
    def mach_timebase_info(self, buf):
        info = _target(buf)
        info.numer, info.denom = 125, 3
        return 0


class DarwinPureTests(unittest.TestCase):
    def test_structure_sizes(self):
        self.assertEqual(ctypes.sizeof(darwin.rusage_info_v4), 296)
        self.assertEqual(darwin.rusage_info_v4.ri_uuid.size, 16)
        self.assertEqual(len(darwin.rusage_info_v4._fields_), 36)
        self.assertEqual(ctypes.sizeof(darwin.proc_taskinfo), 96)
        self.assertEqual(ctypes.sizeof(darwin.proc_fdinfo), darwin.PROC_PIDLISTFD_SIZE)
        self.assertEqual(ctypes.sizeof(darwin.mach_timebase_info_data), 8)

    def test_libraries_loaded_by_absolute_path(self):
        self.assertEqual(darwin.LIBPROC_PATH, "/usr/lib/libproc.dylib")
        self.assertEqual(darwin.LIBSYSTEM_PATH, "/usr/lib/libSystem.B.dylib")
        loaded = []

        class FakeFn:
            def __call__(self, *a):
                return 0

        class FakeCDLL:
            def __init__(self, path, use_errno=False):
                loaded.append((path, use_errno))

            def __getattr__(self, name):
                return FakeFn()

        with mock.patch.object(darwin.ctypes, "CDLL", FakeCDLL):
            darwin._load_libraries()
        self.assertEqual(loaded, [("/usr/lib/libproc.dylib", True), ("/usr/lib/libSystem.B.dylib", True)])

    def test_mach_to_ns(self):
        self.assertEqual(darwin.mach_to_ns(24, 125, 3), 1000)
        self.assertEqual(darwin.mach_to_ns(1000, 1, 1), 1000)

    def test_version_key(self):
        self.assertEqual(darwin.os_version_key("15.6.1"), "15")
        self.assertEqual(darwin.os_version_key("15"), "15")
        with self.assertRaises(SamplerError):
            darwin.os_version_key("")

    def test_sampler_with_fake_libraries(self):
        libproc = FakeLibproc()
        with darwin.Sampler(4242, libraries=(libproc, FakeLibSystem())) as sampler:
            s = sampler.sample()
        self.assertEqual(s.footprint_bytes, 50 * MIB)
        self.assertEqual(s.footprint_metric, "phys_footprint")
        self.assertEqual(s.cpu_ns, darwin.mach_to_ns(1500, 125, 3))
        self.assertEqual(s.threads, 7)
        self.assertEqual(s.descriptors, 9)
        self.assertEqual(s.descriptor_kind, "fd")
        self.assertIn(("rusage", 4242, darwin.RUSAGE_INFO_V4), libproc.calls)

    def test_pid_reuse_is_detected(self):
        libproc = FakeLibproc(start=111)
        sampler = darwin.Sampler(4242, libraries=(libproc, FakeLibSystem()))
        libproc.start = 222
        with self.assertRaisesRegex(SamplerError, "start time"):
            sampler.sample()

    def test_exited_process_is_a_failed_sample(self):
        libproc = FakeLibproc()
        sampler = darwin.Sampler(4242, libraries=(libproc, FakeLibSystem()))
        libproc.exit_abstime = 999
        with self.assertRaises(SamplerError):
            sampler.sample()

    def test_failed_call_raises(self):
        libproc = FakeLibproc()
        libproc.proc_pid_rusage = lambda *a: -1
        with self.assertRaises(SamplerError):
            darwin.Sampler(4242, libraries=(libproc, FakeLibSystem()))

    def test_fd_buffer_is_bounded(self):
        libproc = FakeLibproc()
        libproc.proc_pidinfo_orig = libproc.proc_pidinfo

        def huge(pid, flavor, arg, buf, size):
            if flavor == darwin.PROC_PIDLISTFDS and buf is None:
                return 1 << 40
            return libproc.proc_pidinfo_orig(pid, flavor, arg, buf, size)

        libproc.proc_pidinfo = huge
        sampler = darwin.Sampler(4242, libraries=(libproc, FakeLibSystem()))
        with self.assertRaises(SamplerError):
            sampler.sample()


class FakeKernel32:
    """Stands in for WinDLL("kernel32"); fields follow the documented structures."""

    def __init__(self, private_ws=40 * MIB, creation=(1, 2), kernel=(3_000_000, 0), user=(1_000_000, 0),
                 handles=130, threads=9, pid=4242, exit_code=259):
        self.private_ws, self.creation, self.kernel, self.user = private_ws, creation, kernel, user
        self.handles, self.threads, self.pid, self.exit_code = handles, threads, pid, exit_code
        self.calls = []
        self.closed = []

    def OpenProcess(self, access, inherit, pid):
        self.calls.append(("OpenProcess", access, inherit, pid))
        return 0x1234

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return 1

    def GetProcessTimes(self, handle, creation, exit_, kernel, user):
        for arg, (low, high) in ((creation, self.creation), (kernel, self.kernel), (user, self.user)):
            _target(arg).dwLowDateTime = low
            _target(arg).dwHighDateTime = high
        return 1

    def GetExitCodeProcess(self, handle, code):
        _target(code).value = self.exit_code
        return 1

    def K32GetProcessMemoryInfo(self, handle, counters, cb):
        self.calls.append(("K32GetProcessMemoryInfo", cb, _target(counters).cb))
        _target(counters).PrivateWorkingSetSize = self.private_ws
        return 1

    def GetProcessHandleCount(self, handle, count):
        _target(count).value = self.handles
        return 1

    def CreateToolhelp32Snapshot(self, flags, pid):
        self.calls.append(("CreateToolhelp32Snapshot", flags, pid))
        self._entries = [(4, 1), (self.pid, self.threads)]
        return 0x5678

    def Process32FirstW(self, snap, entry):
        self.calls.append(("Process32FirstW", _target(entry).dwSize))
        self._index = 0
        return self._fill(entry)

    def Process32NextW(self, snap, entry):
        self._index += 1
        return self._fill(entry)

    def _fill(self, entry):
        if self._index >= len(self._entries):
            return 0
        pid, threads = self._entries[self._index]
        _target(entry).th32ProcessID = pid
        _target(entry).cntThreads = threads
        return 1


class WindowsPureTests(unittest.TestCase):
    def test_structure_sizes(self):
        self.assertEqual(ctypes.sizeof(windows.PROCESS_MEMORY_COUNTERS_EX2), 96)
        self.assertEqual(windows.EX2_SIZE, 96)
        self.assertEqual(ctypes.sizeof(windows.PROCESSENTRY32W), 568)
        self.assertEqual(ctypes.sizeof(windows.MEMORYSTATUSEX), 64)
        self.assertEqual(ctypes.sizeof(windows.FILETIME), 8)

    def test_kernel32_loaded_as_known_dll(self):
        seen = []

        class Fn:
            pass

        class Lib:
            def __getattr__(self, name):
                fn = Fn()
                setattr(self, name, fn)
                return fn

        def fake_windll(name, use_last_error=False):
            seen.append((name, use_last_error))
            return Lib()

        with mock.patch.object(windows.ctypes, "WinDLL", fake_windll, create=True):
            windows._load_kernel32()
        self.assertEqual(seen, [("kernel32", True)])

    def test_filetime_to_ns(self):
        ft = windows.FILETIME(5, 1)
        self.assertEqual(windows.filetime_to_ns(ft), ((1 << 32) + 5) * 100)

    def test_sampler_with_fake_kernel32(self):
        k = FakeKernel32()
        with windows.Sampler(4242, kernel32=k) as sampler:
            s = sampler.sample()
        self.assertEqual(s.footprint_bytes, 40 * MIB)
        self.assertEqual(s.footprint_metric, "private_working_set")
        self.assertEqual(s.cpu_ns, 4_000_000 * 100)
        self.assertEqual(s.threads, 9)
        self.assertEqual(s.descriptors, 130)
        self.assertEqual(s.descriptor_kind, "handle")
        self.assertIn(("OpenProcess", windows.PROCESS_QUERY_LIMITED_INFORMATION, False, 4242), k.calls)
        self.assertIn(("K32GetProcessMemoryInfo", 96, 96), k.calls)
        self.assertIn(("CreateToolhelp32Snapshot", windows.TH32CS_SNAPPROCESS, 0), k.calls)
        self.assertIn(("Process32FirstW", 568), k.calls)
        self.assertIn(0x1234, k.closed)
        self.assertIn(0x5678, k.closed)

    def test_zero_private_working_set_raises(self):
        k = FakeKernel32(private_ws=0)
        sampler = windows.Sampler(4242, kernel32=k)
        with self.assertRaisesRegex(SamplerError, "PrivateWorkingSetSize"):
            sampler.sample()

    def test_structure_size_checked_before_call(self):
        k = FakeKernel32()
        sampler = windows.Sampler(4242, kernel32=k)
        with mock.patch.object(windows, "EX2_SIZE", 95):
            with self.assertRaises(SamplerError):
                sampler.sample()
        self.assertFalse([c for c in k.calls if c[0] == "K32GetProcessMemoryInfo"])

    def test_exited_process_is_a_failed_sample(self):
        k = FakeKernel32()
        sampler = windows.Sampler(4242, kernel32=k)
        k.exit_code = 0
        with self.assertRaises(SamplerError):
            sampler.sample()

    def test_creation_time_change_is_detected(self):
        k = FakeKernel32()
        sampler = windows.Sampler(4242, kernel32=k)
        k.creation = (9, 9)
        with self.assertRaisesRegex(SamplerError, "start time"):
            sampler.sample()

    def test_missing_snapshot_entry_raises(self):
        k = FakeKernel32(pid=1)
        sampler = windows.Sampler(4242, kernel32=k)
        with self.assertRaises(SamplerError):
            sampler.sample()

    def test_version_key(self):
        self.assertEqual(windows.os_version_key(("2025Server", "10.0.26100", "", "Multiprocessor Free")), "10.0.26100")
        with self.assertRaises(SamplerError):
            windows.os_version_key(("", "", "", ""))


class LinuxVersionKeyTests(unittest.TestCase):
    def test_version_id(self):
        self.assertEqual(linux.os_version_key({"VERSION_ID": "22.04", "PRETTY_NAME": "Ubuntu"}), "22.04")
        with self.assertRaises(SamplerError):
            linux.os_version_key({"PRETTY_NAME": "Ubuntu"})


class CurrentTests(unittest.TestCase):
    def test_current_matches_platform(self):
        expected = {"linux": linux, "darwin": darwin, "win32": windows}[sys.platform]
        self.assertIs(samplers.current(), expected)


if __name__ == "__main__":
    unittest.main()
