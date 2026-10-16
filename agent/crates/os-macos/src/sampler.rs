//! The macOS process sampler (spec section 7).

use crate::sys;
use ricevanta_os::{Descriptors, FootprintMetric, ProcessSample, ProcessSampler, SampleError};

/// Samples a process with `proc_pid_rusage(RUSAGE_INFO_V4)` (footprint
/// `ri_phys_footprint` and CPU times in Mach absolute time units, converted
/// with `mach_timebase_info`), `proc_pidinfo(PROC_PIDTASKINFO)` (threads)
/// and `proc_pidinfo(PROC_PIDLISTFDS)` (descriptors).
///
/// Memory bound (spec section 7), the property code review checks: every
/// call fills fixed stack values only, the descriptor list included, whose
/// buffer is 4 KiB ([`sys::FD_ENTRIES`] entries); nothing is allocated, kept
/// or grown, and nothing is cached between calls except the time base read
/// once at construction. A process with so many descriptors that the buffer
/// fills reports a sampler failure rather than a cut count. The steady-state
/// proof is the `growth` test binary with `ri_phys_footprint` as the measure.
#[derive(Debug, Clone, Copy)]
pub struct MacSampler {
    pid: i32,
    numer: u32,
    denom: u32,
}

impl MacSampler {
    /// A sampler of the calling process.
    pub fn new() -> Result<MacSampler, SampleError> {
        let pid = i32::try_from(std::process::id()).map_err(|_| SampleError::Unsupported)?;
        MacSampler::for_pid(pid)
    }

    /// A sampler of `pid`. Sampling another process needs the privilege
    /// `proc_pid_rusage` requires; the agent samples only itself.
    pub fn for_pid(pid: i32) -> Result<MacSampler, SampleError> {
        let (numer, denom) = sys::timebase().map_err(os_error)?;
        Ok(MacSampler { pid, numer, denom })
    }

    /// Converts Mach absolute time units to nanoseconds; `None` on overflow.
    pub fn mach_to_ns(&self, ticks: u64) -> Option<u64> {
        let ns = u128::from(ticks) * u128::from(self.numer) / u128::from(self.denom);
        u64::try_from(ns).ok()
    }
}

pub(crate) fn os_error(error: std::io::Error) -> SampleError {
    match error.raw_os_error() {
        Some(code) => SampleError::Os { code },
        None => SampleError::io(error),
    }
}

impl ProcessSampler for MacSampler {
    fn sample(&self) -> Result<ProcessSample, SampleError> {
        let usage = sys::rusage_v4(self.pid).map_err(os_error)?;
        let task = sys::task_info(self.pid).map_err(os_error)?;
        let fd_bytes = sys::listed_fd_bytes(self.pid)?;
        let entry = std::mem::size_of::<libc::proc_fdinfo>();
        let overflow = || SampleError::Format {
            source: "rusage_info_v4",
        };
        let to_ms = |ticks| self.mach_to_ns(ticks).map(|ns| ns / 1_000_000);
        let threads = u32::try_from(task.pti_threadnum)
            .ok()
            .filter(|&n| n > 0)
            .ok_or(SampleError::Format {
                source: "proc_taskinfo",
            })?;
        Ok(ProcessSample {
            footprint_bytes: usage.ri_phys_footprint,
            footprint_metric: FootprintMetric::PhysFootprint,
            cpu_user_ms: to_ms(usage.ri_user_time).ok_or_else(overflow)?,
            cpu_system_ms: to_ms(usage.ri_system_time).ok_or_else(overflow)?,
            threads,
            descriptors: Descriptors::Fds((fd_bytes / entry) as u64),
        })
    }
}
