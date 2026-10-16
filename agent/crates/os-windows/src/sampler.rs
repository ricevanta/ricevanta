//! The Windows process sampler (spec section 7).

use crate::convert::{filetime_to_ms, private_working_set_footprint};
use crate::sys;
use ricevanta_os::{Descriptors, FootprintMetric, ProcessSample, ProcessSampler, SampleError};

/// Samples the own process: `GetProcessMemoryInfo` with
/// `PROCESS_MEMORY_COUNTERS_EX2.PrivateWorkingSetSize`, `GetProcessTimes`,
/// `GetProcessHandleCount`, and `cntThreads` of the own entry in a
/// `CreateToolhelp32Snapshot` process snapshot.
///
/// Memory bound (spec section 7), the property code review checks: every
/// call fills fixed stack values only; the snapshot walk holds one stack
/// `PROCESSENTRY32W` and one snapshot handle, closed before returning;
/// nothing is allocated by this crate, kept or cached between calls. The
/// snapshot itself is allocated and freed by the OS within the call. The
/// steady-state proof is the `growth` test binary with `PrivateUsage`, the
/// commit charge, as the measure.
#[derive(Debug, Clone, Copy)]
pub struct WindowsSampler {
    pid: u32,
}

impl WindowsSampler {
    /// A sampler of the calling process.
    pub fn new() -> WindowsSampler {
        WindowsSampler {
            pid: std::process::id(),
        }
    }
}

impl Default for WindowsSampler {
    fn default() -> WindowsSampler {
        WindowsSampler::new()
    }
}

fn os_error(error: std::io::Error) -> SampleError {
    match error.raw_os_error() {
        Some(code) => SampleError::Os { code },
        None => SampleError::io(error),
    }
}

/// The process's commit charge (`PrivateUsage`) in bytes, the growth test's
/// measure.
pub fn private_usage_bytes() -> Result<u64, SampleError> {
    sys::memory().map(|m| m.private_usage).map_err(os_error)
}

impl ProcessSampler for WindowsSampler {
    fn sample(&self) -> Result<ProcessSample, SampleError> {
        let memory = sys::memory().map_err(os_error)?;
        let footprint_bytes = private_working_set_footprint(memory.private_working_set)?;
        let (user, kernel) = sys::times().map_err(os_error)?;
        let handles = sys::handle_count().map_err(os_error)?;
        let threads = sys::thread_count(self.pid).map_err(os_error)?;
        if threads == 0 {
            return Err(SampleError::Format {
                source: "PROCESSENTRY32W",
            });
        }
        Ok(ProcessSample {
            footprint_bytes,
            footprint_metric: FootprintMetric::PrivateWorkingSet,
            cpu_user_ms: filetime_to_ms(user),
            cpu_system_ms: filetime_to_ms(kernel),
            threads,
            descriptors: Descriptors::Handles(u64::from(handles)),
        })
    }
}
