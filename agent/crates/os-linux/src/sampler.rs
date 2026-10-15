//! The `/proc/self` process sampler.

use crate::procfs::{
    BUFFER_BYTES, SMAPS_ROLLUP, STAT, STATUS, parse_smaps_rollup_pss, parse_stat_cpu,
    parse_status_threads, read_bounded, ticks_to_ms,
};
use ricevanta_os::{Descriptors, FootprintMetric, ProcessSample, ProcessSampler, SampleError};

const FD_DIR: &str = "/proc/self/fd";

/// Samples the own process from `/proc/self`: `Pss` from `smaps_rollup`,
/// `utime` and `stime` from `stat`, `Threads` from `status` and the entry
/// count of `fd`. Each source is read into one fixed stack buffer; only the
/// directory iteration allocates, a small amount per entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxSampler {
    _private: (),
}

impl LinuxSampler {
    /// A sampler of the calling process.
    pub const fn new() -> LinuxSampler {
        LinuxSampler { _private: () }
    }
}

impl ProcessSampler for LinuxSampler {
    fn sample(&self) -> Result<ProcessSample, SampleError> {
        let mut buffer = [0u8; BUFFER_BYTES];
        let footprint_bytes = parse_smaps_rollup_pss(read_bounded(SMAPS_ROLLUP, &mut buffer)?)?;
        let (utime, stime) = parse_stat_cpu(read_bounded(STAT, &mut buffer)?)?;
        let threads = parse_status_threads(read_bounded(STATUS, &mut buffer)?)?;
        let overflow = SampleError::Format { source: STAT };
        let cpu_user_ms = ticks_to_ms(utime).ok_or(overflow)?;
        let cpu_system_ms = ticks_to_ms(stime).ok_or(overflow)?;
        let mut fds = 0u64;
        for entry in std::fs::read_dir(FD_DIR).map_err(|e| SampleError::io(&e))? {
            entry.map_err(|e| SampleError::io(&e))?;
            fds = fds.saturating_add(1);
        }
        Ok(ProcessSample {
            footprint_bytes,
            footprint_metric: FootprintMetric::Pss,
            cpu_user_ms,
            cpu_system_ms,
            threads,
            descriptors: Descriptors::Fds(fds),
        })
    }
}
