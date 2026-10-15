//! The `/proc/self` process sampler.

use crate::procfs::{
    BUFFER_BYTES, SMAPS_ROLLUP, STAT, STATUS, open, parse_smaps_rollup_pss, parse_stat_cpu,
    read_bounded, status_threads, ticks_to_ms,
};
use ricevanta_os::{Descriptors, FootprintMetric, ProcessSample, ProcessSampler, SampleError};

const FD_DIR: &str = "/proc/self/fd";

/// Samples the own process from `/proc/self`: `Pss` from `smaps_rollup`,
/// `utime` and `stime` from `stat`, `Threads` from `status` and the entry
/// count of `fd`. `smaps_rollup` and `stat` are read whole into one fixed
/// stack buffer, `status` is scanned line by line through another, and only
/// the directory iteration allocates, a small amount per entry.
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
        let smaps = read_bounded(open(SMAPS_ROLLUP)?, &mut buffer, SMAPS_ROLLUP)?;
        let footprint_bytes = parse_smaps_rollup_pss(smaps)?;
        let (utime, stime) = parse_stat_cpu(read_bounded(open(STAT)?, &mut buffer, STAT)?)?;
        let threads = status_threads(open(STATUS)?)?;
        let overflow = || SampleError::Format { source: STAT };
        let cpu_user_ms = ticks_to_ms(utime).ok_or_else(overflow)?;
        let cpu_system_ms = ticks_to_ms(stime).ok_or_else(overflow)?;
        Ok(ProcessSample {
            footprint_bytes,
            footprint_metric: FootprintMetric::Pss,
            cpu_user_ms,
            cpu_system_ms,
            threads,
            descriptors: Descriptors::Fds(count_fds()?),
        })
    }
}

/// The process's open descriptors: the entries of `/proc/self/fd` minus the
/// one descriptor the listing itself holds open while it runs.
fn count_fds() -> Result<u64, SampleError> {
    let mut entries = 0u64;
    for entry in std::fs::read_dir(FD_DIR).map_err(SampleError::io)? {
        entry.map_err(SampleError::io)?;
        entries = entries.saturating_add(1);
    }
    // The listing's own descriptor is always among the entries.
    entries
        .checked_sub(1)
        .ok_or(SampleError::Format { source: FD_DIR })
}
