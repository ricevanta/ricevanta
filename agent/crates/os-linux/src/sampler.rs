//! The `/proc/self` process sampler.

use crate::procfs::{
    BUFFER_BYTES, SMAPS_ROLLUP, STAT, STATUS, open, parse_smaps_rollup_pss, parse_stat_cpu,
    read_bounded, status_threads, ticks_to_ms,
};
use ricevanta_os::{Descriptors, FootprintMetric, ProcessSample, ProcessSampler, SampleError};

const FD_DIR: &str = "/proc/self/fd";

/// Samples the own process from `/proc/self`: `Pss` from `smaps_rollup`,
/// `utime` and `stime` from `stat`, `Threads` from `status` and the entry
/// count of `fd`.
///
/// Memory bound (spec section 7), the property code review checks:
///
/// - Every reader uses a fixed stack buffer of [`BUFFER_BYTES`] (4 KiB):
///   `smaps_rollup` and `stat` are read whole into one, a source that does
///   not fit is unsupported, and `status` is scanned line by line through
///   another.
/// - No collection is kept or grown: nothing scales with the number of
///   mappings, descriptors or threads; the descriptor count is a counter.
/// - At most one directory enumeration is open at a time, `/proc/self/fd`;
///   its native storage remains a qualification gate;
///   each entry is dropped before the next is read.
/// - Each source file is opened and closed within the call; nothing is
///   cached between calls.
///
/// The steady-state evidence is the `growth` test binary: after 1,000 warm-up
/// samples, 10,000 more raise `Anonymous` in `/proc/self/smaps_rollup` by at
/// most 64 KiB, including high descriptor counts and injected failures.
/// This does not prove a transient native allocation bound. Section 7 still
/// requires qualified Rust/libc source evidence for directory-stream storage,
/// entry allocations, allocator overhead and retention. RAII drops the
/// ReadDir and each DirEntry on success and early error; no PathBuf is made.
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
    crate::fd_count::count_entries(std::fs::read_dir(FD_DIR))
}

#[cfg(test)]
mod tests {
    use crate::fd_count::count_entries;
    use ricevanta_os::SampleError;
    use std::io;

    #[test]
    fn enumeration_errors_are_not_partial_counts_and_release_the_stream() {
        let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        let opened = std::fs::read_dir("/proc/self/fd").unwrap();
        let entries = opened.enumerate().map(|(i, entry)| {
            if i == 1 {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                entry
            }
        });
        let result = count_entries(Ok(entries));
        assert!(
            matches!(result, Err(SampleError::Io(ref cause)) if cause.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
        let result = count_entries(Err::<std::fs::ReadDir, _>(io::Error::from(
            io::ErrorKind::PermissionDenied,
        )));
        assert!(matches!(result, Err(SampleError::Io(_))));
    }
}
