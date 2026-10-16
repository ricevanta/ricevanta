//! Pure conversions of the Windows sampler, tested on every host.

use ricevanta_os::SampleError;

/// The footprint from `PROCESS_MEMORY_COUNTERS_EX2.PrivateWorkingSetSize`.
/// Zero means the OS build predates the member (it fills only the older
/// counters), which is reported as [`SampleError::Unsupported`], the rule
/// the footprint harness applies too (spec section 7).
pub fn private_working_set_footprint(bytes: u64) -> Result<u64, SampleError> {
    if bytes == 0 {
        Err(SampleError::Unsupported)
    } else {
        Ok(bytes)
    }
}

/// Converts `GetProcessTimes` 100-nanosecond units to milliseconds.
pub fn filetime_to_ms(units_100ns: u64) -> u64 {
    units_100ns / 10_000
}
