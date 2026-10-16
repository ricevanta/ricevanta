//! Streaming descriptor enumeration, with ownership covering every failure.

use ricevanta_os::SampleError;
use std::fs::DirEntry;
use std::io;

pub(crate) fn count_entries(
    entries: io::Result<impl Iterator<Item = io::Result<DirEntry>>>,
) -> Result<u64, SampleError> {
    let mut count = 0u64;
    for entry in entries.map_err(SampleError::io)? {
        entry.map_err(SampleError::io)?;
        count = count.saturating_add(1);
    }
    // The listing's own descriptor is always among the entries.
    count.checked_sub(1).ok_or(SampleError::Format {
        source: "/proc/self/fd",
    })
}
