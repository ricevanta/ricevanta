//! Parsers for the `/proc/self` sources of the Linux sampler.
//!
//! Every parser takes a borrowed byte slice, allocates nothing and returns
//! [`SampleError::Format`] for any input that does not have the documented
//! form. Numbers are ASCII decimal digits only: no sign, no whitespace.

use ricevanta_os::SampleError;
use std::fs::File;
use std::io::Read;

/// The kernel's fixed `USER_HZ` for user interfaces (uapi `asm-generic/param.h`).
pub const USER_HZ: u64 = 100;
/// Size of each fixed read buffer; `/proc/self/stat` and `smaps_rollup` are
/// far smaller, and `status` holds `Uid` and `Threads` well inside it.
pub const BUFFER_BYTES: usize = 4096;

pub(crate) const STAT: &str = "/proc/self/stat";
pub(crate) const SMAPS_ROLLUP: &str = "/proc/self/smaps_rollup";
pub(crate) const STATUS: &str = "/proc/self/status";

/// Converts `USER_HZ` ticks to milliseconds; `None` on overflow.
pub fn ticks_to_ms(ticks: u64) -> Option<u64> {
    ticks.checked_mul(1000 / USER_HZ)
}

fn format(source: &'static str) -> SampleError {
    SampleError::Format { source }
}

fn digits(field: &[u8], source: &'static str) -> Result<u64, SampleError> {
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return Err(format(source));
    }
    field.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(d - b'0')))
            .ok_or(format(source))
    })
}

fn fields(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|b| matches!(b, b' ' | b'\t' | b'\n'))
        .filter(|f| !f.is_empty())
}

/// The value of the line `name` (for example `b"Threads:"`), which must start
/// a line.
fn line_value<'a>(bytes: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    bytes
        .split(|&b| b == b'\n')
        .find_map(|line| line.strip_prefix(name))
}

/// `utime` and `stime` (fields 14 and 15, in ticks) from `/proc/self/stat`.
///
/// Fields are counted after the last `)`, so a `comm` holding spaces or
/// parentheses cannot shift them.
pub fn parse_stat_cpu(bytes: &[u8]) -> Result<(u64, u64), SampleError> {
    let close = bytes.iter().rposition(|&b| b == b')').ok_or(format(STAT))?;
    // After `)` the first field is field 3 (`state`), so field 14 is the
    // twelfth.
    let mut rest = fields(&bytes[close + 1..]).skip(11);
    let utime = digits(rest.next().ok_or(format(STAT))?, STAT)?;
    let stime = digits(rest.next().ok_or(format(STAT))?, STAT)?;
    Ok((utime, stime))
}

/// The `Pss:` line of `/proc/self/smaps_rollup`, in bytes.
pub fn parse_smaps_rollup_pss(bytes: &[u8]) -> Result<u64, SampleError> {
    let value = line_value(bytes, b"Pss:").ok_or(format(SMAPS_ROLLUP))?;
    let mut parts = fields(value);
    let kib = digits(parts.next().ok_or(format(SMAPS_ROLLUP))?, SMAPS_ROLLUP)?;
    if parts.next() != Some(b"kB") || parts.next().is_some() {
        return Err(format(SMAPS_ROLLUP));
    }
    kib.checked_mul(1024).ok_or(format(SMAPS_ROLLUP))
}

/// The `Threads:` line of `/proc/self/status`; zero is a format error.
pub fn parse_status_threads(bytes: &[u8]) -> Result<u32, SampleError> {
    let value = line_value(bytes, b"Threads:").ok_or(format(STATUS))?;
    let mut parts = fields(value);
    let n = digits(parts.next().ok_or(format(STATUS))?, STATUS)?;
    if parts.next().is_some() || n == 0 {
        return Err(format(STATUS));
    }
    u32::try_from(n).map_err(|_| format(STATUS))
}

/// The effective uid, the second of the four `Uid:` fields of
/// `/proc/self/status`.
pub fn parse_status_euid(bytes: &[u8]) -> Result<u32, SampleError> {
    let value = line_value(bytes, b"Uid:").ok_or(format(STATUS))?;
    let mut parts = fields(value);
    let mut ids = [0u64; 4];
    for id in &mut ids {
        *id = digits(parts.next().ok_or(format(STATUS))?, STATUS)?;
    }
    if parts.next().is_some() {
        return Err(format(STATUS));
    }
    u32::try_from(ids[1]).map_err(|_| format(STATUS))
}

/// Reads at most `buffer.len()` bytes of `path` into `buffer`.
pub(crate) fn read_bounded<'a>(
    path: &'static str,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], SampleError> {
    let mut file = File::open(path).map_err(|e| SampleError::io(&e))?;
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SampleError::io(&e)),
        }
    }
    Ok(&buffer[..filled])
}
