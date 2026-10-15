//! Parsers for the `/proc/self` sources of the Linux sampler.
//!
//! Every parser reads a borrowed byte slice or a reader through a fixed
//! buffer, allocates nothing and returns
//! [`SampleError::Format`] for any input that does not have the documented
//! form. Numbers are ASCII decimal digits only: no sign, no whitespace.

use ricevanta_os::SampleError;
use std::fs::File;
use std::io::Read;

/// The kernel's fixed `USER_HZ` for user interfaces (uapi `asm-generic/param.h`).
pub const USER_HZ: u64 = 100;
/// Size of each fixed read buffer. `/proc/self/stat` and `smaps_rollup` must
/// fit in it whole; `status`, whose `Groups:` line grows with the number of
/// supplementary groups, is scanned line by line through it.
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

/// The `Threads:` line of `/proc/self/status`, read from `reader` line by
/// line through one fixed buffer; zero is a format error.
pub fn status_threads<R: Read>(reader: R) -> Result<u32, SampleError> {
    let mut buffer = [0u8; BUFFER_BYTES];
    let value = find_line(reader, &mut buffer, b"Threads:", STATUS)?;
    let mut parts = fields(value);
    let n = digits(parts.next().ok_or(format(STATUS))?, STATUS)?;
    if parts.next().is_some() || n == 0 {
        return Err(format(STATUS));
    }
    u32::try_from(n).map_err(|_| format(STATUS))
}

/// The effective uid, the second of the four `Uid:` fields of
/// `/proc/self/status`, read like [`status_threads`].
pub fn status_euid<R: Read>(reader: R) -> Result<u32, SampleError> {
    let mut buffer = [0u8; BUFFER_BYTES];
    let value = find_line(reader, &mut buffer, b"Uid:", STATUS)?;
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

/// Returns the rest of the first line of `reader` that starts with `name`,
/// scanning line by line through `buffer` and carrying a partial line
/// between reads, so the document may be any length.
///
/// A line longer than `buffer` is skipped, unless it is the requested line,
/// which is then a format error rather than a silently cut value. A missing
/// line is a format error.
pub fn find_line<'b, R: Read>(
    mut reader: R,
    buffer: &'b mut [u8],
    name: &[u8],
    source: &'static str,
) -> Result<&'b [u8], SampleError> {
    let mut len = 0;
    let mut skipping = false;
    let mut eof = false;
    loop {
        let mut start = 0;
        while let Some(offset) = buffer[start..len].iter().position(|&b| b == b'\n') {
            let end = start + offset;
            if skipping {
                skipping = false;
            } else if buffer[start..end].starts_with(name) {
                return Ok(&buffer[start + name.len()..end]);
            }
            start = end + 1;
        }
        if eof {
            if !skipping && buffer[start..len].starts_with(name) {
                return Ok(&buffer[start + name.len()..len]);
            }
            return Err(format(source));
        }
        buffer.copy_within(start..len, 0);
        len -= start;
        if len == buffer.len() {
            // One line fills the buffer.
            if !skipping && buffer.starts_with(name) {
                return Err(format(source));
            }
            skipping = true;
            len = 0;
        }
        match reader.read(&mut buffer[len..]) {
            Ok(0) => eof = true,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SampleError::io(e)),
        }
    }
}

/// Reads all of `reader` into `buffer`. A source that does not reach end of
/// file within `buffer.len()` bytes is a format error, never a cut document.
pub fn read_bounded<'a, R: Read>(
    mut reader: R,
    buffer: &'a mut [u8],
    source: &'static str,
) -> Result<&'a [u8], SampleError> {
    let mut filled = 0;
    loop {
        if filled == buffer.len() {
            let mut probe = [0u8; 1];
            match reader.read(&mut probe) {
                Ok(0) => return Ok(&buffer[..filled]),
                Ok(_) => return Err(format(source)),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(SampleError::io(e)),
            }
        }
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return Ok(&buffer[..filled]),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SampleError::io(e)),
        }
    }
}

/// Opens one of the `/proc/self` sources.
pub(crate) fn open(path: &'static str) -> Result<File, SampleError> {
    File::open(path).map_err(SampleError::io)
}
