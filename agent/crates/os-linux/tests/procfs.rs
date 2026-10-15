//! `/proc/self` parsing against recorded fixtures, and a live sample of the
//! test process.
#![cfg(target_os = "linux")]

use ricevanta_os::{Descriptors, FootprintMetric, ProcessSampler, SampleError};
use ricevanta_os_linux::LinuxSampler;
use ricevanta_os_linux::procfs::{
    BUFFER_BYTES, USER_HZ, find_line, parse_smaps_rollup_pss, parse_stat_cpu, read_bounded,
    status_euid, status_threads, ticks_to_ms,
};
use std::io::Read;
use std::time::{Duration, Instant};

const STAT_PLAIN: &[u8] = include_bytes!("fixtures/stat-plain");
const STAT_COMM_PARENS: &[u8] = include_bytes!("fixtures/stat-comm-parens");
const SMAPS: &[u8] = include_bytes!("fixtures/smaps_rollup");
const SMAPS_NO_PSS: &[u8] = include_bytes!("fixtures/smaps_rollup-no-pss");
const STATUS: &[u8] = include_bytes!("fixtures/status");
const STATUS_NO_THREADS: &[u8] = include_bytes!("fixtures/status-no-threads");

#[test]
fn stat_fields_follow_the_last_parenthesis() {
    assert_eq!(parse_stat_cpu(STAT_PLAIN), Ok((1234, 567)));
    // `comm` is "a) (b c": spaces and parentheses must not shift fields.
    assert_eq!(parse_stat_cpu(STAT_COMM_PARENS), Ok((1234, 567)));
    assert_eq!(USER_HZ, 100);
    assert_eq!(ticks_to_ms(1234), Some(12_340));
    assert_eq!(ticks_to_ms(u64::MAX), None);
}

#[test]
fn malformed_stat_is_a_format_error() {
    for bad in [
        &b""[..],
        b"1 (x R 1 2",
        b"1 (x) R 1 2 3",
        b"1 (x) R 0 0 0 0 0 0 0 0 0 0 abc 5 0",
        b"1 (x) R 0 0 0 0 0 0 0 0 0 0 -1 5 0",
        b"1 (x) R 0 0 0 0 0 0 0 0 0 0 99999999999999999999999 5 0",
        b"\xff\xfe",
    ] {
        assert!(
            matches!(parse_stat_cpu(bad), Err(SampleError::Format { .. })),
            "{bad:?}"
        );
    }
    assert_eq!(
        parse_stat_cpu(b"1 (x) R 0 0 0 0 0 0 0 0 0 0 7 8"),
        Ok((7, 8))
    );
}

#[test]
fn smaps_rollup_pss() {
    assert_eq!(parse_smaps_rollup_pss(SMAPS), Ok(361 * 1024));
    // Pss_Anon, Pss_File and friends are not `Pss`.
    assert!(matches!(
        parse_smaps_rollup_pss(SMAPS_NO_PSS),
        Err(SampleError::Format { .. })
    ));
    for bad in [
        &b"Pss: x kB\n"[..],
        b"Pss: 12 MB\n",
        b"Pss: 12\n",
        b"Pss: 18014398509481984 kB\n",
    ] {
        assert!(
            matches!(parse_smaps_rollup_pss(bad), Err(SampleError::Format { .. })),
            "{bad:?}"
        );
    }
}

#[test]
fn status_threads_and_euid() {
    assert_eq!(status_threads(STATUS), Ok(7));
    assert!(matches!(
        status_threads(STATUS_NO_THREADS),
        Err(SampleError::Format { .. })
    ));
    assert!(matches!(
        status_threads(&b"Threads:\t0\n"[..]),
        Err(SampleError::Format { .. })
    ));
    assert_eq!(status_euid(STATUS), Ok(1001));
    assert!(status_euid(&b"Uid:\t1\n"[..]).is_err());
    assert!(status_euid(&b"Name:\tx\n"[..]).is_err());
}

/// Hands out at most `chunk` bytes per read, so lines are cut between reads.
struct Chunked<'a> {
    rest: &'a [u8],
    chunk: usize,
}

impl Read for Chunked<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let n = self.rest.len().min(self.chunk).min(buffer.len());
        buffer[..n].copy_from_slice(&self.rest[..n]);
        self.rest = &self.rest[n..];
        Ok(n)
    }
}

/// A `status` document with 1,000 supplementary groups, as a host with
/// many groups produces: the `Groups:` line alone exceeds the buffer.
fn status_with_groups(threads: &str) -> Vec<u8> {
    let text = String::from_utf8(STATUS.to_vec()).unwrap();
    let groups: Vec<String> = (100_000..101_000).map(|g| g.to_string()).collect();
    let groups_line = format!("Groups:\t{}", groups.join(" "));
    let replaced: Vec<String> = text
        .lines()
        .map(|line| {
            if line.starts_with("Groups:") {
                groups_line.clone()
            } else if line.starts_with("Threads:") {
                format!("Threads:\t{threads}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    let document = replaced.join("\n") + "\n";
    assert!(document.len() > 2 * BUFFER_BYTES, "{}", document.len());
    document.into_bytes()
}

#[test]
fn status_larger_than_the_buffer() {
    let document = status_with_groups("12");
    assert_eq!(status_threads(&document[..]), Ok(12));
    assert_eq!(status_euid(&document[..]), Ok(1001));
    // Every cut position inside and around the `Threads:` line.
    let at = document.windows(8).position(|w| w == b"Threads:").unwrap();
    for chunk in [1, 2, 3, 5, 7, 11, 64, 4095, 4096, 4097] {
        let reader = Chunked {
            rest: &document,
            chunk,
        };
        assert_eq!(status_threads(reader), Ok(12), "chunk {chunk}");
    }
    for cut in at..at + 12 {
        // A reader that delivers everything up to `cut`, then the rest.
        let (head, tail) = document.split_at(cut);
        let reader = head.chain(tail);
        assert_eq!(status_threads(reader), Ok(12), "cut {cut}");
    }
}

#[test]
fn requested_line_longer_than_the_buffer_is_a_format_error() {
    let mut document = b"Name:\tx\nThreads:\t".to_vec();
    document.extend(std::iter::repeat_n(b'1', BUFFER_BYTES));
    document.extend_from_slice(b"\nUid:\t0\t0\t0\t0\n");
    assert!(matches!(
        status_threads(&document[..]),
        Err(SampleError::Format { .. })
    ));
    // Other overlong lines are skipped.
    assert_eq!(status_euid(&document[..]), Ok(0));
    let mut buffer = [0u8; 8];
    assert_eq!(
        find_line(
            &b"aaaaaaaaaaaaaaaaaaaa\nKey:v\n"[..],
            &mut buffer,
            b"Key:",
            "t"
        ),
        Ok(&b"v"[..])
    );
    // The final line needs no newline.
    assert_eq!(
        find_line(&b"a\nKey:end"[..], &mut buffer, b"Key:", "t"),
        Ok(&b"end"[..])
    );
}

#[test]
fn whole_sources_must_fit_the_buffer() {
    let mut buffer = [0u8; BUFFER_BYTES];
    let exact = vec![b'x'; BUFFER_BYTES];
    assert_eq!(
        read_bounded(&exact[..], &mut buffer, "src").map(<[u8]>::len),
        Ok(BUFFER_BYTES)
    );
    let over = vec![b'x'; BUFFER_BYTES + 1];
    assert!(matches!(
        read_bounded(&over[..], &mut buffer, "src"),
        Err(SampleError::Format { source: "src" })
    ));
    let chunked = Chunked {
        rest: &over,
        chunk: 100,
    };
    assert!(matches!(
        read_bounded(chunked, &mut buffer, "src"),
        Err(SampleError::Format { .. })
    ));
}

#[test]
fn live_sample_of_own_process() {
    let sampler = LinuxSampler::new();
    // Hold extra descriptors open so the count is not trivially satisfied.
    let _held: Vec<_> = (0..3)
        .map(|_| std::fs::File::open("/proc/self/stat").unwrap())
        .collect();
    let started = Instant::now();
    let sample = sampler.sample().unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "sample took {elapsed:?}"
    );
    assert_eq!(sample.footprint_metric, FootprintMetric::Pss);
    assert!(sample.footprint_bytes > 0);
    assert!(sample.threads >= 1);
    let fds = match sample.descriptors {
        Descriptors::Fds(n) => n,
        other => panic!("Linux reports file descriptors, got {other:?}"),
    };
    assert!(fds >= 6, "fd_count {fds}");
    // Independent oracle: since Linux 6.2 the size of /proc/self/fd is the
    // number of open descriptors, read without opening one.
    let size = std::fs::metadata("/proc/self/fd").unwrap().len();
    if size > 0 {
        assert_eq!(fds, size, "fd_count must exclude the listing descriptor");
    }
    // Opening one more descriptor raises the count by exactly one.
    let extra = std::fs::File::open("/proc/self/stat").unwrap();
    let after = match sampler.sample().unwrap().descriptors {
        Descriptors::Fds(n) => n,
        other => panic!("{other:?}"),
    };
    drop(extra);
    assert_eq!(after, fds + 1);
    eprintln!("live sample {sample:?} in {elapsed:?}");
}
