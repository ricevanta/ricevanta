//! `/proc/self` parsing against recorded fixtures, and a live sample of the
//! test process.
#![cfg(target_os = "linux")]

use ricevanta_os::{Descriptors, FootprintMetric, ProcessSampler, SampleError};
use ricevanta_os_linux::LinuxSampler;
use ricevanta_os_linux::procfs::{
    USER_HZ, parse_smaps_rollup_pss, parse_stat_cpu, parse_status_euid, parse_status_threads,
    ticks_to_ms,
};
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
    assert_eq!(parse_status_threads(STATUS), Ok(7));
    assert!(matches!(
        parse_status_threads(STATUS_NO_THREADS),
        Err(SampleError::Format { .. })
    ));
    assert!(matches!(
        parse_status_threads(b"Threads:\t0\n"),
        Err(SampleError::Format { .. })
    ));
    assert_eq!(parse_status_euid(STATUS), Ok(1001));
    assert!(parse_status_euid(b"Uid:\t1\n").is_err());
    assert!(parse_status_euid(b"Name:\tx\n").is_err());
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
    match sample.descriptors {
        Descriptors::Fds(n) => assert!(n >= 3, "fd_count {n}"),
        other => panic!("Linux reports file descriptors, got {other:?}"),
    }
    eprintln!("live sample {sample:?} in {elapsed:?}");
}
