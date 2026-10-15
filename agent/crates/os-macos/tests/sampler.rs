//! The macOS self-sampler (spec section 7).
#![cfg(target_os = "macos")]

use ricevanta_os::{Descriptors, FootprintMetric, ProcessSampler, SampleError};
use ricevanta_os_macos::{MacSampler, RUSAGE_INFO_V4_BYTES};
use std::time::{Duration, Instant};

#[test]
fn rusage_info_v4_layout() {
    assert_eq!(RUSAGE_INFO_V4_BYTES, 296);
    assert_eq!(std::mem::size_of::<libc::rusage_info_v4>(), 16 + 35 * 8);
}

#[test]
fn live_sample_of_own_process() {
    let sampler = MacSampler::new().unwrap();
    let _held: Vec<_> = (0..3)
        .map(|_| std::fs::File::open("/dev/null").unwrap())
        .collect();
    let started = Instant::now();
    let sample = sampler.sample().unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "sample took {elapsed:?}"
    );
    assert_eq!(sample.footprint_metric, FootprintMetric::PhysFootprint);
    assert!(sample.footprint_bytes > 0);
    assert!(sample.threads >= 1);
    let fds = match sample.descriptors {
        Descriptors::Fds(n) => n,
        other => panic!("macOS reports file descriptors, got {other:?}"),
    };
    assert!(fds >= 6, "fd_count {fds}");
    let extra = std::fs::File::open("/dev/null").unwrap();
    let after = match sampler.sample().unwrap().descriptors {
        Descriptors::Fds(n) => n,
        other => panic!("{other:?}"),
    };
    drop(extra);
    assert_eq!(after, fds + 1);
    eprintln!("live sample {sample:?} in {elapsed:?}");
}

#[test]
fn invalid_pid_is_an_os_error() {
    // Pid 0 is the kernel task; i32::MAX is never a live pid.
    let sampler = MacSampler::for_pid(i32::MAX).unwrap();
    let result = sampler.sample();
    assert!(matches!(result, Err(SampleError::Os { .. })), "{result:?}");
}

#[test]
fn mach_time_conversion_matches_the_wall_clock() {
    // A single-threaded busy loop accrues CPU time at the wall-clock rate;
    // the converted user plus system time must agree within 5 %.
    let sampler = MacSampler::new().unwrap();
    let before = sampler.sample().unwrap();
    let started = Instant::now();
    let mut x = 0u64;
    while started.elapsed() < Duration::from_millis(1_000) {
        x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
    let wall = started.elapsed().as_millis() as f64;
    let after = sampler.sample().unwrap();
    let cpu = ((after.cpu_user_ms + after.cpu_system_ms)
        - (before.cpu_user_ms + before.cpu_system_ms)) as f64;
    let ratio = cpu / wall;
    eprintln!("busy loop: wall {wall} ms, cpu {cpu} ms, ratio {ratio:.3}");
    assert!((0.95..=1.05).contains(&ratio), "ratio {ratio}");
    assert_eq!(sampler.mach_to_ns(0), Some(0));
}
