//! `mach_timebase_info` conversion against the wall clock (spec section 7).
//! This binary holds exactly one test, so no other test competes for the
//! CPU while the busy loop measures; the ratio is of this process's CPU
//! time, which only this thread accrues meanwhile.
#![cfg(target_os = "macos")]

use ricevanta_os::ProcessSampler;
use ricevanta_os_macos::MacSampler;
use std::time::{Duration, Instant};

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
