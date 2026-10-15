//! Steady-state memory of the sampler (spec section 7). This binary holds
//! exactly one test, so no other test allocates while it measures.
#![cfg(target_os = "linux")]

use ricevanta_os::ProcessSampler;
use ricevanta_os_linux::LinuxSampler;

const WARM_UP: usize = 1_000;
const SAMPLES: usize = 10_000;
const LIMIT_BYTES: u64 = 64 * 1024;

/// `Anonymous` from `/proc/self/smaps_rollup` in bytes, parsed here
/// independently of the crate's readers.
fn anonymous_bytes() -> u64 {
    let text = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
    let line = text
        .lines()
        .find(|l| l.starts_with("Anonymous:"))
        .expect("Anonymous line");
    let mut parts = line.split_whitespace().skip(1);
    let kib: u64 = parts.next().unwrap().parse().unwrap();
    assert_eq!(parts.next(), Some("kB"));
    kib * 1024
}

#[test]
fn sampling_does_not_grow_private_memory() {
    let sampler = LinuxSampler::new();
    for _ in 0..WARM_UP {
        sampler.sample().unwrap();
    }
    let before = anonymous_bytes();
    let started = std::time::Instant::now();
    for _ in 0..SAMPLES {
        sampler.sample().unwrap();
    }
    let elapsed = started.elapsed();
    let after = anonymous_bytes();
    let growth = after.saturating_sub(before);
    eprintln!(
        "growth: warm_up={WARM_UP} samples={SAMPLES} anonymous_before={before} \
         anonymous_after={after} growth={growth} limit={LIMIT_BYTES} elapsed={elapsed:?}"
    );
    assert!(
        growth <= LIMIT_BYTES,
        "Anonymous grew by {growth} bytes over {SAMPLES} samples"
    );
}
