//! Steady-state memory of the sampler (spec section 7), measured as
//! `PrivateUsage`, the commit charge. This binary holds exactly one test, so
//! no other test allocates while it measures.
#![cfg(windows)]

use ricevanta_os::ProcessSampler;
use ricevanta_os_windows::{WindowsSampler, private_usage_bytes};

const WARM_UP: usize = 1_000;
const SAMPLES: usize = 10_000;
const LIMIT_BYTES: u64 = 64 * 1024;

#[test]
fn sampling_does_not_grow_private_memory() {
    let sampler = WindowsSampler::new();
    for _ in 0..WARM_UP {
        sampler.sample().unwrap();
    }
    let before = private_usage_bytes().unwrap();
    let started = std::time::Instant::now();
    for _ in 0..SAMPLES {
        sampler.sample().unwrap();
    }
    let elapsed = started.elapsed();
    let after = private_usage_bytes().unwrap();
    let growth = after.saturating_sub(before);
    eprintln!(
        "growth: warm_up={WARM_UP} samples={SAMPLES} private_usage_before={before} \
         private_usage_after={after} growth={growth} limit={LIMIT_BYTES} elapsed={elapsed:?}"
    );
    assert!(
        growth <= LIMIT_BYTES,
        "PrivateUsage grew by {growth} bytes over {SAMPLES} samples"
    );
}
