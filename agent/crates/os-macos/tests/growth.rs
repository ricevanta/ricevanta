//! Steady-state memory of the sampler (spec section 7), measured as
//! `ri_phys_footprint`. This binary holds exactly one test, so no other test
//! allocates while it measures.
#![cfg(target_os = "macos")]

use ricevanta_os::ProcessSampler;
use ricevanta_os_macos::MacSampler;

const WARM_UP: usize = 1_000;
const SAMPLES: usize = 10_000;
const LIMIT_BYTES: u64 = 64 * 1024;

#[test]
fn sampling_does_not_grow_private_memory() {
    let sampler = MacSampler::new().unwrap();
    for _ in 0..WARM_UP {
        sampler.sample().unwrap();
    }
    let before = sampler.sample().unwrap().footprint_bytes;
    let started = std::time::Instant::now();
    for _ in 0..SAMPLES {
        sampler.sample().unwrap();
    }
    let elapsed = started.elapsed();
    let after = sampler.sample().unwrap().footprint_bytes;
    let growth = after.saturating_sub(before);
    eprintln!(
        "growth: warm_up={WARM_UP} samples={SAMPLES} phys_footprint_before={before} \
         phys_footprint_after={after} growth={growth} limit={LIMIT_BYTES} elapsed={elapsed:?}"
    );
    assert!(
        growth <= LIMIT_BYTES,
        "ri_phys_footprint grew by {growth} bytes over {SAMPLES} samples"
    );
}
