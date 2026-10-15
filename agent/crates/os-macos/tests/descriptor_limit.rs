//! Native refusal when the fixed descriptor-list buffer fills.
#![cfg(target_os = "macos")]

use ricevanta_os::{ProcessSampler, SampleError};
use ricevanta_os_macos::MacSampler;

#[test]
fn full_descriptor_buffer_is_unsupported() {
    let sampler = MacSampler::new().unwrap();
    // 512 eight-byte proc_fdinfo records fill the 4 KiB caller buffer.
    let held: Vec<_> = (0..512)
        .map(|_| std::fs::File::open("/dev/null").unwrap())
        .collect();
    assert_eq!(sampler.sample(), Err(SampleError::Unsupported));
    drop(held);
    assert!(
        sampler.sample().is_ok(),
        "overflow must not retain descriptors"
    );
}
