//! The Windows self-sampler (spec section 7).
#![cfg(windows)]

use ricevanta_os::{Descriptors, FootprintMetric, ProcessSampler};
use ricevanta_os_windows::{WindowsSampler, private_usage_bytes};
use std::time::{Duration, Instant};

#[test]
fn live_sample_of_own_process() {
    let sampler = WindowsSampler::new();
    let started = Instant::now();
    let sample = sampler
        .sample()
        .expect("PrivateWorkingSetSize needs the 2023 servicing baseline");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "sample took {elapsed:?}"
    );
    assert_eq!(sample.footprint_metric, FootprintMetric::PrivateWorkingSet);
    assert!(sample.footprint_bytes > 0);
    assert!(sample.threads >= 1);
    match sample.descriptors {
        Descriptors::Handles(n) => assert!(n > 0, "handle_count {n}"),
        other => panic!("Windows reports handles, got {other:?}"),
    }
    assert!(private_usage_bytes().unwrap() > 0);
    // A new thread is counted.
    let (send, receive) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || receive.recv().ok());
    let with_thread = sampler.sample().unwrap();
    assert!(with_thread.threads > sample.threads || with_thread.threads >= 2);
    drop(send);
    worker.join().unwrap();
    eprintln!("live sample {sample:?} in {elapsed:?}");
}
