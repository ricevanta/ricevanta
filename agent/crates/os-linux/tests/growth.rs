//! Steady-state memory of the sampler (spec section 7). This binary holds
//! exactly one test, so no other test allocates while it measures.
#![cfg(target_os = "linux")]

use ricevanta_os::{Descriptors, ProcessSampler, SampleError};

// Compile the production iterator consumer into this dedicated process so
// errors can be injected without a public sampler hook or another test.
#[path = "../src/fd_count.rs"]
mod fd_count;
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

fn measure(label: &str, mut sample: impl FnMut()) {
    for _ in 0..WARM_UP {
        sample();
    }
    let before = anonymous_bytes();
    let started = std::time::Instant::now();
    for _ in 0..SAMPLES {
        sample();
    }
    let elapsed = started.elapsed();
    let after = anonymous_bytes();
    let growth = after.saturating_sub(before);
    eprintln!(
        "growth: case={label} warm_up={WARM_UP} samples={SAMPLES} anonymous_before={before} anonymous_after={after} growth={growth} limit={LIMIT_BYTES} elapsed={elapsed:?}"
    );
    assert!(
        growth <= LIMIT_BYTES,
        "{label}: Anonymous grew by {growth} bytes"
    );
}

#[test]
fn sampling_does_not_grow_private_memory() {
    let sampler = LinuxSampler::new();
    measure("baseline", || {
        sampler.sample().unwrap();
    });
    let baseline = match sampler.sample().unwrap().descriptors {
        Descriptors::Fds(n) => n,
        other => panic!("{other:?}"),
    };
    let held: Vec<_> = (0..2048)
        .map(|_| std::fs::File::open("/dev/null").unwrap())
        .collect();
    measure("2048-held-descriptors", || {
        assert_eq!(
            sampler.sample().unwrap().descriptors,
            Descriptors::Fds(baseline + 2048)
        );
    });
    for fail_at in [0, 1024, 2048] {
        measure("enumeration-failure", || {
            let entries =
                std::fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .enumerate()
                    .map(|(index, entry)| {
                        if index == fail_at {
                            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                        } else {
                            entry
                        }
                    });
            assert!(
                matches!(fd_count::count_entries(Ok(entries)), Err(SampleError::Io(ref cause)) if cause.kind() == std::io::ErrorKind::PermissionDenied)
            );
        });
        // An early return must release the ReadDir, including its descriptor.
        assert_eq!(
            sampler.sample().unwrap().descriptors,
            Descriptors::Fds(baseline + 2048)
        );
    }
    measure("open-failure", || {
        let entries =
            Err::<std::fs::ReadDir, _>(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(matches!(
            fd_count::count_entries(entries),
            Err(SampleError::Io(_))
        ));
    });
    drop(held);
    assert_eq!(
        sampler.sample().unwrap().descriptors,
        Descriptors::Fds(baseline)
    );
}
