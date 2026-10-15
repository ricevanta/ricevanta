//! Pure conversions of the Windows sampler; run on every host.

use ricevanta_os::SampleError;
use ricevanta_os_windows::convert::{filetime_to_ms, private_working_set_footprint};

#[test]
fn zero_private_working_set_is_unsupported() {
    assert_eq!(
        private_working_set_footprint(0),
        Err(SampleError::Unsupported)
    );
    assert_eq!(private_working_set_footprint(4096), Ok(4096));
}

#[test]
fn filetime_units_are_100_ns() {
    assert_eq!(filetime_to_ms(0), 0);
    assert_eq!(filetime_to_ms(9_999), 0);
    assert_eq!(filetime_to_ms(10_000), 1);
    assert_eq!(filetime_to_ms(u64::MAX), u64::MAX / 10_000);
}
