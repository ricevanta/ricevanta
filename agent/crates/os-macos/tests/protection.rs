//! Descriptor-based file protection of spec section 3.1 on macOS: the same
//! cases as on Linux, run against `openat`, `mkdirat`, `renameat` and
//! `unlinkat`.
#![cfg(target_os = "macos")]

use ricevanta_os_macos::MacPlatform as TestPlatform;

fn platform() -> TestPlatform {
    TestPlatform::new().unwrap()
}

include!("../../os-linux/tests/support/unix_protection.rs");

#[test]
fn platform_constants() {
    let p = platform();
    assert_eq!(p.os(), ricevanta_os::Os::MacOs);
    assert_eq!(
        p.footprint_metric(),
        ricevanta_os::FootprintMetric::PhysFootprint
    );
    assert_eq!(
        p.data_root(),
        Ok(Some(PathBuf::from(
            "/Library/Application Support/Ricevanta"
        )))
    );
    assert_eq!(p.program_data(), Ok(None));
    let paths = p.default_paths().unwrap().unwrap();
    assert_eq!(
        paths.config_file,
        Path::new("/Library/Application Support/Ricevanta/agent.json")
    );
    let _: Option<File> = None;
}
