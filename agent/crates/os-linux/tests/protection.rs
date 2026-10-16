//! Descriptor-based file protection of spec section 3.1 on Linux.
#![cfg(target_os = "linux")]

use ricevanta_os_linux::LinuxPlatform as TestPlatform;

fn platform() -> TestPlatform {
    TestPlatform::new().unwrap()
}

include!("support/unix_protection.rs");

#[test]
fn platform_constants() {
    let p = platform();
    assert_eq!(p.os(), ricevanta_os::Os::Linux);
    assert_eq!(p.footprint_metric(), ricevanta_os::FootprintMetric::Pss);
    assert_eq!(p.data_root(), Ok(None));
    assert_eq!(p.program_data(), Ok(None));
    let paths = p.default_paths().unwrap().unwrap();
    assert_eq!(paths.config_file, Path::new("/etc/ricevanta/agent.json"));
    // Keep File imported for the helper signature on every toolchain.
    let _: Option<File> = None;
}
