//! The extended-ACL rule on the macOS host (spec section 3.1, plan Task 4):
//! ACL entries set with `chmod +a` on real objects. Run as the runner user,
//! who owns the scratch tree and may set ACLs on it.
#![cfg(target_os = "macos")]

use ricevanta_os::{DirKind, FileKind, Mode, Object, Platform, ProtectionError, Reason};
use ricevanta_os_macos::MacPlatform;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rv-acl-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        Scratch(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .args(["-R", "-N"])
            .arg(&self.0)
            .status();
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn chmod_acl(path: &Path, entry: &str) {
    let status = Command::new("chmod")
        .args(["+a", entry])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "chmod +a {entry:?} {}", path.display());
}

fn write_file(path: &Path, mode: u32) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(b"{}")
        .unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn make_dir(path: &Path, mode: u32) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn insecure<T: std::fmt::Debug>(result: Result<T, ProtectionError>, object: Object) {
    let error = result.expect_err("an allow entry must fail");
    assert_eq!(
        error,
        ProtectionError::new(object, Reason::InsecureAcl { sid: None })
    );
}

fn platform() -> MacPlatform {
    MacPlatform::new().unwrap()
}

const ALLOW: &str = "user:nobody allow write";
const DENY: &str = "everyone deny delete";

#[test]
fn allow_entry_on_the_configuration_file_fails() {
    let dir = Scratch::new();
    let config = dir.join("agent.json");
    write_file(&config, 0o600);
    platform().open_config(&config, Mode::Run).unwrap().unwrap();
    chmod_acl(&config, ALLOW);
    insecure(
        platform().open_config(&config, Mode::Run),
        Object::ConfigFile,
    );
}

#[test]
fn deny_entry_on_the_configuration_file_passes() {
    let dir = Scratch::new();
    let config = dir.join("agent.json");
    write_file(&config, 0o600);
    chmod_acl(&config, DENY);
    platform().open_config(&config, Mode::Run).unwrap().unwrap();
}

#[test]
fn allow_entry_on_the_configuration_parent_fails() {
    let dir = Scratch::new();
    let etc = dir.join("etc");
    make_dir(&etc, 0o755);
    write_file(&etc.join("agent.json"), 0o600);
    chmod_acl(&etc, ALLOW);
    insecure(
        platform().open_config(&etc.join("agent.json"), Mode::Run),
        Object::ConfigParent,
    );
}

#[test]
fn allow_entry_on_the_state_directory_fails() {
    let p = platform();
    let dir = Scratch::new();
    let state = dir.join("state");
    make_dir(&state, 0o700);
    chmod_acl(&state, ALLOW);
    let (parent, name) = p.open_parent(&state, DirKind::State, Mode::Run).unwrap();
    insecure(
        p.open_or_create_dir(&parent, &name, DirKind::State, Mode::Run),
        Object::StateDir,
    );
}

#[test]
fn allow_entry_on_the_log_directory_parent_fails() {
    let p = platform();
    let dir = Scratch::new();
    let root = dir.join("log-root");
    // Group write is accepted on the log root; an ACL allow entry is not.
    make_dir(&root, 0o775);
    p.open_parent(&root.join("logs"), DirKind::Log, Mode::Run)
        .unwrap();
    chmod_acl(&root, ALLOW);
    insecure(
        p.open_parent(&root.join("logs"), DirKind::Log, Mode::Run),
        Object::LogParent,
    );
}

#[test]
fn inheritable_allow_on_a_parent_fails_before_any_child_is_created() {
    let p = platform();
    let dir = Scratch::new();
    let parent = dir.join("parent");
    make_dir(&parent, 0o755);
    chmod_acl(&parent, &format!("{ALLOW},file_inherit,directory_inherit"));
    insecure(
        p.open_parent(&parent.join("run"), DirKind::Runtime, Mode::Run),
        Object::RuntimeParent,
    );
    assert!(!parent.join("run").exists());
}

#[test]
fn objects_created_under_an_inheritable_deny_pass_the_recheck() {
    let p = platform();
    let dir = Scratch::new();
    let parent = dir.join("parent");
    make_dir(&parent, 0o755);
    chmod_acl(&parent, &format!("{DENY},file_inherit,directory_inherit"));
    let (checked_parent, name) = p
        .open_parent(&parent.join("run"), DirKind::Runtime, Mode::Run)
        .unwrap();
    let run = p
        .open_or_create_dir(&checked_parent, &name, DirKind::Runtime, Mode::Run)
        .unwrap();
    p.create_file(
        &run,
        OsStr::new("health.json.tmp"),
        FileKind::HealthDocument,
    )
    .unwrap();
    // The inherited entry is really there.
    let listing = Command::new("ls")
        .arg("-led")
        .arg(parent.join("run").join("health.json.tmp"))
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("deny"), "{listing}");
}

/// `everyone deny readsecurity` makes `fgetattrlist(ATTR_CMN_EXTENDED_SECURITY)`
/// fail with `EACCES` for a non-root caller (xnu authorizes
/// `KAUTH_VNODE_READ_SECURITY` for that attribute and a deny entry is
/// evaluated first). The entry itself is a deny entry, so the refusal
/// proves that a failed call fails closed (startup failure, exit 3). As
/// root the call would succeed, so the test refuses to run as root rather
/// than pass vacuously.
fn require_unprivileged(p: &MacPlatform) {
    assert_ne!(
        p.euid(),
        0,
        "the failed-call test needs the unprivileged runner user"
    );
}

const DENY_READ_SECURITY: &str = "everyone deny readsecurity";

#[test]
fn unreadable_acl_on_the_configuration_file_fails_closed() {
    let p = platform();
    require_unprivileged(&p);
    let dir = Scratch::new();
    let config = dir.join("agent.json");
    write_file(&config, 0o600);
    chmod_acl(&config, DENY_READ_SECURITY);
    insecure(p.open_config(&config, Mode::Run), Object::ConfigFile);
}

#[test]
fn unreadable_acl_on_the_configuration_parent_fails_closed() {
    let p = platform();
    require_unprivileged(&p);
    let dir = Scratch::new();
    let etc = dir.join("etc");
    make_dir(&etc, 0o755);
    write_file(&etc.join("agent.json"), 0o600);
    chmod_acl(&etc, DENY_READ_SECURITY);
    insecure(
        p.open_config(&etc.join("agent.json"), Mode::Run),
        Object::ConfigParent,
    );
}
