//! Descriptor-based file protection of spec section 3.1 on Linux.
#![cfg(target_os = "linux")]

use ricevanta_os::{DirKind, FileKind, Mode, Object, Platform, ProtectionError, Reason};
use ricevanta_os_linux::LinuxPlatform;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A fresh directory with an explicit mode, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rv-os-linux-{}-{n}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "-")
        ));
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_file(path: &Path, mode: u32, body: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(body).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn platform() -> LinuxPlatform {
    LinuxPlatform::new().unwrap()
}

fn reason(result: Result<impl std::fmt::Debug, ProtectionError>, object: Object) -> Reason {
    let error = result.expect_err("check must fail");
    assert_eq!(error.object, object, "{error:?}");
    error.reason
}

#[test]
fn effective_user_comes_from_proc() {
    let text = fs::read_to_string("/proc/self/status").unwrap();
    let uid_line = text.lines().find(|l| l.starts_with("Uid:")).unwrap();
    let euid: u32 = uid_line.split_whitespace().nth(2).unwrap().parse().unwrap();
    assert_eq!(platform().euid(), euid);
}

#[test]
fn symbolic_link_config_fails_with_eloop() {
    let dir = Scratch::new();
    let target = dir.join("real.json");
    write_file(&target, 0o600, b"{}");
    let config = dir.join("agent.json");
    symlink(&target, &config).unwrap();
    let got = reason(
        platform().open_config(&config, Mode::Run),
        Object::ConfigFile,
    );
    assert_eq!(
        got,
        Reason::SymbolicLink {
            code: Some(libc::ELOOP)
        }
    );
}

#[test]
fn config_mode_must_grant_nothing_to_group_or_others() {
    let dir = Scratch::new();
    for mode in [0o644, 0o640] {
        let path = dir.join(&format!("bad-{mode:o}.json"));
        write_file(&path, mode, b"{}");
        let got = reason(platform().open_config(&path, Mode::Run), Object::ConfigFile);
        assert_eq!(got, Reason::Mode { mode });
    }
    for mode in [0o600, 0o400] {
        let path = dir.join(&format!("good-{mode:o}.json"));
        write_file(&path, mode, b"{\"k\":1}");
        let mut file = platform()
            .open_config(&path, Mode::Service)
            .unwrap()
            .unwrap();
        let mut body = String::new();
        file.read_to_string(&mut body).unwrap();
        assert_eq!(body, "{\"k\":1}");
    }
}

#[test]
fn missing_config_is_none() {
    let dir = Scratch::new();
    assert!(
        platform()
            .open_config(&dir.join("agent.json"), Mode::Run)
            .unwrap()
            .is_none()
    );
    // A missing parent directory also means no file.
    assert!(
        platform()
            .open_config(&dir.join("absent/agent.json"), Mode::Run)
            .unwrap()
            .is_none()
    );
}

#[test]
fn foreign_owner_and_writable_parent_fail() {
    let p = platform();
    let dir = Scratch::new();
    let path = dir.join("agent.json");
    write_file(&path, 0o600, b"{}");
    if p.euid() == 0 {
        std::os::unix::fs::chown(&path, Some(65534), None).unwrap();
        let got = reason(p.open_config(&path, Mode::Service), Object::ConfigFile);
        assert_eq!(got, Reason::Owner { uid: 65534 });
        std::os::unix::fs::chown(&path, Some(0), None).unwrap();
        std::os::unix::fs::chown(&dir.0, Some(65534), None).unwrap();
        let got = reason(p.open_config(&path, Mode::Service), Object::ConfigParent);
        assert_eq!(got, Reason::Owner { uid: 65534 });
        std::os::unix::fs::chown(&dir.0, Some(0), None).unwrap();
    } else {
        // Without root no file can be given a foreign owner; the owner rule
        // itself is covered by ricevanta-os tests over descriptor facts.
        eprintln!("foreign owner live check skipped: not running as root");
    }
    assert!(p.open_config(&path, Mode::Run).unwrap().is_some());
    fs::set_permissions(&dir.0, Permissions::from_mode(0o775)).unwrap();
    let got = reason(p.open_config(&path, Mode::Run), Object::ConfigParent);
    assert_eq!(got, Reason::ParentWritable { mode: 0o775 });
    fs::set_permissions(&dir.0, Permissions::from_mode(0o757)).unwrap();
    let got = reason(p.open_config(&path, Mode::Run), Object::ConfigParent);
    assert_eq!(got, Reason::ParentWritable { mode: 0o757 });
}

#[test]
fn fifo_config_fails_at_once() {
    let dir = Scratch::new();
    let path = dir.join("agent.json");
    let status = Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    let (send, receive) = mpsc::channel();
    let probe = path.clone();
    std::thread::spawn(move || {
        let result = platform()
            .open_config(&probe, Mode::Run)
            .map(|f| f.is_some());
        let _ = send.send(result);
    });
    // No writer is ever attached; a blocking open would never return.
    let result = receive
        .recv_timeout(Duration::from_secs(1))
        .expect("open_config blocked on a FIFO");
    assert_eq!(
        result,
        Err(ProtectionError {
            object: Object::ConfigFile,
            reason: Reason::NotRegularFile
        })
    );
}

#[test]
fn check_uses_the_opened_descriptor() {
    let dir = Scratch::new();
    let path = dir.join("agent.json");
    let good = dir.join("good.json");
    let bad = dir.join("bad.json");
    let p = platform();

    write_file(&path, 0o600, b"original");
    write_file(&bad, 0o644, b"replaced");
    let mut opened = p.open_config(&path, Mode::Run).unwrap().unwrap();
    fs::rename(&bad, &path).unwrap();
    // The path now names a 0644 file; the descriptor still names the 0600 one.
    assert_eq!(mode_of(&path), 0o644);
    assert_eq!(p.check_opened_config(&opened, Mode::Run), Ok(()));
    let mut body = String::new();
    opened.read_to_string(&mut body).unwrap();
    assert_eq!(body, "original");

    // Reverse: a descriptor on a bad file stays bad after a good file is
    // swapped in at the path.
    let unchecked = OpenOptions::new().read(true).open(&path).unwrap();
    write_file(&good, 0o600, b"good");
    fs::rename(&good, &path).unwrap();
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        p.check_opened_config(&unchecked, Mode::Run),
        Err(ProtectionError {
            object: Object::ConfigFile,
            reason: Reason::Mode { mode: 0o644 }
        })
    );
}

#[test]
fn existing_directories_must_match_exactly() {
    let p = platform();
    let dir = Scratch::new();
    let state = dir.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, Permissions::from_mode(0o750)).unwrap();
    let got = reason(
        p.open_or_create_dir(&state, DirKind::State, Mode::Run),
        Object::StateDir,
    );
    assert_eq!(got, Reason::Mode { mode: 0o750 });
    // A failing directory is never re-moded.
    assert_eq!(mode_of(&state), 0o750);
    fs::set_permissions(&state, Permissions::from_mode(0o700)).unwrap();
    let handle = p
        .open_or_create_dir(&state, DirKind::State, Mode::Run)
        .unwrap();
    assert!(handle.metadata().unwrap().is_dir());
}

#[test]
fn symbolic_link_in_place_of_a_directory_fails() {
    let p = platform();
    let dir = Scratch::new();
    let real = dir.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o700)).unwrap();
    let logs = dir.join("logs");
    symlink(&real, &logs).unwrap();
    let got = reason(
        p.open_or_create_dir(&logs, DirKind::Log, Mode::Run),
        Object::LogDir,
    );
    assert!(matches!(got, Reason::SymbolicLink { .. }), "{got:?}");
    // A regular file is not a directory either.
    let file = dir.join("file");
    write_file(&file, 0o700, b"");
    let got = reason(
        p.open_or_create_dir(&file, DirKind::Runtime, Mode::Run),
        Object::RuntimeDir,
    );
    assert_eq!(got, Reason::NotDirectory);
}

#[test]
fn missing_parent_is_not_created() {
    let p = platform();
    let dir = Scratch::new();
    let nested = dir.join("a/b");
    let got = reason(
        p.open_or_create_dir(&nested, DirKind::State, Mode::Run),
        Object::StateDir,
    );
    assert!(
        matches!(
            got,
            Reason::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }
        ),
        "{got:?}"
    );
    assert!(!dir.join("a").exists());
}

#[test]
fn created_file_refuses_a_symbolic_link() {
    let p = platform();
    let dir = Scratch::new();
    let target = dir.join("elsewhere");
    write_file(&target, 0o600, b"keep");
    let health = dir.join("health.json.tmp");
    symlink(&target, &health).unwrap();
    let got = reason(
        p.create_file(&health, FileKind::HealthDocument),
        Object::HealthDocument,
    );
    assert!(matches!(got, Reason::SymbolicLink { .. }), "{got:?}");
    assert_eq!(fs::read(&target).unwrap(), b"keep");
}

#[test]
fn created_files_truncate_or_append_by_kind() {
    let p = platform();
    let dir = Scratch::new();
    let health = dir.join("health.json.tmp");
    p.create_file(&health, FileKind::HealthDocument)
        .unwrap()
        .write_all(b"first")
        .unwrap();
    p.create_file(&health, FileKind::HealthDocument)
        .unwrap()
        .write_all(b"2")
        .unwrap();
    assert_eq!(fs::read(&health).unwrap(), b"2");
    let log = dir.join("agent.log");
    p.create_file(&log, FileKind::Log)
        .unwrap()
        .write_all(b"a\n")
        .unwrap();
    p.create_file(&log, FileKind::Log)
        .unwrap()
        .write_all(b"b\n")
        .unwrap();
    assert_eq!(fs::read(&log).unwrap(), b"a\nb\n");
    assert_eq!(mode_of(&log), 0o600);
}

fn umask_of_self() -> u32 {
    let text = fs::read_to_string("/proc/self/status").unwrap();
    let line = text.lines().find(|l| l.starts_with("Umask:")).unwrap();
    u32::from_str_radix(line.split_whitespace().nth(1).unwrap(), 8).unwrap()
}

/// Runs one ignored child test of this binary under `umask`.
fn run_child_under_umask(test: &str, umask: &str) {
    let exe = std::env::current_exe().unwrap();
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("umask {umask} && exec \"$0\" \"$@\""))
        .arg(exe)
        .args([test, "--exact", "--ignored", "--test-threads=1"])
        .env("RV_TEST_EXPECT_UMASK", umask)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{test} under umask {umask}: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn created_modes_do_not_depend_on_umask() {
    run_child_under_umask("umask_child_narrow", "0077");
    run_child_under_umask("umask_child_open", "0000");
}

fn expect_umask() {
    if let Some(expected) = std::env::var_os("RV_TEST_EXPECT_UMASK") {
        let expected = u32::from_str_radix(expected.to_str().unwrap(), 8).unwrap();
        assert_eq!(umask_of_self(), expected);
    }
}

#[test]
#[ignore = "child of created_modes_do_not_depend_on_umask"]
fn umask_child_narrow() {
    expect_umask();
    let p = platform();
    let dir = Scratch::new();
    let runtime = dir.join("run");
    let handle = p
        .open_or_create_dir(&runtime, DirKind::Runtime, Mode::Run)
        .unwrap();
    assert_eq!(handle.metadata().unwrap().mode() & 0o7777, 0o755);
    assert_eq!(mode_of(&runtime), 0o755);
    let health = runtime.join("health.json.tmp");
    let file = p.create_file(&health, FileKind::HealthDocument).unwrap();
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o644);
    assert_eq!(mode_of(&health), 0o644);
    // The second open of an existing directory checks, never re-modes.
    p.open_or_create_dir(&runtime, DirKind::Runtime, Mode::Run)
        .unwrap();
}

#[test]
#[ignore = "child of created_modes_do_not_depend_on_umask"]
fn umask_child_open() {
    expect_umask();
    let p = platform();
    let dir = Scratch::new();
    let state = dir.join("state");
    p.open_or_create_dir(&state, DirKind::State, Mode::Run)
        .unwrap();
    assert_eq!(mode_of(&state), 0o700);
    let logs = dir.join("logs");
    p.open_or_create_dir(&logs, DirKind::Log, Mode::Run)
        .unwrap();
    let log = logs.join("agent.log");
    p.create_file(&log, FileKind::Log).unwrap();
    assert_eq!(mode_of(&log), 0o600);
}

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
