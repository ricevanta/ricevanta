// Unix file-protection tests of spec section 3.1, shared by the Linux and
// macOS crates. The including test file defines `TestPlatform`, a
// `platform()` constructor and the per-OS constants test, then `include!`s
// this file, so both implementations run the same cases.
use ricevanta_os::{
    CheckedDir, DirKind, FileKind, Mode, Object, Platform, ProtectionError, Reason,
};
use std::ffi::OsStr;
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


/// Opens the parent of `path` and then the directory itself, as the core
/// does for each configured directory.
fn checked(
    p: &TestPlatform,
    path: &Path,
    kind: DirKind,
    mode: Mode,
) -> Result<CheckedDir, ProtectionError> {
    let (parent, name) = p.open_parent(path, kind, mode)?;
    p.open_or_create_dir(&parent, &name, kind, mode)
}

/// A checked `run`-mode runtime directory `name` inside `scratch`, the
/// directory files are created in.
fn runtime_in(p: &TestPlatform, scratch: &Scratch, name: &str) -> CheckedDir {
    checked(p, &scratch.join(name), DirKind::Runtime, Mode::Run).unwrap()
}

fn os(name: &str) -> &OsStr {
    OsStr::new(name)
}

fn reason(result: Result<impl std::fmt::Debug, ProtectionError>, object: Object) -> Reason {
    let error = result.expect_err("check must fail");
    assert_eq!(error.object, object, "{error:?}");
    error.reason
}

#[test]
fn effective_user_matches_the_owner_of_a_created_file() {
    // Independent of /proc: a new file is owned by the creating process's
    // filesystem uid, which equals the effective uid for this test.
    let dir = Scratch::new();
    let probe = dir.join("probe");
    write_file(&probe, 0o600, b"");
    assert_eq!(platform().euid(), fs::metadata(&probe).unwrap().uid());
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
        // `run` mode: the scratch parent belongs to the effective user,
        // which `service` mode refuses unless that user is root.
        let mut file = platform().open_config(&path, Mode::Run).unwrap().unwrap();
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
fn writable_parent_fails() {
    let p = platform();
    let dir = Scratch::new();
    let path = dir.join("agent.json");
    write_file(&path, 0o600, b"{}");
    assert!(p.open_config(&path, Mode::Run).unwrap().is_some());
    fs::set_permissions(&dir.0, Permissions::from_mode(0o775)).unwrap();
    let got = reason(p.open_config(&path, Mode::Run), Object::ConfigParent);
    assert_eq!(got, Reason::ParentWritable { mode: 0o775 });
    fs::set_permissions(&dir.0, Permissions::from_mode(0o757)).unwrap();
    let got = reason(p.open_config(&path, Mode::Run), Object::ConfigParent);
    assert_eq!(got, Reason::ParentWritable { mode: 0o757 });
}

#[test]
fn service_mode_refuses_a_directory_not_owned_by_root() {
    let p = platform();
    let dir = Scratch::new();
    let state = dir.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, Permissions::from_mode(0o700)).unwrap();
    // As a non-root user the directory belongs to that user; as root it is
    // handed to an unprivileged uid. Both branches assert a real refusal.
    // The parent is checked in `run` mode so that a non-root run reaches the
    // directory rule.
    let owner = if p.euid() == 0 {
        std::os::unix::fs::chown(&state, Some(65534), None).unwrap();
        65534
    } else {
        p.euid()
    };
    let (parent, name) = p.open_parent(&state, DirKind::State, Mode::Run).unwrap();
    let got = reason(
        p.open_or_create_dir(&parent, &name, DirKind::State, Mode::Service),
        Object::StateDir,
    );
    assert_eq!(got, Reason::Owner { uid: owner });
}

#[test]
fn directory_parent_rules() {
    let p = platform();
    let scratch = Scratch::new();
    let cases = [
        (DirKind::State, Object::StateParent),
        (DirKind::Runtime, Object::RuntimeParent),
        (DirKind::Log, Object::LogParent),
    ];
    for (kind, object) in cases {
        let parent = scratch.join(&format!("{object:?}"));
        fs::create_dir(&parent).unwrap();
        let child = parent.join("dir");
        // World-writable, with or without the sticky bit: always refused.
        for mode in [0o777, 0o1777, 0o757] {
            fs::set_permissions(&parent, Permissions::from_mode(mode)).unwrap();
            let got = reason(checked(&p, &child, kind, Mode::Run), object);
            assert_eq!(got, Reason::ParentWritable { mode }, "{kind:?} {mode:o}");
        }
        // Group-writable: refused for state and runtime, accepted for logs.
        fs::set_permissions(&parent, Permissions::from_mode(0o775)).unwrap();
        let result = checked(&p, &child, kind, Mode::Run);
        if kind == DirKind::Log {
            result.unwrap();
        } else {
            let got = reason(result, object);
            assert_eq!(got, Reason::ParentWritable { mode: 0o775 }, "{kind:?}");
        }
        fs::set_permissions(&parent, Permissions::from_mode(0o755)).unwrap();
        checked(&p, &child, kind, Mode::Run).unwrap();
        // A parent that is not a directory.
        let not_dir = scratch.join(&format!("{object:?}-file"));
        write_file(&not_dir, 0o755, b"");
        let got = reason(checked(&p, &not_dir.join("dir"), kind, Mode::Run), object);
        assert_eq!(got, Reason::NotDirectory);
    }
    // In `service` mode a parent owned by a non-root user is refused.
    if p.euid() != 0 {
        let got = reason(
            p.open_parent(&scratch.join("svc"), DirKind::Runtime, Mode::Service),
            Object::RuntimeParent,
        );
        assert_eq!(got, Reason::Owner { uid: p.euid() });
    }
}

/// Fails, never passes, without root. Plan Task 6 builds this test binary
/// as the runner user, takes its path from Cargo's JSON output, and runs
/// only that binary under `sudo <path> root_ --ignored` (no Cargo command
/// under `sudo`), on Linux and on macOS, naming every `root_` test in the
/// receipt.
fn require_root(p: &TestPlatform) {
    assert_eq!(
        p.euid(),
        0,
        "this test needs root: run it with sudo and --ignored"
    );
}

#[test]
#[ignore = "needs root: Task 6 runs the built binary under sudo on Linux and macOS"]
fn root_foreign_owner_of_config_and_parent_fails() {
    let p = platform();
    require_root(&p);
    let dir = Scratch::new();
    let path = dir.join("agent.json");
    write_file(&path, 0o600, b"{}");
    std::os::unix::fs::chown(&path, Some(65534), None).unwrap();
    let got = reason(p.open_config(&path, Mode::Service), Object::ConfigFile);
    assert_eq!(got, Reason::Owner { uid: 65534 });
    std::os::unix::fs::chown(&path, Some(0), None).unwrap();
    assert!(p.open_config(&path, Mode::Service).unwrap().is_some());
    std::os::unix::fs::chown(&dir.0, Some(65534), None).unwrap();
    let got = reason(p.open_config(&path, Mode::Service), Object::ConfigParent);
    assert_eq!(got, Reason::Owner { uid: 65534 });
}

#[test]
#[ignore = "needs root: Task 6 runs the built binary under sudo on Linux and macOS"]
fn root_directory_parent_owner_and_group_rules() {
    let p = platform();
    require_root(&p);
    let scratch = Scratch::new();
    for (kind, object) in [
        (DirKind::State, Object::StateParent),
        (DirKind::Runtime, Object::RuntimeParent),
        (DirKind::Log, Object::LogParent),
    ] {
        let parent = scratch.join(&format!("{object:?}"));
        fs::create_dir(&parent).unwrap();
        let child = parent.join("dir");
        // Root-owned 0775: refused for state and runtime, accepted for logs.
        fs::set_permissions(&parent, Permissions::from_mode(0o775)).unwrap();
        let result = checked(&p, &child, kind, Mode::Service);
        if kind == DirKind::Log {
            result.unwrap();
        } else {
            assert_eq!(
                reason(result, object),
                Reason::ParentWritable { mode: 0o775 }
            );
        }
        // Owned by another user, even with mode 0755: refused in both modes.
        fs::set_permissions(&parent, Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::chown(&parent, Some(65534), None).unwrap();
        for mode in [Mode::Service, Mode::Run] {
            let got = reason(checked(&p, &child, kind, mode), object);
            assert_eq!(got, Reason::Owner { uid: 65534 });
        }
    }
}

#[test]
#[ignore = "needs root: Task 6 runs the built binary under sudo on Linux and macOS"]
fn root_service_mode_refuses_unprivileged_directory_owner() {
    let p = platform();
    require_root(&p);
    let dir = Scratch::new();
    for (name, kind, object) in [
        ("state", DirKind::State, Object::StateDir),
        ("run", DirKind::Runtime, Object::RuntimeDir),
        ("logs", DirKind::Log, Object::LogDir),
    ] {
        let path = dir.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(kind.unix_mode())).unwrap();
        std::os::unix::fs::chown(&path, Some(65534), None).unwrap();
        let got = reason(checked(&p, &path, kind, Mode::Service), object);
        assert_eq!(got, Reason::Owner { uid: 65534 });
        std::os::unix::fs::chown(&path, Some(0), None).unwrap();
        checked(&p, &path, kind, Mode::Service).unwrap();
    }
}

#[test]
#[ignore = "needs root: Task 6 runs the built binary under sudo on Linux and macOS"]
fn root_foreign_health_file_is_refused_untouched() {
    let p = platform();
    require_root(&p);
    let scratch = Scratch::new();
    let run = runtime_in(&p, &scratch, "run");
    let tmp = scratch.join("run/health.json.tmp");
    write_file(&tmp, 0o644, b"planted");
    std::os::unix::fs::chown(&tmp, Some(65534), None).unwrap();
    let got = reason(
        p.create_file(&run, os("health.json.tmp"), FileKind::HealthDocument),
        Object::HealthDocument,
    );
    assert_eq!(got, Reason::Owner { uid: 65534 });
    assert_eq!(fs::read(&tmp).unwrap(), b"planted");
    assert_eq!(mode_of(&tmp), 0o644);
}

#[test]
fn paths_and_names_must_be_plain() {
    let p = platform();
    let dir = Scratch::new();
    let real = dir.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o700)).unwrap();
    let link = dir.join("state");
    symlink(&real, &link).unwrap();
    let base = link.to_str().unwrap();
    for spelled in [
        format!("{base}/"),
        format!("{base}/."),
        format!("{base}/sub/.."),
        "/".to_owned(),
        String::new(),
        "relative/state".to_owned(),
        // N-01: the parent's own spelling must be normal form too.
        format!("{base}//run"),
        format!("{base}/./run"),
        format!("{base}/../run"),
    ] {
        let got = reason(
            p.open_parent(Path::new(&spelled), DirKind::State, Mode::Run),
            Object::StateDir,
        );
        assert_eq!(got, Reason::PathForm, "{spelled:?}");
    }
    let config = dir.join("agent.json");
    write_file(&config, 0o600, b"{}");
    let spelled = format!("{}/.", config.to_str().unwrap());
    let got = reason(
        p.open_config(Path::new(&spelled), Mode::Run),
        Object::ConfigFile,
    );
    assert_eq!(got, Reason::PathForm);
    let run = runtime_in(&p, &dir, "run");
    for bad in ["", ".", "..", "a/b", "../agent.log"] {
        let got = reason(p.create_file(&run, os(bad), FileKind::Log), Object::LogFile);
        assert_eq!(got, Reason::PathForm, "{bad:?}");
        let got = reason(
            p.open_or_create_dir(&run, os(bad), DirKind::State, Mode::Run),
            Object::StateDir,
        );
        assert_eq!(got, Reason::PathForm, "{bad:?}");
        assert_eq!(
            p.rename_in(&run, os(bad), os("x")).unwrap_err().reason,
            Reason::PathForm
        );
        assert_eq!(
            p.remove_in(&run, os(bad)).unwrap_err().reason,
            Reason::PathForm
        );
    }
    // Nothing was created or re-moded through the link.
    assert_eq!(mode_of(&real), 0o700);
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
}

#[test]
fn writes_land_in_the_checked_directory_not_at_its_path() {
    let p = platform();
    let scratch = Scratch::new();
    let run = runtime_in(&p, &scratch, "run");
    // Rename the checked directory away and put a new one at its path.
    fs::rename(scratch.join("run"), scratch.join("moved")).unwrap();
    fs::create_dir(scratch.join("run")).unwrap();
    fs::set_permissions(scratch.join("run"), Permissions::from_mode(0o755)).unwrap();

    p.create_file(&run, os("health.json.tmp"), FileKind::HealthDocument)
        .unwrap()
        .write_all(b"{\"state\":\"ready\"}")
        .unwrap();
    p.rename_in(&run, os("health.json.tmp"), os("health.json"))
        .unwrap();
    p.create_file(&run, os("agent.log"), FileKind::Log)
        .unwrap()
        .write_all(b"line\n")
        .unwrap();
    p.rename_in(&run, os("agent.log"), os("agent.log.1"))
        .unwrap();
    p.create_file(&run, os("agent.log"), FileKind::Log).unwrap();

    let moved = scratch.join("moved");
    assert_eq!(
        fs::read(moved.join("health.json")).unwrap(),
        b"{\"state\":\"ready\"}"
    );
    assert!(!moved.join("health.json.tmp").exists());
    assert_eq!(fs::read(moved.join("agent.log.1")).unwrap(), b"line\n");
    assert!(moved.join("agent.log").exists());
    assert_eq!(fs::read_dir(scratch.join("run")).unwrap().count(), 0);

    // Deletion is relative too, and an absent name is success.
    p.remove_in(&run, os("agent.log.1")).unwrap();
    p.remove_in(&run, os("agent.log.1")).unwrap();
    assert!(!moved.join("agent.log.1").exists());
    // The rename replaces an existing target.
    p.create_file(&run, os("health.json.tmp"), FileKind::HealthDocument)
        .unwrap()
        .write_all(b"2")
        .unwrap();
    p.rename_in(&run, os("health.json.tmp"), os("health.json"))
        .unwrap();
    assert_eq!(fs::read(moved.join("health.json")).unwrap(), b"2");
}

#[test]
fn config_comes_from_the_checked_parent() {
    // A renamer thread alternates a safe and a world-writable directory at
    // the same path. Every file returned must come from the safe one: the
    // parent that passed the check is the parent the file is opened in.
    let p = platform();
    let root = Scratch::new();
    let current = root.join("current");
    let safe = root.join("safe");
    let unsafe_dir = root.join("open");
    for (dir, mode, body) in [(&safe, 0o755, "safe"), (&unsafe_dir, 0o777, "open")] {
        fs::create_dir(dir).unwrap();
        fs::set_permissions(dir, Permissions::from_mode(mode)).unwrap();
        write_file(&dir.join("agent.json"), 0o600, body.as_bytes());
    }
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let renamer = {
        let (stop, current, safe, open) = (
            stop.clone(),
            current.clone(),
            safe.clone(),
            unsafe_dir.clone(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                for source in [&safe, &open] {
                    if fs::rename(source, &current).is_ok() {
                        let _ = fs::rename(&current, source);
                    }
                }
            }
        })
    };
    let config = current.join("agent.json");
    let (mut from_safe, mut refused) = (0u32, 0u32);
    for _ in 0..20_000 {
        match p.open_config(&config, Mode::Run) {
            Ok(Some(mut file)) => {
                let mut body = String::new();
                file.read_to_string(&mut body).unwrap();
                assert_eq!(body, "safe", "file read through an unchecked parent");
                from_safe += 1;
            }
            Ok(None) => {}
            Err(_) => refused += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    renamer.join().unwrap();
    eprintln!("checked-parent race: {from_safe} safe reads, {refused} refusals");
    // The race must actually have happened in both directions.
    assert!(
        from_safe > 0 && refused > 0,
        "race not exercised: {from_safe} safe reads, {refused} refusals"
    );
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
    write_file(&state.join("kept"), 0o600, b"");
    fs::set_permissions(&state, Permissions::from_mode(0o750)).unwrap();
    let got = reason(
        checked(&p, &state, DirKind::State, Mode::Run),
        Object::StateDir,
    );
    assert_eq!(got, Reason::Mode { mode: 0o750 });
    // A pre-existing non-empty directory is never re-moded.
    assert_eq!(mode_of(&state), 0o750);
    fs::set_permissions(&state, Permissions::from_mode(0o700)).unwrap();
    let handle = checked(&p, &state, DirKind::State, Mode::Run).unwrap();
    assert!(handle.file().metadata().unwrap().is_dir());
    assert_eq!(handle.object(), Object::StateDir);
    assert_eq!(mode_of(&state), 0o700);
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
    let got = reason(checked(&p, &logs, DirKind::Log, Mode::Run), Object::LogDir);
    assert!(matches!(got, Reason::SymbolicLink { .. }), "{got:?}");
    // A regular file is not a directory either.
    let file = dir.join("file");
    write_file(&file, 0o700, b"");
    let got = reason(
        checked(&p, &file, DirKind::Runtime, Mode::Run),
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
        checked(&p, &nested, DirKind::State, Mode::Run),
        Object::StateParent,
    );
    assert!(
        matches!(&got, Reason::Io(cause) if cause.kind() == std::io::ErrorKind::NotFound),
        "{got:?}"
    );
    assert!(!dir.join("a").exists());
}

#[test]
fn created_file_refuses_a_symbolic_link() {
    let p = platform();
    let dir = Scratch::new();
    let run = runtime_in(&p, &dir, "run");
    let target = dir.join("elsewhere");
    write_file(&target, 0o600, b"keep");
    symlink(&target, dir.join("run/health.json.tmp")).unwrap();
    let got = reason(
        p.create_file(&run, os("health.json.tmp"), FileKind::HealthDocument),
        Object::HealthDocument,
    );
    assert!(matches!(got, Reason::SymbolicLink { .. }), "{got:?}");
    assert_eq!(fs::read(&target).unwrap(), b"keep");
}

#[test]
fn created_files_truncate_or_append_by_kind() {
    let p = platform();
    let dir = Scratch::new();
    let run = runtime_in(&p, &dir, "run");
    let health = dir.join("run/health.json.tmp");
    p.create_file(&run, os("health.json.tmp"), FileKind::HealthDocument)
        .unwrap()
        .write_all(b"first")
        .unwrap();
    p.create_file(&run, os("health.json.tmp"), FileKind::HealthDocument)
        .unwrap()
        .write_all(b"2")
        .unwrap();
    assert_eq!(fs::read(&health).unwrap(), b"2");
    let log = dir.join("run/agent.log");
    p.create_file(&run, os("agent.log"), FileKind::Log)
        .unwrap()
        .write_all(b"a\n")
        .unwrap();
    p.create_file(&run, os("agent.log"), FileKind::Log)
        .unwrap()
        .write_all(b"b\n")
        .unwrap();
    assert_eq!(fs::read(&log).unwrap(), b"a\nb\n");
    assert_eq!(mode_of(&log), 0o600);
}

/// The process umask within `0o666`, observed without a `libc` call: the
/// mode a new file requested as `0o666` actually receives.
fn umask_of_self() -> u32 {
    let dir = Scratch::new();
    let probe = dir.join("umask-probe");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&probe)
        .unwrap();
    0o666 & !mode_of(&probe)
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
    let passed = format!("test {test} ... ok");
    assert!(
        output.status.success()
            && stdout.lines().filter(|line| *line == passed).count() == 1
            && stdout.lines().any(|line| {
                line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
            }),
        "{test} under umask {umask}: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "RUST_CHILD {{\"target\":\"protection\",\"parent\":\"created_modes_do_not_depend_on_umask\",\"test\":\"{test}\",\"result\":\"success\"}}"
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
        assert_eq!(umask_of_self(), expected & 0o666);
    }
}

#[test]
#[ignore = "child of created_modes_do_not_depend_on_umask"]
fn umask_child_narrow() {
    expect_umask();
    let p = platform();
    let dir = Scratch::new();
    let runtime = dir.join("run");
    let handle = checked(&p, &runtime, DirKind::Runtime, Mode::Run).unwrap();
    assert_eq!(handle.file().metadata().unwrap().mode() & 0o7777, 0o755);
    assert_eq!(mode_of(&runtime), 0o755);
    let file = p
        .create_file(&handle, os("health.json.tmp"), FileKind::HealthDocument)
        .unwrap();
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o644);
    assert_eq!(mode_of(&runtime.join("health.json.tmp")), 0o644);
    // The second open of an existing directory checks, never re-modes.
    checked(&p, &runtime, DirKind::Runtime, Mode::Run).unwrap();
}

#[test]
#[ignore = "child of created_modes_do_not_depend_on_umask"]
fn umask_child_open() {
    expect_umask();
    let p = platform();
    let dir = Scratch::new();
    let state = dir.join("state");
    checked(&p, &state, DirKind::State, Mode::Run).unwrap();
    assert_eq!(mode_of(&state), 0o700);
    let logs = dir.join("logs");
    let handle = checked(&p, &logs, DirKind::Log, Mode::Run).unwrap();
    p.create_file(&handle, os("agent.log"), FileKind::Log)
        .unwrap();
    assert_eq!(mode_of(&logs.join("agent.log")), 0o600);
}
