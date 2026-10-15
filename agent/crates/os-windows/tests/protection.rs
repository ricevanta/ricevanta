//! Windows owner, DACL and reparse-point protection of spec section 3.1.
//! Run as the runner's administrator: trees are prepared with `icacls` the
//! way the AG-12 installer prepares `<ProgramData>\Ricevanta`.
#![cfg(windows)]

use ricevanta_os::{
    CheckedDir, DirKind, FileKind, Mode, Object, Platform, ProtectionError, Reason,
};
use ricevanta_os_windows::WindowsPlatform;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const USERS: &str = "S-1-5-32-545";
const CREATOR_OWNER: &str = "S-1-3-0";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn run(program: &str, args: &[&str]) {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn icacls(path: &Path, args: &[&str]) {
    let mut all = vec![path.to_str().unwrap()];
    all.extend_from_slice(args);
    run("icacls", &all);
}

fn junction(link: &Path, target: &Path) {
    run(
        "cmd",
        &[
            "/C",
            "mklink",
            "/J",
            link.to_str().unwrap(),
            target.to_str().unwrap(),
        ],
    );
}

/// A tree prepared like the installer's: inheritance removed, SYSTEM and
/// Administrators full control, owner Administrators throughout.
struct Tree(PathBuf);

impl Tree {
    fn new() -> Tree {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("rv-os-windows-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        icacls(
            &root,
            &[
                "/inheritance:r",
                "/grant",
                "*S-1-5-18:(OI)(CI)F",
                "/grant",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
        );
        for dir in ["state", "run", "logs"] {
            fs::create_dir(root.join(dir)).unwrap();
        }
        fs::File::create(root.join("agent.json"))
            .unwrap()
            .write_all(b"{}")
            .unwrap();
        icacls(&root, &["/setowner", "*S-1-5-32-544", "/T"]);
        Tree(root)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = Command::new("icacls")
            .args([self.0.to_str().unwrap(), "/reset", "/T", "/Q"])
            .output();
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn platform() -> WindowsPlatform {
    WindowsPlatform::new().unwrap()
}

fn checked(p: &WindowsPlatform, path: &Path, kind: DirKind) -> Result<CheckedDir, ProtectionError> {
    let (parent, name) = p.open_parent(path, kind, Mode::Service)?;
    p.open_or_create_dir(&parent, &name, kind, Mode::Service)
}

fn reason<T: std::fmt::Debug>(result: Result<T, ProtectionError>, object: Object) -> Reason {
    let error = result.expect_err("check must fail");
    assert_eq!(error.object, object, "{error:?}");
    error.reason
}

fn insecure(sid: &str) -> Reason {
    Reason::InsecureAcl {
        sid: Some(sid.to_owned()),
    }
}

#[test]
fn prepared_tree_passes() {
    let p = platform();
    let tree = Tree::new();
    let mut config = p
        .open_config(&tree.join("agent.json"), Mode::Service)
        .unwrap()
        .unwrap();
    let mut body = String::new();
    config.read_to_string(&mut body).unwrap();
    assert_eq!(body, "{}");
    for (name, kind) in [
        ("state", DirKind::State),
        ("run", DirKind::Runtime),
        ("logs", DirKind::Log),
    ] {
        checked(&p, &tree.join(name), kind).unwrap();
    }
}

#[test]
fn users_modify_on_the_root_fails() {
    let p = platform();
    let tree = Tree::new();
    icacls(&tree.0, &["/grant", "*S-1-5-32-545:(OI)(CI)M"]);
    let got = reason(
        p.open_config(&tree.join("agent.json"), Mode::Service),
        Object::ConfigParent,
    );
    assert_eq!(got, insecure(USERS));
    // A configured state directory whose parent grants Users modify fails
    // on the parent.
    let got = reason(
        checked(&p, &tree.join("state"), DirKind::State),
        Object::StateParent,
    );
    assert_eq!(got, insecure(USERS));
}

#[test]
fn owner_set_to_the_runner_user_fails() {
    let p = platform();
    let tree = Tree::new();
    let user = std::env::var("USERNAME").unwrap();
    icacls(&tree.join("state"), &["/setowner", &user]);
    let got = reason(
        checked(&p, &tree.join("state"), DirKind::State),
        Object::StateDir,
    );
    match got {
        Reason::OwnerSid { sid } => {
            assert!(sid.starts_with("S-1-5-21-"), "{sid}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn any_right_for_users_fails() {
    let p = platform();
    for (object_name, grant, kind, object) in [
        (
            "logs",
            "*S-1-5-32-545:(OI)(CI)(IO)W",
            Some(DirKind::Log),
            Object::LogDir,
        ),
        (
            "run",
            "*S-1-5-32-545:(OI)(CI)RX",
            Some(DirKind::Runtime),
            Object::RuntimeDir,
        ),
        (
            "state",
            "*S-1-5-32-545:(S)",
            Some(DirKind::State),
            Object::StateDir,
        ),
        ("agent.json", "*S-1-5-32-545:R", None, Object::ConfigFile),
    ] {
        let tree = Tree::new();
        icacls(&tree.join(object_name), &["/grant", grant]);
        let got = match kind {
            Some(kind) => reason(checked(&p, &tree.join(object_name), kind), object),
            None => reason(
                p.open_config(&tree.join(object_name), Mode::Service),
                object,
            ),
        };
        assert_eq!(got, insecure(USERS), "{object_name} {grant}");
    }
}

#[test]
fn creator_owner_write_fails() {
    let p = platform();
    let tree = Tree::new();
    icacls(&tree.join("state"), &["/grant", "*S-1-3-0:(OI)(CI)(IO)W"]);
    let got = reason(
        checked(&p, &tree.join("state"), DirKind::State),
        Object::StateDir,
    );
    assert_eq!(got, insecure(CREATOR_OWNER));
}

#[test]
fn explicit_deny_passes() {
    let p = platform();
    let tree = Tree::new();
    icacls(&tree.join("state"), &["/deny", "*S-1-5-32-545:(W)"]);
    checked(&p, &tree.join("state"), DirKind::State).unwrap();
}

#[test]
fn junctions_are_refused() {
    let p = platform();
    let tree = Tree::new();
    let target = tree.join("target");
    fs::create_dir(&target).unwrap();
    // A junction in place of the runtime directory.
    fs::remove_dir(tree.join("run")).unwrap();
    junction(&tree.join("run"), &target);
    let got = reason(
        checked(&p, &tree.join("run"), DirKind::Runtime),
        Object::RuntimeDir,
    );
    assert_eq!(got, Reason::ReparsePoint);
    // A junction in place of the configuration file.
    fs::remove_file(tree.join("agent.json")).unwrap();
    junction(&tree.join("agent.json"), &target);
    let got = reason(
        p.open_config(&tree.join("agent.json"), Mode::Service),
        Object::ConfigFile,
    );
    assert_eq!(got, Reason::ReparsePoint);
    // A junction planted as health.json.tmp by an administrator.
    let state = checked(&p, &tree.join("state"), DirKind::State).unwrap();
    junction(&tree.join("state").join("health.json.tmp"), &target);
    let got = reason(
        p.create_file(
            &state,
            OsStr::new("health.json.tmp"),
            FileKind::HealthDocument,
        ),
        Object::HealthDocument,
    );
    assert_eq!(got, Reason::ReparsePoint);
}

#[test]
fn names_win32_would_rewrite_are_refused() {
    let p = platform();
    let tree = Tree::new();
    let state = checked(&p, &tree.join("state"), DirKind::State).unwrap();
    for name in [
        "health.json.",
        "agent.log ",
        "...",
        "NUL",
        "com1.log",
        "a:b",
        "a\\b",
    ] {
        let got = reason(
            p.create_file(&state, OsStr::new(name), FileKind::Log),
            Object::LogFile,
        );
        assert_eq!(got, Reason::PathForm, "{name:?}");
    }
    for path in [r"C:\x\logs.", r"\\server\share\x", r"C:\x\..\y", r"C:\x\"] {
        let got = reason(
            p.open_parent(Path::new(path), DirKind::Log, Mode::Service),
            Object::LogDir,
        );
        assert_eq!(got, Reason::PathForm, "{path}");
    }
}

#[test]
fn files_are_created_renamed_and_removed_in_the_checked_directory() {
    let p = platform();
    let tree = Tree::new();
    let run_dir = checked(&p, &tree.join("run"), DirKind::Runtime).unwrap();
    let tmp = OsStr::new("health.json.tmp");
    p.create_file(&run_dir, tmp, FileKind::HealthDocument)
        .unwrap()
        .write_all(b"first")
        .unwrap();
    p.create_file(&run_dir, tmp, FileKind::HealthDocument)
        .unwrap()
        .write_all(b"2")
        .unwrap();
    p.rename_in(&run_dir, tmp, OsStr::new("health.json"))
        .unwrap();
    assert_eq!(
        fs::read(tree.join("run").join("health.json")).unwrap(),
        b"2"
    );
    let log = OsStr::new("agent.log");
    p.create_file(&run_dir, log, FileKind::Log)
        .unwrap()
        .write_all(b"a\n")
        .unwrap();
    p.create_file(&run_dir, log, FileKind::Log)
        .unwrap()
        .write_all(b"b\n")
        .unwrap();
    assert_eq!(
        fs::read(tree.join("run").join("agent.log")).unwrap(),
        b"a\nb\n"
    );
    p.remove_in(&run_dir, log).unwrap();
    p.remove_in(&run_dir, log).unwrap();
    assert!(!tree.join("run").join("agent.log").exists());
}

#[test]
fn run_mode_creates_directories_and_checks_nothing() {
    let p = platform();
    let root = std::env::temp_dir().join(format!(
        "rv-os-windows-run-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let (parent, name) = p
        .open_parent(&root.join("state"), DirKind::State, Mode::Run)
        .unwrap();
    let state = p
        .open_or_create_dir(&parent, &name, DirKind::State, Mode::Run)
        .unwrap();
    assert!(root.join("state").is_dir());
    p.create_file(&state, OsStr::new("agent.log"), FileKind::Log)
        .unwrap();
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn platform_constants() {
    let p = platform();
    assert_eq!(p.os(), ricevanta_os::Os::Windows);
    assert_eq!(
        p.footprint_metric(),
        ricevanta_os::FootprintMetric::PrivateWorkingSet
    );
    let program_data = p.program_data().unwrap().unwrap();
    assert!(program_data.is_absolute());
    assert_eq!(
        p.data_root().unwrap().unwrap(),
        program_data.join("Ricevanta")
    );
    let paths = p.default_paths().unwrap().unwrap();
    assert_eq!(
        paths.state_dir,
        program_data.join("Ricevanta").join("state")
    );
}
