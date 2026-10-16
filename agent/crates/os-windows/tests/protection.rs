//! Windows owner, DACL and reparse-point protection of spec section 3.1.
//! Run as the runner's administrator: trees are prepared with `icacls` the
//! way the AG-12 installer prepares `<ProgramData>\Ricevanta`.
#![cfg(windows)]

use ricevanta_os::{
    CheckedDir, DirKind, FileKind, Mode, Object, Os, Platform, ProtectionError, Reason,
    is_normal_form,
};
use ricevanta_os_windows::WindowsPlatform;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, IsWellKnownSid,
    OWNER_SECURITY_INFORMATION, WinBuiltinAdministratorsSid,
};

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

fn prepare_root(root: &Path) {
    // Replace the whole DACL, including explicit entries. Combining icacls
    // /inheritance:r with /grant retained the runner's individual allow ACE.
    powershell(&format!(
        "$acl = [System.Security.AccessControl.DirectorySecurity]::new(); \
         $acl.SetSecurityDescriptorSddlForm(\
             'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', \
             [System.Security.AccessControl.AccessControlSections]::Access); \
         [System.IO.FileSystemAclExtensions]::SetAccessControl(\
             [System.IO.DirectoryInfo]::new({}), $acl)",
        literal(root)
    ));
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
        Tree::new_in(&std::env::temp_dir())
    }

    /// A prepared data root inside `outer`.
    fn new_in(outer: &Path) -> Tree {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = outer.join(format!("rv-os-windows-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        prepare_root(&root);
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
    assert_installer_root_acl(&tree.0);
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
fn fixture_preparation_replaces_explicit_and_inherited_grants() {
    let p = platform();
    let outer = Tree::new();
    icacls(&outer.0, &["/grant", "*S-1-5-32-545:(OI)(CI)R"]);
    // A new data root must discard its parent's Users grant.
    let tree = Tree::new_in(&outer.0);
    assert_installer_root_acl(&tree.0);
    p.open_config(&tree.join("agent.json"), Mode::Service)
        .unwrap()
        .unwrap();
    // Repreparing a pre-existing root must also discard explicit grants.
    icacls(&tree.0, &["/grant", "*S-1-5-32-545:(OI)(CI)R"]);
    prepare_root(&tree.0);
    assert_installer_root_acl(&tree.0);
    p.open_config(&tree.join("agent.json"), Mode::Service)
        .unwrap()
        .unwrap();
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

fn new_output_has_trusted_owner_and_inherited_acl(
    directory: &str,
    dir_kind: DirKind,
    name: &str,
    file_kind: FileKind,
    inherit_deny: bool,
) {
    let p = platform();
    let tree = Tree::new();
    let parent = tree.join(directory);
    if inherit_deny {
        icacls(&parent, &["/deny", "*S-1-5-32-545:(OI)(CI)(IO)(D)"]);
    }
    let dir = checked(&p, &parent, dir_kind).unwrap();
    let path = parent.join(name);
    assert!(!path.exists());
    p.create_file(&dir, OsStr::new(name), file_kind)
        .unwrap()
        .write_all(b"new output")
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"new output");
    // Independent persisted-descriptor oracle, including inheritance flags.
    let facts = powershell(&format!(
        "$acl = [System.IO.FileSystemAclExtensions]::GetAccessControl(\
             [System.IO.FileInfo]::new({})); \
         $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(\
             $acl.GetSecurityDescriptorBinaryForm(), 0); \
         $raw.Owner.Value; \
         foreach ($ace in $raw.DiscretionaryAcl) {{ \
             '{{0}}|{{1}}|{{2}}|{{3}}' -f [int]$ace.AceType, [int]$ace.AceFlags, \
                 $ace.AccessMask, $ace.SecurityIdentifier.Value \
         }}",
        literal(&path)
    ));
    let mut got: Vec<_> = facts.lines().map(str::trim).collect();
    let mut expected = vec![
        "S-1-5-32-544",
        "0|16|2032127|S-1-5-18",
        "0|16|2032127|S-1-5-32-544",
    ];
    if inherit_deny {
        expected.push("1|16|65536|S-1-5-32-545");
    }
    got.sort_unstable();
    expected.sort_unstable();
    assert_eq!(got, expected, "{}", path.display());
}

#[test]
fn new_health_output_has_trusted_owner_and_inherited_acl() {
    new_output_has_trusted_owner_and_inherited_acl(
        "run",
        DirKind::Runtime,
        "health.json.tmp",
        FileKind::HealthDocument,
        false,
    );
}

#[test]
fn new_log_output_has_trusted_owner_and_inherited_acl() {
    new_output_has_trusted_owner_and_inherited_acl(
        "logs",
        DirKind::Log,
        "agent.log",
        FileKind::Log,
        false,
    );
}

#[test]
fn new_service_outputs_preserve_inheritable_denies() {
    for (directory, dir_kind, name, file_kind) in [
        (
            "run",
            DirKind::Runtime,
            "health.json.tmp",
            FileKind::HealthDocument,
        ),
        ("logs", DirKind::Log, "agent.log", FileKind::Log),
    ] {
        new_output_has_trusted_owner_and_inherited_acl(directory, dir_kind, name, file_kind, true);
    }
}

#[test]
fn new_service_outputs_support_long_normal_paths() {
    let p = platform();
    let tree = Tree::new();
    let mut path = tree.0.clone();
    for n in 0..3 {
        path = path.join(format!("long-{n}-{}", "x".repeat(100)));
        fs::create_dir(&path).unwrap();
        powershell(&format!(
            "$dir = [System.IO.DirectoryInfo]::new({}); \
             $acl = [System.IO.FileSystemAclExtensions]::GetAccessControl($dir); \
             $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')); \
             [System.IO.FileSystemAclExtensions]::SetAccessControl($dir, $acl)",
            literal(&path)
        ));
    }
    assert!(path.to_str().unwrap().encode_utf16().count() > 260);
    let dir = checked(&p, &path, DirKind::Runtime).unwrap();
    for (name, kind, expected) in [
        ("health.json.tmp", FileKind::HealthDocument, b"B".as_slice()),
        ("agent.log", FileKind::Log, b"AB".as_slice()),
    ] {
        for bytes in [b"A", b"B"] {
            p.create_file(&dir, OsStr::new(name), kind)
                .unwrap()
                .write_all(bytes)
                .unwrap();
        }
        assert_eq!(fs::read(path.join(name)).unwrap(), expected);
    }
}

#[test]
fn service_outputs_support_maximum_configured_directory_length() {
    let p = platform();
    for symbol in ['x', '🦀'] {
        let tree = Tree::new();
        let mut path = tree.0.clone();
        // The schema counts Unicode scalar values, not bytes or UTF-16 units.
        // Keep each added component within 200 units, below NTFS's 255-unit limit.
        let mut remaining = 1_024 - path.to_str().unwrap().chars().count();
        let max_component = 200 / symbol.len_utf16();
        let components = remaining.div_ceil(max_component + 1);
        for left in (1..=components).rev() {
            let length = remaining / left - 1;
            assert!((1..=max_component).contains(&length));
            let component: String = std::iter::repeat_n(symbol, length).collect();
            assert!(component.encode_utf16().count() <= 200);
            path = path.join(component);
            fs::create_dir(&path).unwrap();
            powershell(&format!(
                "$dir = [System.IO.DirectoryInfo]::new({}); \
                 $acl = [System.IO.FileSystemAclExtensions]::GetAccessControl($dir); \
                 $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')); \
                 [System.IO.FileSystemAclExtensions]::SetAccessControl($dir, $acl)",
                literal(&path)
            ));
            remaining -= length + 1;
        }
        assert_eq!(remaining, 0);
        let directory = path.to_str().unwrap();
        assert_eq!(directory.chars().count(), 1_024);
        assert!(is_normal_form(Os::Windows, directory));
        for (dir_kind, name, kind, expected) in [
            (
                DirKind::Runtime,
                "health.json.tmp",
                FileKind::HealthDocument,
                b"B".as_slice(),
            ),
            (DirKind::Log, "agent.log", FileKind::Log, b"AB".as_slice()),
        ] {
            let dir = checked(&p, &path, dir_kind).unwrap();
            let output = path.join(name);
            assert_eq!(output.to_str().unwrap().chars().count(), 1_025 + name.len());
            assert!(!output.exists());
            p.create_file(&dir, OsStr::new(name), kind)
                .unwrap()
                .write_all(b"A")
                .unwrap();
            assert_eq!(fs::read(&output).unwrap(), b"A");
            // Reopen the existing trusted output: health truncates and log appends.
            p.create_file(&dir, OsStr::new(name), kind)
                .unwrap()
                .write_all(b"B")
                .unwrap();
            assert_eq!(fs::read(&output).unwrap(), expected);
        }
    }
}

fn rejected_outputs_stay_unchanged(tamper: impl Fn(&Path), check_reason: impl Fn(Reason)) {
    let p = platform();
    for (directory, kind, name, file_kind) in [
        (
            "run",
            DirKind::Runtime,
            "health.json.tmp",
            FileKind::HealthDocument,
        ),
        ("logs", DirKind::Log, "agent.log", FileKind::Log),
    ] {
        let tree = Tree::new();
        let dir = checked(&p, &tree.join(directory), kind).unwrap();
        let path = tree.join(directory).join(name);
        fs::write(&path, b"planted output").unwrap();
        icacls(&path, &["/setowner", "*S-1-5-32-544"]);
        tamper(&path);
        let got = reason(
            p.create_file(&dir, OsStr::new(name), file_kind),
            file_kind.object(),
        );
        check_reason(got);
        assert_eq!(fs::read(&path).unwrap(), b"planted output", "{name}");
    }
}

#[test]
fn foreign_owned_outputs_are_refused_before_mutation() {
    rejected_outputs_stay_unchanged(
        |path| icacls(path, &["/setowner", &std::env::var("USERNAME").unwrap()]),
        |got| match got {
            Reason::OwnerSid { sid } => assert!(sid.starts_with("S-1-5-21-"), "{sid}"),
            other => panic!("{other:?}"),
        },
    );
}

#[test]
fn foreign_allow_outputs_are_refused_before_mutation() {
    rejected_outputs_stay_unchanged(
        |path| icacls(path, &["/grant", "*S-1-5-32-545:M"]),
        |got| assert_eq!(got, insecure(USERS)),
    );
}

#[test]
fn null_dacl_outputs_are_refused_before_mutation() {
    rejected_outputs_stay_unchanged(set_null_dacl, |got| {
        assert_eq!(got, Reason::InsecureAcl { sid: None })
    });
}

#[test]
fn trusted_existing_outputs_are_checked_and_written_by_kind() {
    let p = platform();
    let tree = Tree::new();
    for (directory, kind, name, file_kind, expected) in [
        (
            "run",
            DirKind::Runtime,
            "health.json.tmp",
            FileKind::HealthDocument,
            b"new".as_slice(),
        ),
        (
            "logs",
            DirKind::Log,
            "agent.log",
            FileKind::Log,
            b"planted outputnew".as_slice(),
        ),
    ] {
        let dir = checked(&p, &tree.join(directory), kind).unwrap();
        let path = tree.join(directory).join(name);
        fs::write(&path, b"planted output").unwrap();
        icacls(&path, &["/setowner", "*S-1-5-32-544"]);
        p.create_file(&dir, OsStr::new(name), file_kind)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), expected);
    }
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
fn run_outputs_keep_developer_ownership_and_permissions() {
    let p = platform();
    let tree = Tree::new();
    let (parent, name) = p
        .open_parent(&tree.join("state"), DirKind::State, Mode::Run)
        .unwrap();
    let dir = p
        .open_or_create_dir(&parent, &name, DirKind::State, Mode::Run)
        .unwrap();
    for (name, kind) in [
        ("health.json.tmp", FileKind::HealthDocument),
        ("agent.log", FileKind::Log),
    ] {
        let path = tree.join("state").join(name);
        fs::write(&path, b"developer output").unwrap();
        icacls(&path, &["/setowner", &std::env::var("USERNAME").unwrap()]);
        icacls(&path, &["/grant", "*S-1-5-32-545:R"]);
        p.create_file(&dir, OsStr::new(name), kind)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        let expected = if kind == FileKind::HealthDocument {
            b"new".as_slice()
        } else {
            b"developer outputnew".as_slice()
        };
        assert_eq!(fs::read(path).unwrap(), expected);
    }
}

fn powershell(script: &str) -> String {
    let output = Command::new("pwsh.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("$ErrorActionPreference = 'Stop'; {script}"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn literal(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "''"))
}

fn assert_installer_root_acl(path: &Path) {
    // Inspect the raw descriptor independently of the production decoder.
    let facts = powershell(&format!(
        "$acl = [System.IO.FileSystemAclExtensions]::GetAccessControl(\
             [System.IO.DirectoryInfo]::new({})); \
         $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(\
             $acl.GetSecurityDescriptorBinaryForm(), 0); \
         $raw.Owner.Value; \
         [bool]($raw.ControlFlags -band \
             [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent); \
         [bool]($raw.ControlFlags -band \
             [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected); \
         foreach ($ace in $raw.DiscretionaryAcl) {{ \
             '{{0}}|{{1}}|{{2}}|{{3}}' -f [int]$ace.AceType, [int]$ace.AceFlags, \
                 $ace.AccessMask, $ace.SecurityIdentifier.Value \
         }}",
        literal(path)
    ));
    let mut facts: Vec<_> = facts.lines().map(str::trim).collect();
    facts.sort_unstable();
    let mut expected = vec![
        "S-1-5-32-544",
        "True",
        "True",
        "0|3|2032127|S-1-5-18",
        "0|3|2032127|S-1-5-32-544",
    ];
    expected.sort_unstable();
    assert_eq!(facts, expected, "fixture root: {}", path.display());
}

#[expect(
    unsafe_code,
    reason = "GetSecurityInfo and GetSecurityDescriptorDacl: the file stays open, output pointers refer to live local values, and the returned descriptor owns the owner SID until LocalFree"
)]
fn assert_null_dacl(path: &Path) {
    let file = fs::File::open(path).unwrap();
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: file owns a live handle with READ_CONTROL; both requested
    // output pointers are writable for this call. No other outputs are requested.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    let mut present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    let mut queried = 0;
    let mut administrator = 0;
    if code == ERROR_SUCCESS && !descriptor.is_null() {
        // SAFETY: descriptor is the live security descriptor just returned;
        // the three outputs are writable local values. No ACL is dereferenced.
        queried = unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        };
        if !owner.is_null() {
            // SAFETY: owner is the SID returned inside the live descriptor.
            administrator = unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) };
        }
    }
    // SAFETY: descriptor is null or the allocation from GetSecurityInfo;
    // this is its sole release, after the last use of the owner and DACL.
    unsafe { LocalFree(descriptor) };
    assert_eq!(code, ERROR_SUCCESS, "GetSecurityInfo");
    assert_ne!(queried, 0, "GetSecurityDescriptorDacl");
    assert_ne!(administrator, 0, "fixture owner must remain Administrators");
    assert_ne!(present, 0, "fixture must have a present DACL");
    assert!(dacl.is_null(), "fixture must have a NULL DACL");
}

#[test]
fn null_dacl_on_a_real_file_fails() {
    let p = platform();
    let tree = Tree::new();
    let config = tree.join("agent.json");
    // SDDL `D:NO_ACCESS_CONTROL` is a NULL DACL; the owner stays
    // Administrators so only the DACL rule can fail.
    set_null_dacl(&config);
    let got = reason(p.open_config(&config, Mode::Service), Object::ConfigFile);
    assert_eq!(got, Reason::InsecureAcl { sid: None });
}

fn set_null_dacl(path: &Path) {
    powershell(&format!(
        "$file = [System.IO.FileInfo]::new({}); \
         $acl = [System.IO.FileSystemAclExtensions]::GetAccessControl($file); \
         $acl.SetSecurityDescriptorSddlForm('D:NO_ACCESS_CONTROL', \
             [System.Security.AccessControl.AccessControlSections]::Access); \
         [System.IO.FileSystemAclExtensions]::SetAccessControl($file, $acl)",
        literal(path)
    ));
    // SDDL serialization can omit the D: section for a NULL DACL. Check the
    // native presence bit and null ACL, with the trusted owner unchanged.
    assert_null_dacl(path);
}

#[test]
fn junctions_at_parents_and_directories_are_refused() {
    let p = platform();
    let tree = Tree::new();
    let target = tree.join("target");
    fs::create_dir(&target).unwrap();
    for name in ["state", "logs"] {
        fs::create_dir(target.join(name)).unwrap();
    }
    // A junction as the checked parent of a configured directory.
    junction(&tree.join("parent"), &target);
    let got = reason(
        checked(&p, &tree.join("parent").join("state"), DirKind::State),
        Object::StateParent,
    );
    assert_eq!(got, Reason::ReparsePoint);
    // Junctions in place of the state and log directories.
    for (name, kind, object) in [
        ("state", DirKind::State, Object::StateDir),
        ("logs", DirKind::Log, Object::LogDir),
    ] {
        fs::remove_dir(tree.join(name)).unwrap();
        junction(&tree.join(name), &target.join(name));
        let got = reason(checked(&p, &tree.join(name), kind), object);
        assert_eq!(got, Reason::ReparsePoint, "{name}");
    }
}

#[test]
fn service_mode_never_creates_a_missing_directory() {
    let p = platform();
    let tree = Tree::new();
    fs::remove_dir(tree.join("state")).unwrap();
    let got = reason(
        checked(&p, &tree.join("state"), DirKind::State),
        Object::StateDir,
    );
    assert!(
        matches!(&got, Reason::Io(cause) if cause.kind() == std::io::ErrorKind::NotFound),
        "{got:?}"
    );
    assert!(!tree.join("state").exists());
}

#[test]
fn program_data_like_parent_is_never_checked() {
    // An outer directory with the default `<ProgramData>` grant that lets
    // Users create folders: the rule would refuse it. A data root inside it,
    // prepared like the installer's, must still start, because the default
    // sequence checks the data root only as a parent and never its parent.
    let p = platform();
    let outer = std::env::temp_dir().join(format!(
        "rv-os-windows-outer-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&outer);
    fs::create_dir(&outer).unwrap();
    // Only SYSTEM, Administrators and the Users create grant, owned by
    // Administrators, so the Users entry is the one thing the rule refuses.
    prepare_root(&outer);
    icacls(&outer, &["/grant", "*S-1-5-32-545:(CI)(WD,AD,WEA,WA)"]);
    icacls(&outer, &["/setowner", "*S-1-5-32-544"]);
    let tree = Tree::new_in(&outer);
    // The default service sequence: agent.json, then each directory.
    p.open_config(&tree.join("agent.json"), Mode::Service)
        .unwrap()
        .unwrap();
    for (name, kind) in [
        ("state", DirKind::State),
        ("run", DirKind::Runtime),
        ("logs", DirKind::Log),
    ] {
        checked(&p, &tree.join(name), kind).unwrap();
    }
    assert_eq!(p.data_root(), Ok(None));
    // The outer directory really fails the rule when it is the one checked.
    let got = reason(
        checked(&p, &outer.join("state"), DirKind::State),
        Object::StateParent,
    );
    assert_eq!(got, insecure(USERS));
    drop(tree);
    let _ = fs::remove_dir_all(&outer);
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
    // The data root is never a separately checked object on Windows.
    assert_eq!(p.data_root(), Ok(None));
    let paths = p.default_paths().unwrap().unwrap();
    assert_eq!(
        paths.state_dir,
        program_data.join("Ricevanta").join("state")
    );
}
