//! Descriptor-based file protection on macOS (spec section 3.1).
//!
//! A path is used only to reach a parent directory, opened with
//! `O_DIRECTORY | O_NOFOLLOW` and checked on its descriptor. Every checked
//! or created object is also checked for an extended ACL: xnu evaluates an
//! ACL before the mode bits, so only deny entries are accepted. Everything below
//! a checked directory goes through `openat`, `mkdirat`, `renameat` and
//! `unlinkat` on that descriptor, never through the directory's path.

use crate::sys;
use ricevanta_os::unix::{
    Facts, Kind, check_config_file, check_config_parent, check_created_file, check_dir,
    check_dir_owner, check_parent,
};
use ricevanta_os::{
    CheckedDir, DirKind, FileKind, FootprintMetric, Mode, Object, Os, Platform, ProtectionError,
    Reason, is_normal_form, is_plain_name,
};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, OpenOptions, Permissions};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Flags for every open: never follow a final symbolic link, close on exec,
/// and never wait for a FIFO writer or reader.
const FILE_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
/// Flags for every directory open.
const DIR_FLAGS: i32 = libc::O_DIRECTORY | FILE_FLAGS;
/// The data root, parent of `agent.json`, `state` and `run`.
const DATA_ROOT: &str = "/Library/Application Support/Ricevanta";

/// The macOS [`Platform`].
#[derive(Debug, Clone)]
pub struct MacPlatform {
    euid: u32,
}

impl MacPlatform {
    /// Learns the effective uid without a `libc` call: xnu's `pipe_stat`
    /// reports a pipe's owner as `kauth_getuid()` of the process calling
    /// `fstat`, the credential's `cr_uid`, which `bsd/sys/ucred.h` names
    /// the effective user id.
    pub fn new() -> io::Result<MacPlatform> {
        let (reader, _writer) = std::io::pipe()?;
        let euid = File::from(OwnedFd::from(reader)).metadata()?.uid();
        Ok(MacPlatform { euid })
    }

    /// The effective uid the ownership rules compare against.
    pub fn euid(&self) -> u32 {
        self.euid
    }

    /// Checks an already opened `agent.json` descriptor: regular file, owner
    /// the effective user or root, mode `0600` or `0400`; `mode` is accepted
    /// for symmetry with Windows.
    pub fn check_opened_config(&self, file: &File, mode: Mode) -> Result<(), ProtectionError> {
        let _ = mode;
        let facts = facts(file, Object::ConfigFile)?;
        check_config_file(&facts, self.euid)
            .map_err(|r| ProtectionError::new(Object::ConfigFile, r))?;
        check_acl(file, Object::ConfigFile)
    }
}

fn kind_of(metadata: &std::fs::Metadata) -> Kind {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        Kind::Regular
    } else if file_type.is_dir() {
        Kind::Directory
    } else if file_type.is_symlink() {
        Kind::Symlink
    } else {
        Kind::Other
    }
}

fn facts(file: &File, object: Object) -> Result<Facts, ProtectionError> {
    let metadata = file
        .metadata()
        .map_err(|e| ProtectionError::new(object, Reason::io(e)))?;
    Ok(Facts {
        kind: kind_of(&metadata),
        mode: metadata.mode(),
        uid: metadata.uid(),
    })
}

/// Names the reason a refused open failed. `ELOOP` is a final symbolic link
/// refused by `O_NOFOLLOW`; for `ENOTDIR` the `lstat` of `diagnostic` only
/// chooses the reported reason, the decision being already made.
fn open_failure(diagnostic: &Path, error: io::Error, object: Object) -> ProtectionError {
    let code = error.raw_os_error();
    let is_link = code == Some(libc::ELOOP)
        || (code == Some(libc::ENOTDIR)
            && std::fs::symlink_metadata(diagnostic).is_ok_and(|m| m.file_type().is_symlink()));
    let reason = if is_link {
        Reason::SymbolicLink { code }
    } else if code == Some(libc::ENOTDIR) {
        Reason::NotDirectory
    } else {
        Reason::io(error)
    };
    ProtectionError::new(object, reason)
}

/// The extended-ACL part of the rule (spec section 3.1), on the opened
/// descriptor: a failed call or any entry other than a deny entry is
/// `insecure_acl`.
fn check_acl(file: &File, object: Object) -> Result<(), ProtectionError> {
    let insecure = || ProtectionError::new(object, Reason::InsecureAcl { sid: None });
    let reply = sys::extended_security(file).map_err(|_| insecure())?;
    crate::acl::check_extended_security(&reply.0).map_err(|_| insecure())
}

fn path_form(object: Object) -> ProtectionError {
    ProtectionError::new(object, Reason::PathForm)
}

/// Splits a normal-form absolute path into its parent and final name.
fn split(path: &Path, object: Object) -> Result<(PathBuf, OsString), ProtectionError> {
    let text = path.to_str().ok_or_else(|| path_form(object))?;
    if !is_normal_form(Os::MacOs, text) {
        return Err(path_form(object));
    }
    let at = text.rfind('/').ok_or_else(|| path_form(object))?;
    let parent = if at == 0 { "/" } else { &text[..at] };
    Ok((PathBuf::from(parent), OsString::from(&text[at + 1..])))
}

/// A name inside a checked directory, as a C string for the `*at` calls.
fn c_name(name: &OsStr, object: Object) -> Result<CString, ProtectionError> {
    match name.to_str() {
        Some(text) if is_plain_name(Os::MacOs, text) => {
            CString::new(name.as_bytes()).map_err(|_| path_form(object))
        }
        _ => Err(path_form(object)),
    }
}

fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(path)
}

fn set_mode(file: &File, mode: u32, object: Object) -> Result<(), ProtectionError> {
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(|e| ProtectionError::new(object, Reason::io(e)))
}

/// Whether the open directory has no entries. `/dev/fd/<fd>` opens a
/// duplicate of the directory descriptor, so the listing is of the checked
/// directory itself.
fn is_empty(dir: &File, object: Object) -> Result<bool, ProtectionError> {
    let mut entries = std::fs::read_dir(format!("/dev/fd/{}", dir.as_raw_fd()))
        .map_err(|e| ProtectionError::new(object, Reason::io(e)))?;
    Ok(entries.next().is_none())
}

fn mode16(mode: u32) -> u16 {
    // Every mode used here is at most 0o755.
    u16::try_from(mode).unwrap_or(0)
}

impl MacPlatform {
    fn checked_parent(
        &self,
        path: PathBuf,
        group_write_allowed: bool,
        mode: Mode,
        object: Object,
    ) -> Result<CheckedDir, ProtectionError> {
        let dir = open_dir(&path).map_err(|e| open_failure(&path, e, object))?;
        check_parent(&facts(&dir, object)?, group_write_allowed, mode, self.euid)
            .map_err(|r| ProtectionError::new(object, r))?;
        check_acl(&dir, object)?;
        Ok(CheckedDir::new(dir, object, path))
    }
}

impl Platform for MacPlatform {
    fn os(&self) -> Os {
        Os::MacOs
    }

    fn data_root(&self) -> Result<Option<PathBuf>, ProtectionError> {
        Ok(Some(PathBuf::from(DATA_ROOT)))
    }

    fn program_data(&self) -> Result<Option<PathBuf>, ProtectionError> {
        Ok(None)
    }

    fn footprint_metric(&self) -> FootprintMetric {
        FootprintMetric::PhysFootprint
    }

    fn open_config(&self, path: &Path, mode: Mode) -> Result<Option<File>, ProtectionError> {
        let (parent, name) = split(path, Object::ConfigFile)?;
        let c = c_name(&name, Object::ConfigFile)?;
        let parent_dir = match open_dir(&parent) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(open_failure(&parent, e, Object::ConfigParent)),
        };
        check_config_parent(&facts(&parent_dir, Object::ConfigParent)?, mode, self.euid)
            .map_err(|r| ProtectionError::new(Object::ConfigParent, r))?;
        check_acl(&parent_dir, Object::ConfigParent)?;
        let file = match sys::openat(&parent_dir, &c, libc::O_RDONLY | FILE_FLAGS, 0) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(open_failure(path, e, Object::ConfigFile)),
        };
        self.check_opened_config(&file, mode)?;
        Ok(Some(file))
    }

    fn open_parent(
        &self,
        path: &Path,
        kind: DirKind,
        mode: Mode,
    ) -> Result<(CheckedDir, OsString), ProtectionError> {
        let (parent, name) = split(path, kind.object())?;
        let dir = self.checked_parent(
            parent,
            kind.parent_group_write_allowed(),
            mode,
            kind.parent_object(),
        )?;
        Ok((dir, name))
    }

    fn open_or_create_dir(
        &self,
        parent: &CheckedDir,
        name: &OsStr,
        kind: DirKind,
        mode: Mode,
    ) -> Result<CheckedDir, ProtectionError> {
        let object = kind.object();
        let c = c_name(name, object)?;
        let fail = |reason| ProtectionError::new(object, reason);
        let diagnostic = parent.path().join(name);
        let open = || sys::openat(parent.file(), &c, libc::O_RDONLY | DIR_FLAGS, 0);
        let mut created = false;
        let dir = match open() {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match sys::mkdirat(parent.file(), &c, mode16(kind.unix_mode())) {
                    Ok(()) => created = true,
                    // Another process created it first: judge it as existing.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(fail(Reason::io(e))),
                }
                open().map_err(|e| open_failure(&diagnostic, e, object))?
            }
            Err(e) => return Err(open_failure(&diagnostic, e, object)),
        };
        if created {
            check_dir_owner(&facts(&dir, object)?, mode, self.euid).map_err(fail)?;
            // mkdirat applied the umask; set the exact mode on the
            // descriptor, but only on the empty directory this call made.
            if is_empty(&dir, object)? {
                set_mode(&dir, kind.unix_mode(), object)?;
            }
        }
        check_dir(&facts(&dir, object)?, kind, mode, self.euid).map_err(fail)?;
        check_acl(&dir, object)?;
        Ok(CheckedDir::new(dir, object, diagnostic))
    }

    fn create_file(
        &self,
        dir: &CheckedDir,
        name: &OsStr,
        kind: FileKind,
    ) -> Result<File, ProtectionError> {
        let object = kind.object();
        let c = c_name(name, object)?;
        // Never `O_TRUNC`: a file that fails the check stays untouched.
        let access = match kind {
            FileKind::HealthDocument => libc::O_WRONLY,
            FileKind::Log => libc::O_WRONLY | libc::O_APPEND,
        };
        let file = sys::openat(
            dir.file(),
            &c,
            access | libc::O_CREAT | FILE_FLAGS,
            mode16(kind.unix_mode()),
        )
        .map_err(|e| open_failure(&dir.path().join(name), e, object))?;
        check_created_file(&facts(&file, object)?, self.euid)
            .map_err(|r| ProtectionError::new(object, r))?;
        // A new file inherits its parent's inheritable entries; the parent
        // was checked to carry none but deny entries, so this recheck
        // proves the file did not gain an allow entry either.
        check_acl(&file, object)?;
        set_mode(&file, kind.unix_mode(), object)?;
        if kind == FileKind::HealthDocument {
            file.set_len(0)
                .map_err(|e| ProtectionError::new(object, Reason::io(e)))?;
        }
        Ok(file)
    }

    fn rename_in(&self, dir: &CheckedDir, from: &OsStr, to: &OsStr) -> Result<(), ProtectionError> {
        let object = dir.object();
        let from = c_name(from, object)?;
        let to = c_name(to, object)?;
        sys::renameat(dir.file(), &from, &to)
            .map_err(|e| ProtectionError::new(object, Reason::io(e)))
    }

    fn remove_in(&self, dir: &CheckedDir, name: &OsStr) -> Result<(), ProtectionError> {
        let object = dir.object();
        let c = c_name(name, object)?;
        match sys::unlinkat(dir.file(), &c) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProtectionError::new(object, Reason::io(e))),
        }
    }
}
