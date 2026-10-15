//! Descriptor-based file protection on Linux (spec section 3.1).
//!
//! A path is used only to reach a parent directory, which is opened with
//! `O_DIRECTORY | O_NOFOLLOW` and checked on its descriptor. Everything below
//! a checked directory is reached as `/proc/self/fd/<descriptor>/<name>`: the
//! descriptor entry is a magic link to the open directory itself, so the name
//! is looked up in the directory that was checked, never by resolving the
//! directory's path again, and only the standard library is needed.

use crate::procfs::{STATUS, open, status_euid};
use ricevanta_os::unix::{
    Facts, Kind, check_config_file, check_config_parent, check_created_file, check_dir,
    check_dir_owner, check_parent,
};
use ricevanta_os::{
    CheckedDir, DirKind, FileKind, FootprintMetric, Mode, Object, Os, Platform, ProtectionError,
    Reason,
};
use std::ffi::{OsStr, OsString};
use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Flags for every file open: never follow a final symbolic link, close on
/// exec, and never wait for a FIFO writer or reader.
const FILE_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
/// Flags for every directory open.
const DIR_FLAGS: i32 = libc::O_DIRECTORY | FILE_FLAGS;

/// The Linux [`Platform`].
#[derive(Debug, Clone)]
pub struct LinuxPlatform {
    euid: u32,
}

impl LinuxPlatform {
    /// Reads the effective uid from `/proc/self/status`.
    pub fn new() -> io::Result<LinuxPlatform> {
        let euid = open(STATUS)
            .and_then(status_euid)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(LinuxPlatform { euid })
    }

    /// The effective uid the ownership rules compare against.
    pub fn euid(&self) -> u32 {
        self.euid
    }

    /// Checks an already opened `agent.json` descriptor: regular file, owner
    /// the effective user or root, mode `0600` or `0400`. The rule is the
    /// same in both modes; `mode` is accepted for symmetry with Windows,
    /// where `run` mode checks nothing.
    pub fn check_opened_config(&self, file: &File, mode: Mode) -> Result<(), ProtectionError> {
        let _ = mode;
        let facts = facts(file, Object::ConfigFile)?;
        check_config_file(&facts, self.euid)
            .map_err(|r| ProtectionError::new(Object::ConfigFile, r))
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
        // FIFO, socket, block or character device.
        Kind::Other
    }
}

/// `fstat` facts of an opened descriptor.
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

/// Names the reason a refused open failed. The decision is already made;
/// the `lstat` here only chooses the reported reason.
fn open_failure(path: &Path, error: io::Error, object: Object) -> ProtectionError {
    let is_link = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    let reason = if is_link {
        Reason::SymbolicLink {
            code: error.raw_os_error(),
        }
    } else if error.kind() == io::ErrorKind::NotADirectory {
        Reason::NotDirectory
    } else {
        Reason::io(error)
    };
    ProtectionError::new(object, reason)
}

fn path_form(object: Object) -> ProtectionError {
    ProtectionError::new(object, Reason::PathForm)
}

/// Splits `path` into its parent and plain final name. A path that is
/// empty, ends in `/`, or ends in `.` or `..` has no plain final name: the
/// kernel would resolve the preceding component as a directory, following a
/// symbolic link there, before `O_NOFOLLOW` applies. A path without a parent
/// component has the current directory as parent.
fn split(path: &Path, object: Object) -> Result<(PathBuf, OsString), ProtectionError> {
    let bytes = path.as_os_str().as_bytes();
    let (parent, name) = match bytes.iter().rposition(|&b| b == b'/') {
        Some(0) => (&b"/"[..], &bytes[1..]),
        Some(at) => (&bytes[..at], &bytes[at + 1..]),
        None => (&b"."[..], bytes),
    };
    check_name(OsStr::from_bytes(name), object)?;
    Ok((
        PathBuf::from(OsStr::from_bytes(parent)),
        OsStr::from_bytes(name).to_os_string(),
    ))
}

/// A name inside a checked directory: not empty, `.` or `..`, and without a
/// separator.
fn check_name(name: &OsStr, object: Object) -> Result<(), ProtectionError> {
    let bytes = name.as_bytes();
    if matches!(bytes, b"" | b"." | b"..") || bytes.contains(&b'/') {
        return Err(path_form(object));
    }
    Ok(())
}

/// `/proc/self/fd/<fd>/<name>`: `name` looked up inside the open directory.
fn relative(dir: &File, name: &OsStr) -> PathBuf {
    let mut path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    path.push(name);
    path
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

/// Whether the open directory has no entries.
fn is_empty(dir: &File, object: Object) -> Result<bool, ProtectionError> {
    let mut entries = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|e| ProtectionError::new(object, Reason::io(e)))?;
    Ok(entries.next().is_none())
}

impl LinuxPlatform {
    /// Opens the directory at `path` and checks it with the parent rule.
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
        Ok(CheckedDir::new(dir, object, path))
    }
}

impl Platform for LinuxPlatform {
    fn os(&self) -> Os {
        Os::Linux
    }

    fn data_root(&self) -> Result<Option<PathBuf>, ProtectionError> {
        Ok(None)
    }

    fn program_data(&self) -> Result<Option<PathBuf>, ProtectionError> {
        Ok(None)
    }

    fn footprint_metric(&self) -> FootprintMetric {
        FootprintMetric::Pss
    }

    fn open_config(&self, path: &Path, mode: Mode) -> Result<Option<File>, ProtectionError> {
        let (parent, name) = split(path, Object::ConfigFile)?;
        let parent_dir = match open_dir(&parent) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(open_failure(&parent, e, Object::ConfigParent)),
        };
        check_config_parent(&facts(&parent_dir, Object::ConfigParent)?, mode, self.euid)
            .map_err(|r| ProtectionError::new(Object::ConfigParent, r))?;
        let target = relative(&parent_dir, &name);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAGS)
            .open(&target)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(open_failure(&target, e, Object::ConfigFile)),
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
        check_name(name, object)?;
        let fail = |reason| ProtectionError::new(object, reason);
        let target = relative(parent.file(), name);
        let mut created = false;
        let dir = match open_dir(&target) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match DirBuilder::new().mode(kind.unix_mode()).create(&target) {
                    Ok(()) => created = true,
                    // Another process created it first: judge it as existing.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(fail(Reason::io(e))),
                }
                open_dir(&target).map_err(|e| open_failure(&target, e, object))?
            }
            Err(e) => return Err(open_failure(&target, e, object)),
        };
        if created {
            check_dir_owner(&facts(&dir, object)?, mode, self.euid).map_err(fail)?;
            // mkdir applied the umask. Set the exact mode on the descriptor,
            // but only on the empty directory this call made: a directory
            // swapped in or filled since is judged as it is.
            if is_empty(&dir, object)? {
                set_mode(&dir, kind.unix_mode(), object)?;
            }
        }
        check_dir(&facts(&dir, object)?, kind, mode, self.euid).map_err(fail)?;
        Ok(CheckedDir::new(dir, object, parent.path().join(name)))
    }

    fn create_file(
        &self,
        dir: &CheckedDir,
        name: &OsStr,
        kind: FileKind,
    ) -> Result<File, ProtectionError> {
        let object = kind.object();
        check_name(name, object)?;
        let target = relative(dir.file(), name);
        let mut options = OpenOptions::new();
        options
            .create(true)
            .mode(kind.unix_mode())
            .custom_flags(FILE_FLAGS);
        // Never `O_TRUNC`: a file that fails the check stays untouched.
        match kind {
            FileKind::HealthDocument => options.write(true),
            FileKind::Log => options.append(true),
        };
        let file = options
            .open(&target)
            .map_err(|e| open_failure(&target, e, object))?;
        check_created_file(&facts(&file, object)?, self.euid)
            .map_err(|r| ProtectionError::new(object, r))?;
        set_mode(&file, kind.unix_mode(), object)?;
        if kind == FileKind::HealthDocument {
            file.set_len(0)
                .map_err(|e| ProtectionError::new(object, Reason::io(e)))?;
        }
        Ok(file)
    }

    fn rename_in(&self, dir: &CheckedDir, from: &OsStr, to: &OsStr) -> Result<(), ProtectionError> {
        let object = dir.object();
        check_name(from, object)?;
        check_name(to, object)?;
        std::fs::rename(relative(dir.file(), from), relative(dir.file(), to))
            .map_err(|e| ProtectionError::new(object, Reason::io(e)))
    }

    fn remove_in(&self, dir: &CheckedDir, name: &OsStr) -> Result<(), ProtectionError> {
        let object = dir.object();
        check_name(name, object)?;
        match std::fs::remove_file(relative(dir.file(), name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProtectionError::new(object, Reason::io(e))),
        }
    }
}
