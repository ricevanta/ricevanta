//! Descriptor-based file protection on Linux (spec section 3.1).

use crate::procfs::{BUFFER_BYTES, STATUS, parse_status_euid, read_bounded};
use ricevanta_os::unix::{
    Facts, Kind, check_config_file, check_config_parent, check_created_file, check_dir,
    check_dir_owner,
};
use ricevanta_os::{
    DirKind, FileKind, FootprintMetric, Mode, Object, Os, Platform, ProtectionError, Reason,
};
use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::io;
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
        let mut buffer = [0u8; BUFFER_BYTES];
        let euid = read_bounded(STATUS, &mut buffer)
            .and_then(parse_status_euid)
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
        .map_err(|e| ProtectionError::new(object, Reason::io(&e)))?;
    Ok(Facts {
        kind: kind_of(&metadata),
        mode: metadata.mode(),
        uid: metadata.uid(),
    })
}

/// Names the reason a refused open failed. The decision is already made;
/// the `lstat` here only chooses the reported reason.
fn open_failure(path: &Path, error: &io::Error, object: Object) -> ProtectionError {
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

fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(path)
}

fn set_mode(file: &File, mode: u32, object: Object) -> Result<(), ProtectionError> {
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(|e| ProtectionError::new(object, Reason::io(&e)))
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
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let parent_dir = match open_dir(parent) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(open_failure(parent, &e, Object::ConfigParent)),
        };
        let parent_facts = facts(&parent_dir, Object::ConfigParent)?;
        check_config_parent(&parent_facts, self.euid)
            .map_err(|r| ProtectionError::new(Object::ConfigParent, r))?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAGS)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(open_failure(path, &e, Object::ConfigFile)),
        };
        self.check_opened_config(&file, mode)?;
        Ok(Some(file))
    }

    fn open_or_create_dir(
        &self,
        path: &Path,
        kind: DirKind,
        mode: Mode,
    ) -> Result<File, ProtectionError> {
        let object = kind.object();
        let fail = |reason| ProtectionError::new(object, reason);
        let existing = match open_dir(path) {
            Ok(dir) => Some(dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(open_failure(path, &e, object)),
        };
        if let Some(dir) = existing {
            check_dir(&facts(&dir, object)?, kind, mode, self.euid).map_err(fail)?;
            return Ok(dir);
        }
        let created = match DirBuilder::new().mode(kind.unix_mode()).create(path) {
            Ok(()) => true,
            // Another process created it first: judge it as existing.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(fail(Reason::io(&e))),
        };
        let dir = open_dir(path).map_err(|e| open_failure(path, &e, object))?;
        if created {
            check_dir_owner(&facts(&dir, object)?, mode, self.euid).map_err(fail)?;
            // mkdir applied the umask; set the exact mode on the descriptor.
            set_mode(&dir, kind.unix_mode(), object)?;
        }
        check_dir(&facts(&dir, object)?, kind, mode, self.euid).map_err(fail)?;
        Ok(dir)
    }

    fn create_file(&self, path: &Path, kind: FileKind) -> Result<File, ProtectionError> {
        let object = kind.object();
        let mut options = OpenOptions::new();
        options
            .create(true)
            .mode(kind.unix_mode())
            .custom_flags(FILE_FLAGS);
        match kind {
            FileKind::HealthDocument => options.write(true).truncate(true),
            FileKind::Log => options.append(true),
        };
        let file = options
            .open(path)
            .map_err(|e| open_failure(path, &e, object))?;
        check_created_file(&facts(&file, object)?, self.euid)
            .map_err(|r| ProtectionError::new(object, r))?;
        set_mode(&file, kind.unix_mode(), object)?;
        Ok(file)
    }
}
