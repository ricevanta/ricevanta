//! File protection on Windows (spec section 3.1).
//!
//! In `service` mode every checked object (`agent.json`, its parent, the
//! state, runtime and log directories and each directory's parent; in the
//! default layout the data root is that parent, and `<ProgramData>` is never
//! checked) is opened with `FILE_FLAG_OPEN_REPARSE_POINT`
//! (and `FILE_FLAG_BACKUP_SEMANTICS` for directories) and
//! `READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA`, refused when it is
//! a reparse point, and judged by its owner and DACL read with
//! `GetSecurityInfo` on that handle. Files inside a checked directory are
//! created by path, as the spec allows on Windows, each opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT` and refused when it is a reparse point.
//! Every path is in normal form and every name a plain Windows name, which
//! Win32 normalisation leaves unchanged (no trailing period or space, no
//! reserved device name), so the final component checked is the final
//! component opened. In `run` mode nothing is checked and missing
//! directories are created with inherited permissions.

use crate::{dacl, sys};
use ricevanta_os::{
    CheckedDir, DirKind, FileKind, FootprintMetric, Mode, Object, Os, Platform, ProtectionError,
    Reason, is_normal_form, is_plain_name,
};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, READ_CONTROL,
};

/// The Windows [`Platform`].
#[derive(Debug, Clone)]
pub struct WindowsPlatform {
    program_data: PathBuf,
}

impl WindowsPlatform {
    /// Resolves `FOLDERID_ProgramData` with `SHGetKnownFolderPath`, never
    /// from `%ProgramData%`; a failed lookup is a startup failure.
    pub fn new() -> Result<WindowsPlatform, ProtectionError> {
        let program_data = sys::program_data()
            .map_err(|e| ProtectionError::new(Object::DataRoot, Reason::io(e)))?;
        Ok(WindowsPlatform {
            program_data: PathBuf::from(program_data),
        })
    }
}

fn path_form(object: Object) -> ProtectionError {
    ProtectionError::new(object, Reason::PathForm)
}

fn io_error(object: Object) -> impl Fn(io::Error) -> ProtectionError {
    move |e| ProtectionError::new(object, Reason::io(e))
}

/// Splits a normal-form drive path into its parent and final name.
fn split(path: &Path, object: Object) -> Result<(PathBuf, OsString), ProtectionError> {
    let text = path.to_str().ok_or_else(|| path_form(object))?;
    if !is_normal_form(Os::Windows, text) {
        return Err(path_form(object));
    }
    let at = text.rfind('\\').ok_or_else(|| path_form(object))?;
    // `C:\x` has the drive root `C:\` as parent.
    let parent = if at == 2 { &text[..3] } else { &text[..at] };
    Ok((PathBuf::from(parent), OsString::from(&text[at + 1..])))
}

fn check_name(name: &OsStr, object: Object) -> Result<(), ProtectionError> {
    match name.to_str() {
        Some(text) if is_plain_name(Os::Windows, text) => Ok(()),
        _ => Err(path_form(object)),
    }
}

/// Opens an object for inspection without following a reparse point.
/// `FILE_FLAG_BACKUP_SEMANTICS` is always set, as the standard library does
/// for every open, so a directory or directory junction planted where a file
/// is expected opens and is reported as what it is.
fn open_object(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// The type and reparse-point part of the rule, on the opened handle.
fn check_kind(file: &File, object: Object, directory: bool) -> Result<(), ProtectionError> {
    let metadata = file.metadata().map_err(io_error(object))?;
    let fail = |reason| Err(ProtectionError::new(object, reason));
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return fail(Reason::ReparsePoint);
    }
    match (directory, metadata.is_dir(), metadata.is_file()) {
        (true, true, _) | (false, _, true) => Ok(()),
        (true, false, _) => fail(Reason::NotDirectory),
        (false, _, false) => fail(Reason::NotRegularFile),
    }
}

/// The whole `service`-mode rule on an opened handle.
fn check_object(file: &File, object: Object, directory: bool) -> Result<(), ProtectionError> {
    check_kind(file, object, directory)?;
    let facts = sys::security(file).map_err(io_error(object))?;
    dacl::evaluate(&facts).map_err(|r| ProtectionError::new(object, r))
}

impl Platform for WindowsPlatform {
    fn os(&self) -> Os {
        Os::Windows
    }

    fn data_root(&self) -> Result<Option<PathBuf>, ProtectionError> {
        // Checked only as the parent of `agent.json` and the directories;
        // a separate check would open `<ProgramData>` as its parent, whose
        // default DACL lets Users create folders (spec section 3.1).
        Ok(None)
    }

    fn program_data(&self) -> Result<Option<PathBuf>, ProtectionError> {
        Ok(Some(self.program_data.clone()))
    }

    fn footprint_metric(&self) -> FootprintMetric {
        FootprintMetric::PrivateWorkingSet
    }

    fn open_config(&self, path: &Path, mode: Mode) -> Result<Option<File>, ProtectionError> {
        let (parent, _name) = split(path, Object::ConfigFile)?;
        if mode == Mode::Run {
            // A development run checks nothing (spec section 3.1).
            return match File::open(path) {
                Ok(file) => Ok(Some(file)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(ProtectionError::new(Object::ConfigFile, Reason::io(e))),
            };
        }
        let parent_dir = match open_object(&parent) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ProtectionError::new(Object::ConfigParent, Reason::io(e))),
        };
        check_object(&parent_dir, Object::ConfigParent, true)?;
        let file = match open_object(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ProtectionError::new(Object::ConfigFile, Reason::io(e))),
        };
        check_object(&file, Object::ConfigFile, false)?;
        Ok(Some(file))
    }

    fn open_parent(
        &self,
        path: &Path,
        kind: DirKind,
        mode: Mode,
    ) -> Result<(CheckedDir, OsString), ProtectionError> {
        let (parent, name) = split(path, kind.object())?;
        let object = kind.parent_object();
        let dir = open_object(&parent).map_err(io_error(object))?;
        if mode == Mode::Service {
            // The parent rule on Windows is the same owner and DACL rule:
            // it leaves no other principal any right, group write included.
            check_object(&dir, object, true)?;
        }
        Ok((CheckedDir::new(dir, object, parent), name))
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
        let target = parent.path().join(name);
        let dir = match open_object(&target) {
            Ok(dir) => dir,
            // The agent never creates these objects in `service` mode; the
            // installer does (spec section 3.1).
            Err(e) if e.kind() == io::ErrorKind::NotFound && mode == Mode::Run => {
                match std::fs::create_dir(&target) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(ProtectionError::new(object, Reason::io(e))),
                }
                open_object(&target).map_err(io_error(object))?
            }
            Err(e) => return Err(ProtectionError::new(object, Reason::io(e))),
        };
        match mode {
            Mode::Service => check_object(&dir, object, true)?,
            Mode::Run => {}
        }
        Ok(CheckedDir::new(dir, object, target))
    }

    fn create_file(
        &self,
        dir: &CheckedDir,
        name: &OsStr,
        kind: FileKind,
    ) -> Result<File, ProtectionError> {
        let object = kind.object();
        check_name(name, object)?;
        let target = dir.path().join(name);
        // An existing object is inspected first with backup semantics, so a
        // planted junction or directory is reported as what it is rather than
        // as a failed open for writing.
        if let Ok(existing) = open_object(&target) {
            check_kind(&existing, object, false)?;
        }
        let mut options = OpenOptions::new();
        options
            .create(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        // Never truncating on open: a reparse point stays untouched.
        match kind {
            FileKind::HealthDocument => options.write(true),
            FileKind::Log => options.append(true),
        };
        let file = options.open(&target).map_err(io_error(object))?;
        check_kind(&file, object, false)?;
        if kind == FileKind::HealthDocument {
            file.set_len(0).map_err(io_error(object))?;
        }
        Ok(file)
    }

    fn rename_in(&self, dir: &CheckedDir, from: &OsStr, to: &OsStr) -> Result<(), ProtectionError> {
        let object = dir.object();
        check_name(from, object)?;
        check_name(to, object)?;
        std::fs::rename(dir.path().join(from), dir.path().join(to)).map_err(io_error(object))
    }

    fn remove_in(&self, dir: &CheckedDir, name: &OsStr) -> Result<(), ProtectionError> {
        let object = dir.object();
        check_name(name, object)?;
        match std::fs::remove_file(dir.path().join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProtectionError::new(object, Reason::io(e))),
        }
    }
}
