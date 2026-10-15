//! Portable operating-system traits of the agent runtime
//! (docs/specs/agent-runtime.md sections 1, 3.1, 5 and 7).
//!
//! This crate makes no OS calls. The native crates `ricevanta-os-linux`,
//! `ricevanta-os-macos` and `ricevanta-os-windows` implement
//! [`ProcessSampler`], [`ServiceManager`] and [`Platform`]; the core depends
//! on these traits so the lifecycle can be tested with fakes. The [`unix`]
//! module holds the Unix ownership and mode rules as pure functions over
//! facts read from an opened descriptor, shared by Linux and macOS.

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

pub use ricevanta_config::{DefaultPaths, Mode, Os};

/// The footprint metric of the OCSF `process_sample` object, fixed per OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FootprintMetric {
    /// macOS `ri_phys_footprint`.
    PhysFootprint,
    /// Windows `PrivateWorkingSetSize`.
    PrivateWorkingSet,
    /// Linux proportional set size from `smaps_rollup`.
    Pss,
}

impl FootprintMetric {
    /// The `footprint_metric` token.
    pub const fn as_str(self) -> &'static str {
        match self {
            FootprintMetric::PhysFootprint => "phys_footprint",
            FootprintMetric::PrivateWorkingSet => "private_working_set",
            FootprintMetric::Pss => "pss",
        }
    }
}

/// The descriptor count, whose kind is fixed per OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Descriptors {
    /// `fd_count` on macOS and Linux.
    Fds(u64),
    /// `handle_count` on Windows.
    Handles(u64),
}

/// One sample of the agent's own process (spec section 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSample {
    /// Memory footprint in bytes, measured as `footprint_metric` says.
    pub footprint_bytes: u64,
    /// The metric `footprint_bytes` uses.
    pub footprint_metric: FootprintMetric,
    /// User CPU time in milliseconds.
    pub cpu_user_ms: u64,
    /// System CPU time in milliseconds.
    pub cpu_system_ms: u64,
    /// Thread count, at least 1.
    pub threads: u32,
    /// Open descriptors or handles.
    pub descriptors: Descriptors,
}

/// Why a sample could not be taken. The agent keeps running and reports
/// `sampler_failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleError {
    /// An OS text source did not have the expected form.
    Format {
        /// The source, for example `/proc/self/stat`.
        source: &'static str,
    },
    /// Reading a source failed.
    Io {
        /// The I/O error kind.
        kind: io::ErrorKind,
        /// The raw OS error code, when there is one.
        code: Option<i32>,
    },
    /// An OS call failed with this code.
    Os {
        /// The raw OS error code.
        code: i32,
    },
    /// The OS does not provide the metric (for example a zero
    /// `PrivateWorkingSetSize` on an old Windows build).
    Unsupported,
}

impl SampleError {
    /// A [`SampleError::Io`] from an I/O error.
    pub fn io(error: &io::Error) -> SampleError {
        SampleError::Io {
            kind: error.kind(),
            code: error.raw_os_error(),
        }
    }
}

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SampleError::Format { source } => write!(f, "unexpected format in {source}"),
            SampleError::Io { kind, code } => write!(f, "sampler I/O error {kind:?} ({code:?})"),
            SampleError::Os { code } => write!(f, "sampler OS error {code}"),
            SampleError::Unsupported => write!(f, "metric unsupported by this OS build"),
        }
    }
}

impl std::error::Error for SampleError {}

/// Samples the agent's own process.
pub trait ProcessSampler: Send + Sync {
    /// Takes one sample. Must complete within 50 ms and allocate at most
    /// 64 KiB (spec section 7).
    fn sample(&self) -> Result<ProcessSample, SampleError>;
}

/// The agent lifecycle states reported to the service manager and in the
/// health document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Startup in progress.
    Starting,
    /// Running.
    Ready,
    /// Stop in progress.
    Stopping,
    /// Stopped.
    Stopped,
}

impl LifecycleState {
    /// The `state` token.
    pub const fn as_str(self) -> &'static str {
        match self {
            LifecycleState::Starting => "starting",
            LifecycleState::Ready => "ready",
            LifecycleState::Stopping => "stopping",
            LifecycleState::Stopped => "stopped",
        }
    }
}

/// A service-manager notification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyError {
    /// The notification address is not one this agent supports.
    Address,
    /// A service-manager environment variable has an invalid value.
    Environment {
        /// The variable name.
        variable: &'static str,
    },
    /// Sending failed.
    Io {
        /// The I/O error kind.
        kind: io::ErrorKind,
        /// The raw OS error code, when there is one.
        code: Option<i32>,
    },
}

impl NotifyError {
    /// A [`NotifyError::Io`] from an I/O error.
    pub fn io(error: &io::Error) -> NotifyError {
        NotifyError::Io {
            kind: error.kind(),
            code: error.raw_os_error(),
        }
    }
}

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotifyError::Address => write!(f, "unsupported notification address"),
            NotifyError::Environment { variable } => write!(f, "invalid {variable}"),
            NotifyError::Io { kind, code } => {
                write!(f, "notification I/O error {kind:?} ({code:?})")
            }
        }
    }
}

impl std::error::Error for NotifyError {}

/// Service-manager notifications (spec section 5). Every method is a no-op
/// returning `Ok` when no service manager listens.
pub trait ServiceManager: Send + Sync {
    /// Reports readiness (`READY=1`).
    fn ready(&self) -> Result<(), NotifyError>;
    /// Reports a state change (`STATUS=<state>`).
    fn status(&self, state: LifecycleState) -> Result<(), NotifyError>;
    /// Reports one completed sampler tick (`WATCHDOG=1`) when a watchdog is
    /// enabled for this process.
    fn watchdog(&self) -> Result<(), NotifyError>;
    /// Reports that a stop began (`STOPPING=1`).
    fn stopping(&self) -> Result<(), NotifyError>;
}

/// The directories the agent opens or creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirKind {
    /// The data root holding `agent.json`, `state` and `run` (macOS
    /// `/Library/Application Support/Ricevanta`, Windows
    /// `<ProgramData>\Ricevanta`).
    DataRoot,
    /// The state directory.
    State,
    /// The runtime directory holding the health document.
    Runtime,
    /// The log directory.
    Log,
}

impl DirKind {
    /// The exact Unix mode the directory must have.
    pub const fn unix_mode(self) -> u32 {
        match self {
            DirKind::DataRoot | DirKind::Runtime => 0o755,
            DirKind::State | DirKind::Log => 0o700,
        }
    }

    /// The object this directory is reported as.
    pub const fn object(self) -> Object {
        match self {
            DirKind::DataRoot => Object::DataRoot,
            DirKind::State => Object::StateDir,
            DirKind::Runtime => Object::RuntimeDir,
            DirKind::Log => Object::LogDir,
        }
    }
}

/// The files the agent creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `health.json.tmp`, created or truncated, then renamed over
    /// `health.json`.
    HealthDocument,
    /// A log file, created or opened for appending.
    Log,
}

impl FileKind {
    /// The exact Unix mode the file is given.
    pub const fn unix_mode(self) -> u32 {
        match self {
            FileKind::HealthDocument => 0o644,
            FileKind::Log => 0o600,
        }
    }

    /// The object this file is reported as.
    pub const fn object(self) -> Object {
        match self {
            FileKind::HealthDocument => Object::HealthDocument,
            FileKind::Log => Object::LogFile,
        }
    }
}

/// The object a protection check failed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// `agent.json`.
    ConfigFile,
    /// The directory holding `agent.json`.
    ConfigParent,
    /// The data root.
    DataRoot,
    /// The state directory.
    StateDir,
    /// The runtime directory.
    RuntimeDir,
    /// The log directory.
    LogDir,
    /// The health document.
    HealthDocument,
    /// A log file.
    LogFile,
}

impl Object {
    /// A stable `snake_case` token for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Object::ConfigFile => "config_file",
            Object::ConfigParent => "config_parent",
            Object::DataRoot => "data_root",
            Object::StateDir => "state_dir",
            Object::RuntimeDir => "runtime_dir",
            Object::LogDir => "log_dir",
            Object::HealthDocument => "health_document",
            Object::LogFile => "log_file",
        }
    }
}

/// Why an object failed its protection check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// The path names a symbolic link; `code` is the open's OS error
    /// (`ELOOP` for a file opened with `O_NOFOLLOW`).
    SymbolicLink {
        /// The raw OS error code of the refused open.
        code: Option<i32>,
    },
    /// Not a regular file (a FIFO, device, socket or directory).
    NotRegularFile,
    /// Not a directory.
    NotDirectory,
    /// The owner is not one the rule accepts.
    Owner {
        /// The owner's uid.
        uid: u32,
    },
    /// The permission bits are not the required ones.
    Mode {
        /// The permission bits found (`st_mode & 0o7777`).
        mode: u32,
    },
    /// The parent directory of `agent.json` is group- or world-writable.
    ParentWritable {
        /// The permission bits found.
        mode: u32,
    },
    /// Windows: the object is a reparse point.
    ReparsePoint,
    /// Windows: the owner SID is neither Local System nor Administrators.
    OwnerSid {
        /// The owner SID in string form.
        sid: String,
    },
    /// Windows: the DACL is absent or null, or an entry grants a right to
    /// another principal or has an unsupported type (`insecure_acl`).
    InsecureAcl {
        /// The offending SID in string form, when an entry names one.
        sid: Option<String>,
    },
    /// Opening, creating or inspecting the object failed.
    Io {
        /// The I/O error kind.
        kind: io::ErrorKind,
        /// The raw OS error code, when there is one.
        code: Option<i32>,
    },
}

impl Reason {
    /// A [`Reason::Io`] from an I/O error.
    pub fn io(error: &io::Error) -> Reason {
        Reason::Io {
            kind: error.kind(),
            code: error.raw_os_error(),
        }
    }

    /// A stable `snake_case` token for logs.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Reason::SymbolicLink { .. } => "symbolic_link",
            Reason::NotRegularFile => "not_regular_file",
            Reason::NotDirectory => "not_directory",
            Reason::Owner { .. } | Reason::OwnerSid { .. } => "insecure_owner",
            Reason::Mode { .. } => "insecure_mode",
            Reason::ParentWritable { .. } => "parent_writable",
            Reason::ReparsePoint => "reparse_point",
            Reason::InsecureAcl { .. } => "insecure_acl",
            Reason::Io { .. } => "io_error",
        }
    }
}

/// A failed protection check: `startup_failed` with exit code 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionError {
    /// The object checked.
    pub object: Object,
    /// Why it failed.
    pub reason: Reason,
}

impl ProtectionError {
    /// A new error.
    pub fn new(object: Object, reason: Reason) -> ProtectionError {
        ProtectionError { object, reason }
    }
}

impl fmt::Display for ProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({:?})",
            self.object.as_str(),
            self.reason.as_str(),
            self.reason
        )
    }
}

impl std::error::Error for ProtectionError {}

/// Per-OS locations and the descriptor-based protection checks of spec
/// section 3.1. Every check runs on the opened descriptor or handle, never on
/// a path; no method falls back to defaults or a weaker mode.
pub trait Platform: Send + Sync {
    /// The OS whose rules this platform applies.
    fn os(&self) -> Os;

    /// The data root to create or verify before the other directories:
    /// macOS `/Library/Application Support/Ricevanta`, Windows
    /// `<ProgramData>\Ricevanta`; `None` on Linux, where systemd creates the
    /// directories.
    fn data_root(&self) -> Result<Option<PathBuf>, ProtectionError>;

    /// The `FOLDERID_ProgramData` known folder on Windows, `None` elsewhere.
    fn program_data(&self) -> Result<Option<PathBuf>, ProtectionError>;

    /// The default locations of spec section 3.
    fn default_paths(&self) -> Result<Option<DefaultPaths>, ProtectionError> {
        Ok(ricevanta_config::default_paths(
            self.os(),
            self.program_data()?.as_deref(),
        ))
    }

    /// The footprint metric this OS reports.
    fn footprint_metric(&self) -> FootprintMetric;

    /// Opens `agent.json` read-only without following a final symbolic link
    /// and without blocking, checks its parent directory and then the opened
    /// file, and returns it for reading. `Ok(None)` when the file or its
    /// parent does not exist.
    fn open_config(&self, path: &Path, mode: Mode) -> Result<Option<File>, ProtectionError>;

    /// Opens the directory `path`, creating it when missing (never its
    /// parents), and checks owner and exact mode. A created directory is
    /// given its exact mode on the opened descriptor; an existing one is
    /// never re-moded.
    fn open_or_create_dir(
        &self,
        path: &Path,
        kind: DirKind,
        mode: Mode,
    ) -> Result<File, ProtectionError>;

    /// Creates (or truncates or appends to, by `kind`) a file the agent
    /// writes, without following a final symbolic link, checks the opened
    /// descriptor and sets the file's exact mode on it.
    fn create_file(&self, path: &Path, kind: FileKind) -> Result<File, ProtectionError>;
}

/// Unix ownership and mode rules over facts from an opened descriptor.
///
/// Check order is type, then owner, then mode, so the first failing property
/// in that order is reported.
pub mod unix {
    use super::{DirKind, Mode, Reason};

    /// The file type of an opened object.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Kind {
        /// Regular file.
        Regular,
        /// Directory.
        Directory,
        /// Symbolic link.
        Symlink,
        /// FIFO, socket or device.
        Other,
    }

    /// Facts read with `fstat` on an opened descriptor.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Facts {
        /// File type.
        pub kind: Kind,
        /// `st_mode`; only the low twelve bits are judged.
        pub mode: u32,
        /// `st_uid`.
        pub uid: u32,
    }

    impl Facts {
        fn perm(&self) -> u32 {
            self.mode & 0o7777
        }
    }

    /// The owner a directory must have: root in `service` mode, the
    /// effective user in `run` mode.
    pub const fn dir_owner(mode: Mode, euid: u32) -> u32 {
        match mode {
            Mode::Service => 0,
            Mode::Run => euid,
        }
    }

    /// `agent.json`: a regular file owned by the effective user or root
    /// (only root when the effective user is root) with mode exactly `0600`
    /// or `0400`.
    pub fn check_config_file(facts: &Facts, euid: u32) -> Result<(), Reason> {
        if facts.kind != Kind::Regular {
            return Err(Reason::NotRegularFile);
        }
        if facts.uid != euid && facts.uid != 0 {
            return Err(Reason::Owner { uid: facts.uid });
        }
        match facts.perm() {
            0o600 | 0o400 => Ok(()),
            mode => Err(Reason::Mode { mode }),
        }
    }

    /// The parent of `agent.json`: a directory owned by the effective user
    /// or root that is neither group- nor world-writable.
    pub fn check_config_parent(facts: &Facts, euid: u32) -> Result<(), Reason> {
        if facts.kind != Kind::Directory {
            return Err(Reason::NotDirectory);
        }
        if facts.uid != euid && facts.uid != 0 {
            return Err(Reason::Owner { uid: facts.uid });
        }
        if facts.perm() & 0o022 != 0 {
            return Err(Reason::ParentWritable { mode: facts.perm() });
        }
        Ok(())
    }

    /// An agent directory: owned by [`dir_owner`] with exactly
    /// [`DirKind::unix_mode`].
    pub fn check_dir(facts: &Facts, kind: DirKind, mode: Mode, euid: u32) -> Result<(), Reason> {
        check_dir_owner(facts, mode, euid)?;
        match facts.perm() {
            m if m == kind.unix_mode() => Ok(()),
            m => Err(Reason::Mode { mode: m }),
        }
    }

    /// The type and owner part of [`check_dir`], applied to a freshly
    /// created directory before its mode is set.
    pub fn check_dir_owner(facts: &Facts, mode: Mode, euid: u32) -> Result<(), Reason> {
        if facts.kind != Kind::Directory {
            return Err(Reason::NotDirectory);
        }
        if facts.uid != dir_owner(mode, euid) {
            return Err(Reason::Owner { uid: facts.uid });
        }
        Ok(())
    }

    /// A file the agent creates: a regular file owned by the effective user.
    /// Its mode is then set exactly on the descriptor.
    pub fn check_created_file(facts: &Facts, euid: u32) -> Result<(), Reason> {
        if facts.kind != Kind::Regular {
            return Err(Reason::NotRegularFile);
        }
        if facts.uid != euid {
            return Err(Reason::Owner { uid: facts.uid });
        }
        Ok(())
    }
}
