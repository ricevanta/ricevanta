//! Typed agent configuration: defaults, validation, precedence and per-OS
//! default paths for `agent.json` (docs/specs/agent-runtime.md section 3).
//!
//! The loader reads an already opened and checked file (the `Platform` trait
//! of `ricevanta-os` performs the descriptor-based ownership and permission
//! checks), so this crate makes no OS calls and reads no environment variable.
//! Precedence, highest first: command-line flags ([`Overrides`]), the file,
//! built-in defaults.

use ricevanta_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The required value of the `schema` member.
pub const SCHEMA: &str = "ricevanta-agent-config-v1";
/// Bounds of `log.max_file_bytes`.
pub const MAX_FILE_BYTES_RANGE: (u64, u64) = (65_536, 268_435_456);
/// Bounds of `log.max_files`.
pub const MAX_FILES_RANGE: (u64, u64) = (1, 16);
/// Bounds of `health.interval_ms`.
pub const INTERVAL_MS_RANGE: (u64, u64) = (100, 3_600_000);
/// Bounds of `shutdown.timeout_ms`.
pub const TIMEOUT_MS_RANGE: (u64, u64) = (1_000, 60_000);
/// Upper bound of `shutdown.timeout_ms` on macOS (spec section 5.3).
pub const MACOS_TIMEOUT_MS_MAX: u64 = 15_000;
/// Bounds of a path value's length in Unicode scalar values.
pub const PATH_CHARS_RANGE: (usize, usize) = (2, 1_024);

/// The operating system whose rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux x64.
    Linux,
    /// macOS ARM64.
    MacOs,
    /// Windows x64.
    Windows,
}

impl Os {
    /// The operating system this crate was compiled for. Unix targets other
    /// than macOS follow the Linux rules; only the three supported targets
    /// are built.
    pub const fn host() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        }
    }
}

/// The command that selected the agent's mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Foreground `run` mode.
    Run,
    /// Service-manager `service` mode.
    Service,
}

/// `log.level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// `error`.
    Error,
    /// `warn`.
    Warn,
    /// `info`.
    Info,
    /// `debug`.
    Debug,
}

impl LogLevel {
    /// The configuration token.
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }

    fn parse(token: &str) -> Option<LogLevel> {
        match token {
            "error" => Some(LogLevel::Error),
            "warn" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            _ => None,
        }
    }
}

/// `log.sink`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSink {
    /// `agent.log` in the log directory.
    File,
    /// Standard error.
    Stderr,
}

impl LogSink {
    /// The configuration token, also accepted by `--log`.
    pub const fn as_str(self) -> &'static str {
        match self {
            LogSink::File => "file",
            LogSink::Stderr => "stderr",
        }
    }

    /// Parses a configuration or `--log` token.
    pub fn parse(token: &str) -> Option<LogSink> {
        match token {
            "file" => Some(LogSink::File),
            "stderr" => Some(LogSink::Stderr),
            _ => None,
        }
    }

    const fn default_for(mode: Mode) -> LogSink {
        match mode {
            Mode::Run => LogSink::Stderr,
            Mode::Service => LogSink::File,
        }
    }
}

/// The fixed per-OS locations of spec section 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultPaths {
    /// `agent.json`.
    pub config_file: PathBuf,
    /// State directory.
    pub state_dir: PathBuf,
    /// Runtime directory holding the health document.
    pub runtime_dir: PathBuf,
    /// Log directory.
    pub log_dir: PathBuf,
}

/// Returns the default locations for `os`.
///
/// On Windows they lie under `program_data`, the `FOLDERID_ProgramData`
/// known folder the caller resolved; without it the result is `None`.
/// `program_data` is ignored elsewhere.
pub fn default_paths(os: Os, program_data: Option<&Path>) -> Option<DefaultPaths> {
    match os {
        Os::Linux => Some(DefaultPaths {
            config_file: PathBuf::from("/etc/ricevanta/agent.json"),
            state_dir: PathBuf::from("/var/lib/ricevanta"),
            runtime_dir: PathBuf::from("/run/ricevanta"),
            log_dir: PathBuf::from("/var/log/ricevanta"),
        }),
        Os::MacOs => Some(DefaultPaths {
            config_file: PathBuf::from("/Library/Application Support/Ricevanta/agent.json"),
            state_dir: PathBuf::from("/Library/Application Support/Ricevanta/state"),
            runtime_dir: PathBuf::from("/Library/Application Support/Ricevanta/run"),
            log_dir: PathBuf::from("/Library/Logs/Ricevanta"),
        }),
        Os::Windows => {
            let root = program_data?;
            // Built as text with `\` so the result is the same on every host.
            let under = |leaf: &str| {
                let mut path = OsString::from(root.as_os_str());
                if !root.as_os_str().to_string_lossy().ends_with('\\') {
                    path.push("\\");
                }
                path.push("Ricevanta\\");
                path.push(leaf);
                PathBuf::from(path)
            };
            Some(DefaultPaths {
                config_file: under("agent.json"),
                state_dir: under("state"),
                runtime_dir: under("run"),
                log_dir: under("logs"),
            })
        }
    }
}

/// `log.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Lowest level written.
    pub level: LogLevel,
    /// Sink.
    pub sink: LogSink,
    /// Rotation threshold of the active file.
    pub max_file_bytes: u64,
    /// Number of files kept, the active one included.
    pub max_files: u32,
}

/// `health.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthConfig {
    /// Sampler tick and health document interval.
    pub interval_ms: u64,
}

/// `shutdown.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownConfig {
    /// Stop deadline before per-source caps.
    pub timeout_ms: u64,
}

/// `paths.*`; every path is absolute for its OS and valid UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathsConfig {
    /// State directory.
    pub state_dir: PathBuf,
    /// Runtime directory holding the health document.
    pub runtime_dir: PathBuf,
    /// Log directory.
    pub log_dir: PathBuf,
}

/// The effective agent configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// Logging.
    pub log: LogConfig,
    /// Health sampling.
    pub health: HealthConfig,
    /// Stop deadline.
    pub shutdown: ShutdownConfig,
    /// Directories.
    pub paths: PathsConfig,
}

impl AgentConfig {
    /// The built-in defaults for `os` and `mode`; `None` when the OS has no
    /// default paths in that mode (Windows `run`, or Windows without the
    /// resolved `program_data` known folder).
    pub fn default_for(os: Os, mode: Mode, program_data: Option<&Path>) -> Option<AgentConfig> {
        if os == Os::Windows && mode == Mode::Run {
            return None;
        }
        let paths = default_paths(os, program_data)?;
        Some(AgentConfig {
            log: LogConfig {
                level: LogLevel::Info,
                sink: LogSink::default_for(mode),
                max_file_bytes: 8_388_608,
                max_files: 4,
            },
            health: HealthConfig {
                interval_ms: 60_000,
            },
            shutdown: ShutdownConfig { timeout_ms: 10_000 },
            paths: PathsConfig {
                state_dir: paths.state_dir,
                runtime_dir: paths.runtime_dir,
                log_dir: paths.log_dir,
            },
        })
    }

    /// The complete configuration as a document that `load` accepts, for
    /// `check-config` and logs; encode it with `ricevanta_json::encode`.
    pub fn to_value(&self) -> Value {
        fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
            Value::Object(
                members
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect::<BTreeMap<_, _>>(),
            )
        }
        let int = |n: u64| Value::Integer(i64::try_from(n).unwrap_or(i64::MAX));
        // Paths are valid UTF-8 by construction (see `PathsConfig`).
        let path = |p: &Path| Value::String(p.to_string_lossy().into_owned());
        object([
            ("schema", Value::String(SCHEMA.to_owned())),
            (
                "log",
                object([
                    ("level", Value::String(self.log.level.as_str().to_owned())),
                    ("sink", Value::String(self.log.sink.as_str().to_owned())),
                    ("max_file_bytes", int(self.log.max_file_bytes)),
                    ("max_files", int(u64::from(self.log.max_files))),
                ]),
            ),
            (
                "health",
                object([("interval_ms", int(self.health.interval_ms))]),
            ),
            (
                "shutdown",
                object([("timeout_ms", int(self.shutdown.timeout_ms))]),
            ),
            (
                "paths",
                object([
                    ("state_dir", path(&self.paths.state_dir)),
                    ("runtime_dir", path(&self.paths.runtime_dir)),
                    ("log_dir", path(&self.paths.log_dir)),
                ]),
            ),
        ])
    }
}

/// Values given on the command line; each beats the file and the default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `--state-dir`.
    pub state_dir: Option<PathBuf>,
    /// `--runtime-dir`.
    pub runtime_dir: Option<PathBuf>,
    /// `--log-dir`.
    pub log_dir: Option<PathBuf>,
    /// `--log`.
    pub log_sink: Option<LogSink>,
}

/// Everything besides the file that decides the effective configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOptions {
    /// Target OS rules.
    pub os: Os,
    /// Command mode.
    pub mode: Mode,
    /// Command-line values.
    pub overrides: Overrides,
    /// Windows `FOLDERID_ProgramData`, resolved by the platform; unused
    /// elsewhere.
    pub program_data: Option<PathBuf>,
    /// The systemd watchdog period in microseconds when the watchdog is
    /// enabled for this process (`WATCHDOG_USEC`, with `WATCHDOG_PID` unset
    /// or equal to the own pid).
    pub watchdog_usec: Option<u64>,
}

impl LoadOptions {
    /// Options with no overrides, no data root and no watchdog.
    pub fn new(os: Os, mode: Mode) -> LoadOptions {
        LoadOptions {
            os,
            mode,
            overrides: Overrides::default(),
            program_data: None,
            watchdog_usec: None,
        }
    }
}

/// A configuration error. Every variant is a configuration or command-line
/// error (exit code 2), except [`Error::Read`] and [`Error::NoDataRoot`],
/// which the caller reports as startup failures.
#[derive(Debug)]
pub enum Error {
    /// Reading the opened file failed.
    Read(std::io::Error),
    /// The file is not strict-profile JSON.
    Json(ricevanta_json::Error),
    /// A required member is absent.
    Missing {
        /// JSON pointer of the absent member.
        pointer: String,
    },
    /// A member the schema does not define.
    UnknownKey {
        /// JSON pointer of the member.
        pointer: String,
    },
    /// A member of the wrong JSON type.
    WrongType {
        /// JSON pointer of the member; empty for the document itself.
        pointer: String,
    },
    /// An integer or length outside its bounds.
    OutOfBounds {
        /// JSON pointer of the member.
        pointer: String,
    },
    /// A value outside its token set, a wrong `schema`, or a path that is
    /// not absolute for the target OS.
    InvalidValue {
        /// JSON pointer of the member.
        pointer: String,
    },
    /// `health.interval_ms` cannot keep two watchdog pings inside one
    /// watchdog period (token `watchdog_interval_conflict`).
    WatchdogIntervalConflict {
        /// Effective interval.
        interval_ms: u64,
        /// `WATCHDOG_USEC`.
        watchdog_usec: u64,
    },
    /// A directory flag that Windows `run` requires is absent.
    MissingDirectoryFlag {
        /// The flag.
        flag: &'static str,
    },
    /// A directory flag is not an absolute, UTF-8 path for the target OS.
    InvalidPathFlag {
        /// The flag.
        flag: &'static str,
    },
    /// Windows `service` defaults were needed but no `program_data` was
    /// given because the platform could not resolve it.
    NoDataRoot,
}

impl Error {
    /// The JSON pointer of the offending member, when the error names one.
    pub fn pointer(&self) -> Option<&str> {
        match self {
            Error::Missing { pointer }
            | Error::UnknownKey { pointer }
            | Error::WrongType { pointer }
            | Error::OutOfBounds { pointer }
            | Error::InvalidValue { pointer } => Some(pointer),
            _ => None,
        }
    }

    /// A stable `snake_case` token for logs.
    pub fn token(&self) -> &'static str {
        match self {
            Error::Read(_) => "config_read_failed",
            Error::Json(_) => "config_json_invalid",
            Error::Missing { .. } => "config_member_missing",
            Error::UnknownKey { .. } => "config_unknown_key",
            Error::WrongType { .. } => "config_wrong_type",
            Error::OutOfBounds { .. } => "config_out_of_bounds",
            Error::InvalidValue { .. } => "config_invalid_value",
            Error::WatchdogIntervalConflict { .. } => "watchdog_interval_conflict",
            Error::MissingDirectoryFlag { .. } => "missing_directory_flag",
            Error::InvalidPathFlag { .. } => "invalid_path_flag",
            Error::NoDataRoot => "no_data_root",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Read(e) => write!(f, "reading configuration failed: {e}"),
            Error::Json(e) => write!(f, "configuration is not valid JSON: {e}"),
            Error::WatchdogIntervalConflict {
                interval_ms,
                watchdog_usec,
            } => write!(
                f,
                "health.interval_ms {interval_ms} exceeds half of WATCHDOG_USEC {watchdog_usec}"
            ),
            Error::MissingDirectoryFlag { flag } => write!(f, "{flag} is required"),
            Error::InvalidPathFlag { flag } => write!(f, "{flag} must be an absolute path"),
            Error::NoDataRoot => write!(f, "the ProgramData known folder is unavailable"),
            other => write!(
                f,
                "{} at {:?}",
                other.token(),
                other.pointer().unwrap_or_default()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Read(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

/// The members a file sets, validated against `config.schema.json` without
/// any OS rule. Absent members are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Document {
    /// `log.level`.
    pub log_level: Option<LogLevel>,
    /// `log.sink`.
    pub log_sink: Option<LogSink>,
    /// `log.max_file_bytes`.
    pub max_file_bytes: Option<u64>,
    /// `log.max_files`.
    pub max_files: Option<u32>,
    /// `health.interval_ms`.
    pub interval_ms: Option<u64>,
    /// `shutdown.timeout_ms`.
    pub timeout_ms: Option<u64>,
    /// `paths.state_dir`.
    pub state_dir: Option<String>,
    /// `paths.runtime_dir`.
    pub runtime_dir: Option<String>,
    /// `paths.log_dir`.
    pub log_dir: Option<String>,
}

/// Validates file bytes against the schema, OS-independently.
///
/// Error precedence: the strict JSON profile, then the document type, then
/// `/schema`, then the remaining members in canonical (byte) key order,
/// depth first. The first violation is returned.
pub fn validate_document(bytes: &[u8]) -> Result<Document, Error> {
    let value = ricevanta_json::parse(bytes).map_err(Error::Json)?;
    let root = value.as_object().ok_or_else(|| wrong_type(""))?;
    match root.get("schema") {
        None => return Err(missing("/schema")),
        Some(Value::String(s)) if s == SCHEMA => {}
        Some(Value::String(_)) => return Err(invalid("/schema")),
        Some(_) => return Err(wrong_type("/schema")),
    }
    let mut doc = Document::default();
    for (key, member) in root {
        let pointer = child("", key);
        match key.as_str() {
            "schema" => {}
            "log" => {
                for (key, item) in object(member, &pointer)? {
                    let pointer = child(&pointer, key);
                    match key.as_str() {
                        "level" => doc.log_level = Some(token(item, &pointer, LogLevel::parse)?),
                        "sink" => doc.log_sink = Some(token(item, &pointer, LogSink::parse)?),
                        "max_file_bytes" => {
                            doc.max_file_bytes =
                                Some(integer(item, &pointer, MAX_FILE_BYTES_RANGE)?);
                        }
                        "max_files" => {
                            let n = integer(item, &pointer, MAX_FILES_RANGE)?;
                            doc.max_files =
                                Some(u32::try_from(n).map_err(|_| out_of_bounds(&pointer))?);
                        }
                        _ => return Err(unknown(&pointer)),
                    }
                }
            }
            "health" => {
                for (key, item) in object(member, &pointer)? {
                    let pointer = child(&pointer, key);
                    match key.as_str() {
                        "interval_ms" => {
                            doc.interval_ms = Some(integer(item, &pointer, INTERVAL_MS_RANGE)?);
                        }
                        _ => return Err(unknown(&pointer)),
                    }
                }
            }
            "shutdown" => {
                for (key, item) in object(member, &pointer)? {
                    let pointer = child(&pointer, key);
                    match key.as_str() {
                        "timeout_ms" => {
                            doc.timeout_ms = Some(integer(item, &pointer, TIMEOUT_MS_RANGE)?);
                        }
                        _ => return Err(unknown(&pointer)),
                    }
                }
            }
            "paths" => {
                for (key, item) in object(member, &pointer)? {
                    let pointer = child(&pointer, key);
                    let slot = match key.as_str() {
                        "state_dir" => &mut doc.state_dir,
                        "runtime_dir" => &mut doc.runtime_dir,
                        "log_dir" => &mut doc.log_dir,
                        _ => return Err(unknown(&pointer)),
                    };
                    *slot = Some(schema_path(item, &pointer)?);
                }
            }
            _ => return Err(unknown(&pointer)),
        }
    }
    Ok(doc)
}

/// Loads the effective configuration.
///
/// `file` is the opened and checked `agent.json`, or `None` when it does not
/// exist (the caller logs `config_default`). At most
/// `ricevanta_json::MAX_INPUT_BYTES + 1` bytes are read, so a larger file is
/// rejected as too large without reading the rest. Error precedence: read,
/// document ([`validate_document`]), Windows `run` directory flags, flag
/// paths, file paths for the target OS, the macOS timeout cap, the data
/// root, then the watchdog rule. Nothing is created or modified.
pub fn load(file: Option<&mut dyn Read>, options: &LoadOptions) -> Result<AgentConfig, Error> {
    let doc = match file {
        None => Document::default(),
        Some(reader) => {
            let limit = ricevanta_json::MAX_INPUT_BYTES as u64 + 1;
            let mut bytes = Vec::new();
            reader
                .take(limit)
                .read_to_end(&mut bytes)
                .map_err(Error::Read)?;
            validate_document(&bytes)?
        }
    };
    let os = options.os;
    let flags = &options.overrides;
    if os == Os::Windows && options.mode == Mode::Run {
        for (flag, value) in [
            ("--state-dir", &flags.state_dir),
            ("--runtime-dir", &flags.runtime_dir),
            ("--log-dir", &flags.log_dir),
        ] {
            if value.is_none() {
                return Err(Error::MissingDirectoryFlag { flag });
            }
        }
    }
    let state_flag = flag_path(os, "--state-dir", &flags.state_dir)?;
    let runtime_flag = flag_path(os, "--runtime-dir", &flags.runtime_dir)?;
    let log_flag = flag_path(os, "--log-dir", &flags.log_dir)?;
    let state_dir = state_flag.or(os_path(os, "/paths/state_dir", &doc.state_dir)?);
    let runtime_dir = runtime_flag.or(os_path(os, "/paths/runtime_dir", &doc.runtime_dir)?);
    let log_dir = log_flag.or(os_path(os, "/paths/log_dir", &doc.log_dir)?);
    if os == Os::MacOs && doc.timeout_ms.is_some_and(|t| t > MACOS_TIMEOUT_MS_MAX) {
        return Err(out_of_bounds("/shutdown/timeout_ms"));
    }
    let paths = match (state_dir, runtime_dir, log_dir) {
        (Some(state_dir), Some(runtime_dir), Some(log_dir)) => PathsConfig {
            state_dir,
            runtime_dir,
            log_dir,
        },
        (state_dir, runtime_dir, log_dir) => {
            let defaults =
                default_paths(os, options.program_data.as_deref()).ok_or(Error::NoDataRoot)?;
            PathsConfig {
                state_dir: state_dir.unwrap_or(defaults.state_dir),
                runtime_dir: runtime_dir.unwrap_or(defaults.runtime_dir),
                log_dir: log_dir.unwrap_or(defaults.log_dir),
            }
        }
    };
    let config = AgentConfig {
        log: LogConfig {
            level: doc.log_level.unwrap_or(LogLevel::Info),
            sink: flags
                .log_sink
                .or(doc.log_sink)
                .unwrap_or(LogSink::default_for(options.mode)),
            max_file_bytes: doc.max_file_bytes.unwrap_or(8_388_608),
            max_files: doc.max_files.unwrap_or(4),
        },
        health: HealthConfig {
            interval_ms: doc.interval_ms.unwrap_or(60_000),
        },
        shutdown: ShutdownConfig {
            timeout_ms: doc.timeout_ms.unwrap_or(10_000),
        },
        paths,
    };
    if let Some(watchdog_usec) = options.watchdog_usec {
        // interval_ms * 1000 > watchdog_usec / 2, compared without rounding.
        let interval_ms = config.health.interval_ms;
        if u128::from(interval_ms) * 2_000 > u128::from(watchdog_usec) {
            return Err(Error::WatchdogIntervalConflict {
                interval_ms,
                watchdog_usec,
            });
        }
    }
    Ok(config)
}

fn child(parent: &str, key: &str) -> String {
    // RFC 6901: `~` becomes `~0`, `/` becomes `~1`.
    format!("{parent}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn missing(pointer: &str) -> Error {
    Error::Missing {
        pointer: pointer.to_owned(),
    }
}

fn unknown(pointer: &str) -> Error {
    Error::UnknownKey {
        pointer: pointer.to_owned(),
    }
}

fn wrong_type(pointer: &str) -> Error {
    Error::WrongType {
        pointer: pointer.to_owned(),
    }
}

fn out_of_bounds(pointer: &str) -> Error {
    Error::OutOfBounds {
        pointer: pointer.to_owned(),
    }
}

fn invalid(pointer: &str) -> Error {
    Error::InvalidValue {
        pointer: pointer.to_owned(),
    }
}

fn object<'a>(value: &'a Value, pointer: &str) -> Result<&'a BTreeMap<String, Value>, Error> {
    value.as_object().ok_or_else(|| wrong_type(pointer))
}

fn token<T>(value: &Value, pointer: &str, parse: fn(&str) -> Option<T>) -> Result<T, Error> {
    let text = value.as_str().ok_or_else(|| wrong_type(pointer))?;
    parse(text).ok_or_else(|| invalid(pointer))
}

fn integer(value: &Value, pointer: &str, (min, max): (u64, u64)) -> Result<u64, Error> {
    let n = value.as_i64().ok_or_else(|| wrong_type(pointer))?;
    match u64::try_from(n) {
        Ok(n) if (min..=max).contains(&n) => Ok(n),
        _ => Err(out_of_bounds(pointer)),
    }
}

fn length_ok(text: &str) -> bool {
    let chars = text.chars().count();
    (PATH_CHARS_RANGE.0..=PATH_CHARS_RANGE.1).contains(&chars)
}

/// The schema's `absolutePath`: 2 to 1,024 characters (length is checked
/// first), no NUL, and either a Unix form starting with `/` or a drive form
/// `X:\` followed by at least one character.
fn schema_path(value: &Value, pointer: &str) -> Result<String, Error> {
    let text = value.as_str().ok_or_else(|| wrong_type(pointer))?;
    if !length_ok(text) {
        return Err(out_of_bounds(pointer));
    }
    if !pattern_ok(text) {
        return Err(invalid(pointer));
    }
    Ok(text.to_owned())
}

fn pattern_ok(text: &str) -> bool {
    !text.contains('\0') && (is_unix_absolute(text) || is_drive_absolute(text))
}

fn is_unix_absolute(text: &str) -> bool {
    text.starts_with('/') && text.len() >= 2
}

fn is_drive_absolute(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 4 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

/// A directory path for `os`: absolute, and ending in a plain name. A path
/// ending in a separator, `.` or `..` is refused, because the OS would
/// resolve its preceding component as a directory and follow a symbolic link
/// there before `O_NOFOLLOW` or `FILE_FLAG_OPEN_REPARSE_POINT` applies.
fn absolute_for(os: Os, text: &str) -> bool {
    let absolute = match os {
        Os::Linux | Os::MacOs => is_unix_absolute(text),
        Os::Windows => is_drive_absolute(text),
    };
    absolute && ends_in_plain_name(os, Path::new(text))
}

/// Whether `path` ends in a plain name for `os`: not empty, not `.` or
/// `..`, and without a trailing separator. The core applies it to
/// `--config` so that a path the platform would refuse is a configuration
/// error (exit 2), as for directory values and flags.
pub fn ends_in_plain_name(os: Os, path: &Path) -> bool {
    let text = path.to_string_lossy();
    let separators: &[char] = match os {
        Os::Linux | Os::MacOs => &['/'],
        Os::Windows => &['\\', '/'],
    };
    let last = text.rsplit(separators).next().unwrap_or_default();
    !matches!(last, "" | "." | "..")
}

fn os_path(os: Os, pointer: &str, value: &Option<String>) -> Result<Option<PathBuf>, Error> {
    match value {
        None => Ok(None),
        Some(text) if absolute_for(os, text) => Ok(Some(PathBuf::from(text))),
        Some(_) => Err(invalid(pointer)),
    }
}

fn flag_path(
    os: Os,
    flag: &'static str,
    value: &Option<PathBuf>,
) -> Result<Option<PathBuf>, Error> {
    match value {
        None => Ok(None),
        Some(path) => match path.to_str() {
            Some(text) if length_ok(text) && pattern_ok(text) && absolute_for(os, text) => {
                Ok(Some(path.clone()))
            }
            _ => Err(Error::InvalidPathFlag { flag }),
        },
    }
}
