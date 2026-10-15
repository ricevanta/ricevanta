//! Precedence, bounds and per-OS rules of the configuration loader.

use ricevanta_config::{
    AgentConfig, Error, LoadOptions, LogLevel, LogSink, Mode, Os, SCHEMA, default_paths,
    is_normal_form, is_plain_name, load,
};
use std::io::Read;
use std::path::{Path, PathBuf};

fn doc(body: &str) -> Vec<u8> {
    format!("{{\"schema\":\"{SCHEMA}\"{body}}}").into_bytes()
}

fn load_bytes(bytes: &[u8], options: &LoadOptions) -> Result<AgentConfig, Error> {
    load(Some(&mut &bytes[..]), options)
}

fn linux_run() -> LoadOptions {
    LoadOptions::new(Os::Linux, Mode::Run)
}

#[test]
fn missing_file_equals_defaults() {
    for (os, mode) in [
        (Os::Linux, Mode::Run),
        (Os::Linux, Mode::Service),
        (Os::MacOs, Mode::Run),
        (Os::MacOs, Mode::Service),
    ] {
        let options = LoadOptions::new(os, mode);
        assert_eq!(
            load(None, &options).unwrap(),
            AgentConfig::default_for(os, mode, None).unwrap()
        );
    }
    let config = load(None, &linux_run()).unwrap();
    assert_eq!(config.log.level, LogLevel::Info);
    assert_eq!(config.log.sink, LogSink::Stderr);
    assert_eq!(config.log.max_file_bytes, 8_388_608);
    assert_eq!(config.log.max_files, 4);
    assert_eq!(config.health.interval_ms, 60_000);
    assert_eq!(config.shutdown.timeout_ms, 10_000);
    let service = load(None, &LoadOptions::new(Os::Linux, Mode::Service)).unwrap();
    assert_eq!(service.log.sink, LogSink::File);
}

#[test]
fn precedence_flag_over_file_over_default() {
    let file = doc(
        r#","log":{"sink":"file","level":"debug"},"paths":{"state_dir":"/srv/state","log_dir":"/srv/log"}"#,
    );
    let mut options = linux_run();
    options.overrides.state_dir = Some(PathBuf::from("/flag/state"));
    options.overrides.log_sink = Some(LogSink::Stderr);
    let config = load_bytes(&file, &options).unwrap();
    // Flag beats file.
    assert_eq!(config.paths.state_dir, Path::new("/flag/state"));
    assert_eq!(config.log.sink, LogSink::Stderr);
    // File beats default.
    assert_eq!(config.paths.log_dir, Path::new("/srv/log"));
    assert_eq!(config.log.level, LogLevel::Debug);
    // Default fills the rest.
    assert_eq!(config.paths.runtime_dir, Path::new("/run/ricevanta"));
    assert_eq!(config.health.interval_ms, 60_000);
    // The file's sink beats the mode default.
    let config = load_bytes(&file, &linux_run()).unwrap();
    assert_eq!(config.log.sink, LogSink::File);
}

#[test]
fn oversized_file_is_rejected() {
    let mut bytes = doc(r#","log":{"level":"info"}"#);
    let pad = 65_537 - bytes.len();
    bytes.splice(1..1, std::iter::repeat_n(b' ', pad));
    assert_eq!(bytes.len(), 65_537);
    assert!(matches!(
        load_bytes(&bytes, &linux_run()),
        Err(Error::Json(ricevanta_json::Error::TooLarge { .. }))
    ));
    // Exactly the limit is read completely.
    bytes.remove(1);
    assert!(load_bytes(&bytes, &linux_run()).is_ok());
}

#[test]
fn read_is_bounded_for_an_endless_file() {
    /// Yields spaces without end and counts what the loader consumed.
    struct Endless(u64);
    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            buffer.fill(b' ');
            self.0 += buffer.len() as u64;
            Ok(buffer.len())
        }
    }
    let mut endless = Endless(0);
    let result = load(Some(&mut endless), &linux_run());
    assert!(matches!(
        result,
        Err(Error::Json(ricevanta_json::Error::TooLarge { .. }))
    ));
    assert!(endless.0 <= 65_537, "consumed {} bytes", endless.0);
}

#[test]
fn directory_paths_must_end_in_a_plain_name() {
    let unix_bad = [
        "/srv/state/",
        "/srv/state/.",
        "/srv/state/..",
        "/srv/.",
        "//",
    ];
    for bad in unix_bad {
        let body = format!(r#","paths":{{"runtime_dir":"{bad}"}}"#);
        assert!(
            matches!(
                load_bytes(&doc(&body), &linux_run()),
                Err(Error::InvalidValue { pointer }) if pointer == "/paths/runtime_dir"
            ),
            "{bad}"
        );
        let mut options = LoadOptions::new(Os::MacOs, Mode::Run);
        options.overrides.state_dir = Some(PathBuf::from(bad));
        assert!(
            matches!(
                load(None, &options),
                Err(Error::InvalidPathFlag {
                    flag: "--state-dir"
                })
            ),
            "{bad}"
        );
    }
    let mut windows = LoadOptions::new(Os::Windows, Mode::Run);
    windows.overrides.state_dir = Some(PathBuf::from(r"C:\dev\state"));
    windows.overrides.runtime_dir = Some(PathBuf::from(r"C:\dev\run"));
    for bad in [
        r"C:\dev\logs\",
        r"C:\dev\logs\.",
        r"C:\dev\..",
        r"C:\dev\logs/",
    ] {
        windows.overrides.log_dir = Some(PathBuf::from(bad));
        assert!(
            matches!(
                load(None, &windows),
                Err(Error::InvalidPathFlag { flag: "--log-dir" })
            ),
            "{bad}"
        );
    }
    let file = doc(r#","paths":{"log_dir":"C:\\dev\\logs\\"}"#);
    let mut service = LoadOptions::new(Os::Windows, Mode::Service);
    service.program_data = Some(PathBuf::from(r"C:\ProgramData"));
    assert!(matches!(
        load_bytes(&file, &service),
        Err(Error::InvalidValue { pointer }) if pointer == "/paths/log_dir"
    ));
    // A dot inside a name is still a plain name.
    let ok = doc(r#","paths":{"state_dir":"/srv/.state","log_dir":"/srv/log.d"}"#);
    assert!(load_bytes(&ok, &linux_run()).is_ok());
}

#[test]
fn reader_failure_is_reported() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected"))
        }
    }
    let result = load(Some(&mut Failing), &linux_run());
    assert!(matches!(result, Err(Error::Read(_))));
}

#[test]
fn duplicate_key_is_rejected() {
    let bytes = doc(r#","health":{"interval_ms":1000,"interval_ms":2000}"#);
    assert!(matches!(
        load_bytes(&bytes, &linux_run()),
        Err(Error::Json(ricevanta_json::Error::DuplicateKey { .. }))
    ));
}

#[test]
fn members_are_typed_bounded_and_named_by_pointer() {
    type Check = fn(&Error) -> bool;
    let cases: &[(&str, Check)] = &[
        (
            r#","log":{"level":"trace"}"#,
            |e| matches!(e, Error::InvalidValue { pointer } if pointer == "/log/level"),
        ),
        (
            r#","log":{"sink":"syslog"}"#,
            |e| matches!(e, Error::InvalidValue { pointer } if pointer == "/log/sink"),
        ),
        (
            r#","log":{"max_file_bytes":65535}"#,
            |e| matches!(e, Error::OutOfBounds { pointer } if pointer == "/log/max_file_bytes"),
        ),
        (
            r#","log":{"max_file_bytes":268435457}"#,
            |e| matches!(e, Error::OutOfBounds { pointer } if pointer == "/log/max_file_bytes"),
        ),
        (
            r#","log":{"max_files":0}"#,
            |e| matches!(e, Error::OutOfBounds { pointer } if pointer == "/log/max_files"),
        ),
        (
            r#","log":{"max_files":17}"#,
            |e| matches!(e, Error::OutOfBounds { pointer } if pointer == "/log/max_files"),
        ),
        (
            r#","log":{"max_files":"4"}"#,
            |e| matches!(e, Error::WrongType { pointer } if pointer == "/log/max_files"),
        ),
        (
            r#","log":[]"#,
            |e| matches!(e, Error::WrongType { pointer } if pointer == "/log"),
        ),
        (
            r#","health":{"interval_ms":3600001}"#,
            |e| matches!(e, Error::OutOfBounds { pointer } if pointer == "/health/interval_ms"),
        ),
        (
            r#","shutdown":{"timeout_ms":999}"#,
            |e| matches!(e, Error::OutOfBounds { pointer } if pointer == "/shutdown/timeout_ms"),
        ),
        (
            r#","shutdown":{"grace":1}"#,
            |e| matches!(e, Error::UnknownKey { pointer } if pointer == "/shutdown/grace"),
        ),
        (
            r#","a/b~c":1"#,
            |e| matches!(e, Error::UnknownKey { pointer } if pointer == "/a~1b~0c"),
        ),
        (
            r#","paths":{"state_dir":"/"}"#,
            |e| matches!(e, Error::OutOfBounds { pointer } if pointer == "/paths/state_dir"),
        ),
        (
            r#","paths":{"log_dir":"/a\u0000b"}"#,
            |e| matches!(e, Error::InvalidValue { pointer } if pointer == "/paths/log_dir"),
        ),
        (
            r#","paths":{"runtime_dir":true}"#,
            |e| matches!(e, Error::WrongType { pointer } if pointer == "/paths/runtime_dir"),
        ),
    ];
    for (body, check) in cases {
        let result = load_bytes(&doc(body), &linux_run());
        let error = result.expect_err(body);
        assert!(check(&error), "{body}: {error:?}");
    }
    let long = format!(r#","paths":{{"state_dir":"/{}"}}"#, "a".repeat(1023));
    assert!(load_bytes(&doc(&long), &linux_run()).is_ok());
    let too_long = format!(r#","paths":{{"state_dir":"/{}"}}"#, "a".repeat(1024));
    assert!(matches!(
        load_bytes(&doc(&too_long), &linux_run()),
        Err(Error::OutOfBounds { .. })
    ));
    assert!(matches!(
        load_bytes(b"[]", &linux_run()),
        Err(Error::WrongType { pointer }) if pointer.is_empty()
    ));
}

#[test]
fn schema_is_checked_before_other_members() {
    let bytes = br#"{"zzz":1,"schema":"other"}"#;
    assert!(matches!(
        load_bytes(bytes, &linux_run()),
        Err(Error::InvalidValue { pointer }) if pointer == "/schema"
    ));
    let bytes = br#"{"health":{"interval_ms":1},"log":{"level":1}}"#;
    assert!(matches!(
        load_bytes(bytes, &linux_run()),
        Err(Error::Missing { pointer }) if pointer == "/schema"
    ));
    // Remaining members follow canonical key order.
    let bytes = doc(r#","log":{"level":1},"health":{"interval_ms":1}"#);
    assert!(matches!(
        load_bytes(&bytes, &linux_run()),
        Err(Error::OutOfBounds { pointer }) if pointer == "/health/interval_ms"
    ));
}

#[test]
fn shutdown_timeout_is_capped_on_macos() {
    let at_cap = doc(r#","shutdown":{"timeout_ms":15000}"#);
    let over = doc(r#","shutdown":{"timeout_ms":15001}"#);
    let macos = LoadOptions::new(Os::MacOs, Mode::Service);
    assert_eq!(
        load_bytes(&at_cap, &macos).unwrap().shutdown.timeout_ms,
        15_000
    );
    assert!(matches!(
        load_bytes(&over, &macos),
        Err(Error::OutOfBounds { pointer }) if pointer == "/shutdown/timeout_ms"
    ));
    assert_eq!(
        load_bytes(&over, &linux_run()).unwrap().shutdown.timeout_ms,
        15_001
    );
}

#[test]
fn watchdog_interval_rule() {
    let interval = |ms: u64| doc(&format!(r#","health":{{"interval_ms":{ms}}}"#));
    let mut options = LoadOptions::new(Os::Linux, Mode::Service);
    options.watchdog_usec = Some(180_000_000);
    assert!(load_bytes(&interval(90_000), &options).is_ok());
    assert!(matches!(
        load_bytes(&interval(90_001), &options),
        Err(Error::WatchdogIntervalConflict {
            interval_ms: 90_001,
            watchdog_usec: 180_000_000
        })
    ));
    options.watchdog_usec = Some(60_000_000);
    assert!(matches!(
        load(None, &options),
        Err(Error::WatchdogIntervalConflict {
            interval_ms: 60_000,
            ..
        })
    ));
    assert!(load_bytes(&interval(30_000), &options).is_ok());
    assert_eq!(
        Error::WatchdogIntervalConflict {
            interval_ms: 1,
            watchdog_usec: 1
        }
        .token(),
        "watchdog_interval_conflict"
    );
}

#[test]
fn windows_run_requires_directory_flags() {
    let mut options = LoadOptions::new(Os::Windows, Mode::Run);
    assert!(matches!(
        load(None, &options),
        Err(Error::MissingDirectoryFlag {
            flag: "--state-dir"
        })
    ));
    options.overrides.state_dir = Some(PathBuf::from(r"C:\dev\state"));
    assert!(matches!(
        load(None, &options),
        Err(Error::MissingDirectoryFlag {
            flag: "--runtime-dir"
        })
    ));
    options.overrides.runtime_dir = Some(PathBuf::from(r"C:\dev\run"));
    // A file naming the log directory does not replace the required flag.
    let file = doc(r#","paths":{"log_dir":"C:\\dev\\logs"}"#);
    assert!(matches!(
        load_bytes(&file, &options),
        Err(Error::MissingDirectoryFlag { flag: "--log-dir" })
    ));
    options.overrides.log_dir = Some(PathBuf::from(r"C:\dev\logs"));
    let config = load(None, &options).unwrap();
    assert_eq!(config.log.sink, LogSink::Stderr);
    assert_eq!(config.paths.log_dir, Path::new(r"C:\dev\logs"));
    assert!(AgentConfig::default_for(Os::Windows, Mode::Run, None).is_none());
}

#[test]
fn windows_service_defaults_come_from_program_data() {
    let root = Path::new(r"C:\ProgramData");
    let paths = default_paths(Os::Windows, Some(root)).unwrap();
    assert_eq!(
        paths.config_file,
        Path::new(r"C:\ProgramData\Ricevanta\agent.json")
    );
    assert_eq!(
        paths.state_dir,
        Path::new(r"C:\ProgramData\Ricevanta\state")
    );
    assert_eq!(
        paths.runtime_dir,
        Path::new(r"C:\ProgramData\Ricevanta\run")
    );
    assert_eq!(paths.log_dir, Path::new(r"C:\ProgramData\Ricevanta\logs"));
    assert!(default_paths(Os::Windows, None).is_none());
    let mut options = LoadOptions::new(Os::Windows, Mode::Service);
    assert!(matches!(load(None, &options), Err(Error::NoDataRoot)));
    options.program_data = Some(root.to_path_buf());
    let config = load(None, &options).unwrap();
    assert_eq!(config.paths.state_dir, paths.state_dir);
    assert_eq!(config.log.sink, LogSink::File);
}

#[test]
fn unix_default_paths() {
    let linux = default_paths(Os::Linux, None).unwrap();
    assert_eq!(linux.config_file, Path::new("/etc/ricevanta/agent.json"));
    assert_eq!(linux.state_dir, Path::new("/var/lib/ricevanta"));
    assert_eq!(linux.runtime_dir, Path::new("/run/ricevanta"));
    assert_eq!(linux.log_dir, Path::new("/var/log/ricevanta"));
    let macos = default_paths(Os::MacOs, None).unwrap();
    assert_eq!(
        macos.config_file,
        Path::new("/Library/Application Support/Ricevanta/agent.json")
    );
    assert_eq!(
        macos.state_dir,
        Path::new("/Library/Application Support/Ricevanta/state")
    );
    assert_eq!(
        macos.runtime_dir,
        Path::new("/Library/Application Support/Ricevanta/run")
    );
    assert_eq!(macos.log_dir, Path::new("/Library/Logs/Ricevanta"));
}

#[test]
fn paths_must_be_absolute_for_the_target_os() {
    let windows_form = doc(r#","paths":{"state_dir":"C:\\state"}"#);
    assert!(matches!(
        load_bytes(&windows_form, &linux_run()),
        Err(Error::InvalidValue { pointer }) if pointer == "/paths/state_dir"
    ));
    let unix_form = doc(r#","paths":{"state_dir":"/state"}"#);
    let mut windows = LoadOptions::new(Os::Windows, Mode::Service);
    windows.program_data = Some(PathBuf::from(r"C:\ProgramData"));
    assert!(matches!(
        load_bytes(&unix_form, &windows),
        Err(Error::InvalidValue { pointer }) if pointer == "/paths/state_dir"
    ));
    let mut options = linux_run();
    options.overrides.log_dir = Some(PathBuf::from("relative/logs"));
    assert!(matches!(
        load(None, &options),
        Err(Error::InvalidPathFlag { flag: "--log-dir" })
    ));
}

#[test]
fn effective_configuration_is_canonical_json() {
    let mut options = linux_run();
    options.overrides.runtime_dir = Some(PathBuf::from("/tmp/run"));
    let config = load(None, &options).unwrap();
    let text = ricevanta_json::encode(&config.to_value());
    assert_eq!(
        text,
        concat!(
            r#"{"health":{"interval_ms":60000},"#,
            r#""log":{"level":"info","max_file_bytes":8388608,"max_files":4,"sink":"stderr"},"#,
            r#""paths":{"log_dir":"/var/log/ricevanta","runtime_dir":"/tmp/run","state_dir":"/var/lib/ricevanta"},"#,
            r#""schema":"ricevanta-agent-config-v1","shutdown":{"timeout_ms":10000}}"#
        )
    );
    // The effective configuration is itself a valid configuration file.
    assert_eq!(load_bytes(text.as_bytes(), &options).unwrap(), config);
}

#[test]
fn host_os_matches_target() {
    let host = Os::host();
    if cfg!(target_os = "linux") {
        assert_eq!(host, Os::Linux);
    } else if cfg!(target_os = "macos") {
        assert_eq!(host, Os::MacOs);
    } else if cfg!(windows) {
        assert_eq!(host, Os::Windows);
    }
}

#[test]
fn normal_form_paths() {
    let unix_good = [
        "/etc/ricevanta/agent.json",
        "/a",
        "/srv/.state",
        "/srv/log.d",
        "/a/b c/...x",
        "/C:/x",
    ];
    let unix_bad = [
        "",
        "/",
        "agent.json",
        "./a",
        "//a",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/a/.",
        "/a/..",
        "/a/",
        "/a\0b",
        r"C:\x",
    ];
    for good in unix_good {
        assert!(is_normal_form(Os::Linux, good), "{good:?}");
        assert!(is_normal_form(Os::MacOs, good), "{good:?}");
        assert!(!is_normal_form(Os::Windows, good), "{good:?}");
    }
    for bad in unix_bad {
        assert!(!is_normal_form(Os::Linux, bad), "{bad:?}");
    }
    let windows_good = [
        r"C:\ProgramData\Ricevanta\state",
        r"d:\x",
        r"C:\a b\c.d",
        r"C:\COM10\CONSOLE\nul0\LPT0\x.CON",
        r"C:\CON x",
    ];
    let windows_bad = [
        r"C:\",
        r"C:",
        r"C:x",
        r"\\server\share\logs",
        r"\\?\C:\x",
        r"\\.\C:\x",
        r"C:\a\\b",
        r"C:\a\.\b",
        r"C:\a\..\b",
        r"C:\a\",
        r"C:/a",
        r"C:\a/b",
        r"C:\a.\b",
        r"C:\a \b",
        r"C:\a\...",
        r"C:\a:b",
        r"C:\a<b",
        r"C:\a>b",
        "C:\\a\"b",
        r"C:\a|b",
        r"C:\a?b",
        r"C:\a*b",
        "C:\\a\u{1f}b",
        "C:\\a\tb",
        r"C:\x\NUL",
        r"C:\x\con",
        r"C:\x\Aux.txt",
        r"C:\x\prn.tar.gz",
        r"C:\x\com1.txt",
        r"C:\x\LPT9",
        "C:\\x\\COM\u{b9}",
        "C:\\x\\lpt\u{b3}.log",
        r"C:\x\NUL.",
        "/a",
    ];
    for good in windows_good {
        assert!(is_normal_form(Os::Windows, good), "{good:?}");
        assert!(!is_normal_form(Os::Linux, good), "{good:?}");
    }
    for bad in windows_bad {
        assert!(!is_normal_form(Os::Windows, bad), "{bad:?}");
    }
    let long = format!("/{}", "a".repeat(1023));
    assert!(is_normal_form(Os::Linux, &long));
    assert!(!is_normal_form(Os::Linux, &format!("{long}a")));
    for name in ["agent.log", "health.json.tmp", "agent.log.1"] {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            assert!(is_plain_name(os, name), "{name}");
        }
    }
    for name in ["", ".", "..", "a/b"] {
        assert!(!is_plain_name(Os::Linux, name), "{name:?}");
        assert!(!is_plain_name(Os::Windows, name), "{name:?}");
    }
    for name in ["logs.", "...", "x ", "a\\b", "CON", "com2.log", "a:b"] {
        assert!(!is_plain_name(Os::Windows, name), "{name:?}");
    }
    assert!(is_plain_name(Os::Linux, "logs."));
    assert!(is_plain_name(Os::Linux, "CON"));
}

#[test]
fn loader_accepts_only_the_running_os_form() {
    // File values: each schema-valid form is refused by the other OS.
    let unix = doc(r#","paths":{"state_dir":"/srv/state"}"#);
    let windows = doc(r#","paths":{"state_dir":"C:\\srv\\state"}"#);
    let mut windows_service = LoadOptions::new(Os::Windows, Mode::Service);
    windows_service.program_data = Some(PathBuf::from(r"C:\ProgramData"));
    assert!(load_bytes(&unix, &linux_run()).is_ok());
    assert!(load_bytes(&windows, &windows_service).is_ok());
    for (bytes, options) in [(&windows, linux_run()), (&unix, windows_service.clone())] {
        assert!(matches!(
            load_bytes(bytes, &options),
            Err(Error::InvalidValue { pointer }) if pointer == "/paths/state_dir"
        ));
    }
    // Flags follow the same rule.
    for bad in ["/var//lib/x", "/run/./x", "/var/log/../x", "/x/"] {
        let mut options = linux_run();
        options.overrides.runtime_dir = Some(PathBuf::from(bad));
        assert!(
            matches!(
                load(None, &options),
                Err(Error::InvalidPathFlag {
                    flag: "--runtime-dir"
                })
            ),
            "{bad}"
        );
    }
    for bad in [
        r"\\server\share\x",
        r"C:\x\NUL",
        r"C:\a.\b",
        r"C:\x\com1.txt",
        "/x",
    ] {
        let mut options = windows_service.clone();
        options.overrides.log_dir = Some(PathBuf::from(bad));
        assert!(
            matches!(
                load(None, &options),
                Err(Error::InvalidPathFlag { flag: "--log-dir" })
            ),
            "{bad}"
        );
    }
}
