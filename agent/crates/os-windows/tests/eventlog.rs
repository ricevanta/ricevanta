//! Event log line escaping and types; pure, so it runs on every host.

use ricevanta_os_windows::eventlog::{EventKind, SOURCE, escape_percent};

#[test]
fn percent_signs_become_json_escapes() {
    let line = r#"{"detail":"50% of %1 %n","event":"startup_failed"}"#;
    let escaped = escape_percent(line);
    assert_eq!(
        escaped,
        r#"{"detail":"50\u0025 of \u00251 \u0025n","event":"startup_failed"}"#
    );
    assert!(!escaped.contains('%'));
    // Still JSON for the same value.
    assert_eq!(
        ricevanta_json::parse(escaped.as_bytes()).unwrap(),
        ricevanta_json::parse(line.as_bytes()).unwrap()
    );
}

#[test]
fn startup_failed_is_an_error_event() {
    assert_eq!(EventKind::for_event("startup_failed"), EventKind::Error);
    assert_eq!(
        EventKind::for_event("agent_starting"),
        EventKind::Information
    );
    assert_eq!(SOURCE, "RicevantaAgent");
}
