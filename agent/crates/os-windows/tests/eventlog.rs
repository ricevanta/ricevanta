//! Event log line escaping and types; pure, so it runs on every host.

use ricevanta_os_windows::eventlog::{
    EventKind, MAX_EVENT_UNITS, SOURCE, TRUNCATED_MARKER, escape_percent, event_text,
};

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

#[test]
fn event_text_fits_report_event_w() {
    let escape = format!("{}u0025", '\\');
    // A short line is only escaped.
    let short = r#"{"detail":"5%"}"#;
    assert_eq!(event_text(short), escape_percent(short));
    // A line whose escapes push it past the limit is cut with a marker.
    let line = format!(r#"{{"detail":"{}"}}"#, "%".repeat(8_000));
    assert!(escape_percent(&line).encode_utf16().count() > MAX_EVENT_UNITS);
    let text = event_text(&line);
    let units = text.encode_utf16().count();
    assert!(units <= MAX_EVENT_UNITS, "{units}");
    assert!(units > MAX_EVENT_UNITS - 6 - TRUNCATED_MARKER.len());
    assert!(text.ends_with(TRUNCATED_MARKER));
    assert!(!text.contains('%'));
    // Every escape is whole: the body is the prefix and then escapes only.
    let body = text.strip_suffix(TRUNCATED_MARKER).unwrap();
    let after_prefix = body.strip_prefix(r#"{"detail":""#).unwrap();
    assert!(after_prefix.len().is_multiple_of(escape.len()));
    assert_eq!(
        after_prefix,
        escape.repeat(after_prefix.len() / escape.len())
    );
    // Characters outside the BMP count as two units and are never split.
    let wide = "\u{1f600}".repeat(20_000);
    let text = event_text(&wide);
    assert!(text.encode_utf16().count() <= MAX_EVENT_UNITS);
    assert!(text.ends_with(TRUNCATED_MARKER));
}
