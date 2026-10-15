//! The Application event log lines of spec section 6, written only before
//! the log file opens. The escaping and type choice are portable; the
//! writer (`EventLog`) exists on Windows only.
//!
//! These lines are unauthenticated diagnostics, never evidence of agent
//! state: the Application log's default access lets interactive users read
//! the lines and write entries under the same source name.

/// The event source name, registered by the AG-12 installer.
pub const SOURCE: &str = "RicevantaAgent";

/// The event type of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// `EVENTLOG_ERROR_TYPE`, for `startup_failed`.
    Error,
    /// `EVENTLOG_INFORMATION_TYPE`, for every other line.
    Information,
}

impl EventKind {
    /// The type for a line carrying the log `event` token.
    pub fn for_event(event: &str) -> EventKind {
        if event == "startup_failed" {
            EventKind::Error
        } else {
            EventKind::Information
        }
    }
}

/// Writes every `%` of a JSON log line as the JSON escape `\u0025`, because
/// Event Viewer treats `%n` in an insertion string as a further insertion.
/// The result is still valid JSON for the same value.
pub fn escape_percent(line: &str) -> String {
    line.replace('%', "\\u0025")
}

/// ReportEventW: "Each string is limited to 31,839 characters", counted in
/// UTF-16 units.
pub const MAX_EVENT_UNITS: usize = 31_839;
/// Appended when a line had to be cut to fit [`MAX_EVENT_UNITS`].
pub const TRUNCATED_MARKER: &str = " [truncated]";

/// The insertion string for a log line: [`escape_percent`] applied, and,
/// when the result would exceed [`MAX_EVENT_UNITS`], cut at a character
/// boundary that never splits an escape and followed by
/// [`TRUNCATED_MARKER`], so `ReportEventW` never refuses the event. A cut
/// line is a diagnostic, no longer JSON.
pub fn event_text(line: &str) -> String {
    let escaped = escape_percent(line);
    if escaped.encode_utf16().count() <= MAX_EVENT_UNITS {
        return escaped;
    }
    let budget = MAX_EVENT_UNITS - TRUNCATED_MARKER.len();
    let mut out = String::new();
    let mut units = 0;
    for c in line.chars() {
        let piece = if c == '%' { 6 } else { c.len_utf16() };
        if units + piece > budget {
            break;
        }
        if c == '%' {
            out.push_str("\\u0025");
        } else {
            out.push(c);
        }
        units += piece;
    }
    out.push_str(TRUNCATED_MARKER);
    out
}
