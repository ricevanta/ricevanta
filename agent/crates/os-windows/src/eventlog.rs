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
