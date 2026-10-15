//! Service Control Manager status logic (spec sections 4, 5.1 and 5.4),
//! portable so the fake-dispatcher tests run on every host. The native
//! dispatcher and control handler (Windows only) feed this module through a
//! [`StatusSink`] that calls `SetServiceStatus`.
//!
//! The rules it enforces:
//!
//! - `ServiceMain` reports `SERVICE_START_PENDING` with a 10,000 ms wait hint
//!   and no accepted controls, then `SERVICE_RUNNING` accepting stop and
//!   shutdown once startup is complete.
//! - `SERVICE_STOP_PENDING` is reported only for a stop the SCM requested,
//!   with the effective deadline plus 5,000 ms as wait hint and an
//!   incremented checkpoint on each [`ServiceSession::check_point`].
//! - `SERVICE_STOPPED` is reported once and last, only for a requested stop,
//!   and for every end once `SERVICE_STOP_PENDING` was reported: `NO_ERROR`
//!   when the stop completed within its deadline, otherwise (late, a panic
//!   or any other end during the stop) `ERROR_SERVICE_SPECIFIC_ERROR` with
//!   service-specific code 1 and exit code 1. The process never ends from
//!   `SERVICE_STOP_PENDING`.
//! - Every other end (a panic, a configuration error, a startup failure, or
//!   any end before a requested stop was reported) reports nothing more, so
//!   the SCM sees the process end from `SERVICE_START_PENDING` or
//!   `SERVICE_RUNNING`, the same transition as a crash, and restarts it.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::Receiver;

/// `SERVICE_STOPPED`.
pub const SERVICE_STOPPED: u32 = 1;
/// `SERVICE_START_PENDING`.
pub const SERVICE_START_PENDING: u32 = 2;
/// `SERVICE_STOP_PENDING`.
pub const SERVICE_STOP_PENDING: u32 = 3;
/// `SERVICE_RUNNING`.
pub const SERVICE_RUNNING: u32 = 4;
/// `SERVICE_ACCEPT_STOP`.
pub const SERVICE_ACCEPT_STOP: u32 = 1;
/// `SERVICE_ACCEPT_SHUTDOWN`.
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 4;
/// `NO_ERROR`.
pub const NO_ERROR: u32 = 0;
/// `ERROR_SERVICE_SPECIFIC_ERROR`.
pub const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;
/// The wait hint of `SERVICE_START_PENDING`.
pub const START_WAIT_HINT_MS: u32 = 10_000;
/// Added to the effective deadline for the `SERVICE_STOP_PENDING` wait hint.
pub const STOP_WAIT_MARGIN_MS: u64 = 5_000;
/// How often the core advances the checkpoint during a requested stop.
pub const CHECK_POINT_INTERVAL_MS: u64 = 2_000;
/// The cap on the deadline of a `SERVICE_CONTROL_SHUTDOWN` stop.
pub const SHUTDOWN_DEADLINE_CAP_MS: u64 = 15_000;

/// One `SERVICE_STATUS` value, without the fixed service type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport {
    /// `dwCurrentState`.
    pub current_state: u32,
    /// `dwControlsAccepted`.
    pub controls_accepted: u32,
    /// `dwWin32ExitCode`.
    pub win32_exit_code: u32,
    /// `dwServiceSpecificExitCode`.
    pub service_specific_exit_code: u32,
    /// `dwCheckPoint`.
    pub check_point: u32,
    /// `dwWaitHint` in milliseconds.
    pub wait_hint_ms: u32,
}

/// Where status reports go: `SetServiceStatus` in the service, a recorder
/// in tests.
pub trait StatusSink {
    /// Reports one status.
    fn report(&mut self, report: StatusReport) -> io::Result<()>;
}

/// A stop the SCM requested through the control handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopRequest {
    /// `SERVICE_CONTROL_STOP`.
    Stop,
    /// `SERVICE_CONTROL_SHUTDOWN`.
    Shutdown,
}

impl StopRequest {
    /// The effective stop deadline: `shutdown.timeout_ms`, capped at
    /// 15,000 ms for a system shutdown (spec section 4).
    pub fn effective_deadline_ms(self, timeout_ms: u64) -> u64 {
        match self {
            StopRequest::Stop => timeout_ms,
            StopRequest::Shutdown => timeout_ms.min(SHUTDOWN_DEADLINE_CAP_MS),
        }
    }
}

/// How the service body ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEnd {
    /// A stop the SCM requested completed, within its deadline or not.
    RequestedStop {
        /// Whether the deadline was met (exit code 0) or passed (exit 1).
        deadline_met: bool,
    },
    /// Any other end, with the process exit code (1 task panic, 2
    /// configuration error, 3 startup failure).
    Other {
        /// The process exit code.
        exit_code: i32,
    },
}

/// What `ServiceMain` does after the body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceExit {
    /// The process exit code.
    pub exit_code: i32,
    /// Whether `SERVICE_STOPPED` was reported; when false the process must
    /// end without returning to the dispatcher, so the SCM restarts it.
    pub reported_stopped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    StartPending,
    Running,
    StopPending,
}

/// Misuse of the status sequence, refused rather than reported.
fn out_of_order(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_owned())
}

/// The status operations the service body may perform.
pub struct ServiceSession<'a> {
    sink: &'a mut dyn StatusSink,
    stops: &'a Receiver<StopRequest>,
    phase: Phase,
    check_point: u32,
    wait_hint_ms: u32,
}

impl ServiceSession<'_> {
    /// Reports `SERVICE_RUNNING` accepting stop and shutdown; only once,
    /// after `SERVICE_START_PENDING`.
    pub fn running(&mut self) -> io::Result<()> {
        if self.phase != Phase::StartPending {
            return Err(out_of_order("running reported twice or after a stop"));
        }
        self.sink.report(StatusReport {
            current_state: SERVICE_RUNNING,
            controls_accepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            win32_exit_code: NO_ERROR,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint_ms: 0,
        })?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// The stop requests the control handler recorded.
    pub fn stop_requests(&self) -> &Receiver<StopRequest> {
        self.stops
    }

    /// Reports `SERVICE_STOP_PENDING` for a stop the SCM requested, with the
    /// deadline plus 5,000 ms as wait hint and checkpoint 1. Only valid once,
    /// while running.
    pub fn stop_pending(&mut self, request: StopRequest, deadline_ms: u64) -> io::Result<()> {
        let _ = request;
        if self.phase != Phase::Running {
            return Err(out_of_order("stop pending before running or twice"));
        }
        self.wait_hint_ms =
            u32::try_from(deadline_ms.saturating_add(STOP_WAIT_MARGIN_MS)).unwrap_or(u32::MAX);
        self.check_point = 1;
        self.report_stop_pending()?;
        self.phase = Phase::StopPending;
        Ok(())
    }

    /// Advances the checkpoint of a requested stop (every 2,000 ms).
    pub fn check_point(&mut self) -> io::Result<()> {
        if self.phase != Phase::StopPending {
            return Err(out_of_order("checkpoint outside a requested stop"));
        }
        self.check_point = self.check_point.saturating_add(1);
        self.report_stop_pending()
    }

    fn report_stop_pending(&mut self) -> io::Result<()> {
        self.sink.report(StatusReport {
            current_state: SERVICE_STOP_PENDING,
            controls_accepted: 0,
            win32_exit_code: NO_ERROR,
            service_specific_exit_code: 0,
            check_point: self.check_point,
            wait_hint_ms: self.wait_hint_ms,
        })
    }
}

/// The body of `ServiceMain`: reports `SERVICE_START_PENDING`, runs `body`
/// with a session (catching a panic), and reports `SERVICE_STOPPED` only
/// when the body ended a stop that was reported as `SERVICE_STOP_PENDING`.
pub fn run_service_main(
    sink: &mut dyn StatusSink,
    stops: &Receiver<StopRequest>,
    body: impl FnOnce(&mut ServiceSession<'_>) -> ServiceEnd,
) -> ServiceExit {
    let start = StatusReport {
        current_state: SERVICE_START_PENDING,
        controls_accepted: 0,
        win32_exit_code: NO_ERROR,
        service_specific_exit_code: 0,
        check_point: 0,
        wait_hint_ms: START_WAIT_HINT_MS,
    };
    if sink.report(start).is_err() {
        return ServiceExit {
            exit_code: 3,
            reported_stopped: false,
        };
    }
    let mut session = ServiceSession {
        sink,
        stops,
        phase: Phase::StartPending,
        check_point: 0,
        wait_hint_ms: 0,
    };
    let end = catch_unwind(AssertUnwindSafe(|| body(&mut session)));
    let deadline_met = if session.phase == Phase::StopPending {
        // The SCM requested this stop and SERVICE_STOP_PENDING was reported:
        // every end now reports SERVICE_STOPPED, so the SCM never restarts a
        // requested stop. Only a completed stop within its deadline is
        // clean; a late stop, a panic or any other end during the stop is
        // ERROR_SERVICE_SPECIFIC_ERROR with code 1.
        matches!(end, Ok(ServiceEnd::RequestedStop { deadline_met: true }))
    } else {
        // No requested stop was reported: end unreported, like a crash, so
        // the SCM runs the restart action. A requested end without a
        // reported stop is a programming error and ends like a task panic.
        let exit_code = match end {
            Ok(ServiceEnd::Other { exit_code }) => exit_code,
            Ok(ServiceEnd::RequestedStop { .. }) | Err(_) => 1,
        };
        return ServiceExit {
            exit_code,
            reported_stopped: false,
        };
    };
    let (win32_exit_code, service_specific_exit_code, exit_code) = if deadline_met {
        (NO_ERROR, 0, 0)
    } else {
        (ERROR_SERVICE_SPECIFIC_ERROR, 1, 1)
    };
    let reported = session
        .sink
        .report(StatusReport {
            current_state: SERVICE_STOPPED,
            controls_accepted: 0,
            win32_exit_code,
            service_specific_exit_code,
            check_point: 0,
            wait_hint_ms: 0,
        })
        .is_ok();
    ServiceExit {
        exit_code,
        reported_stopped: reported,
    }
}
