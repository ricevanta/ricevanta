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
//!   any end without an accepted stop) reports nothing more, so
//!   the SCM sees the process end from `SERVICE_START_PENDING` or
//!   `SERVICE_RUNNING`, the same transition as a crash, and restarts it.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::Receiver;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

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

/// Latched shutdown intent shared by the handler and terminal owner.
/// Captured deadlines are monotonic and never extended by another cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSnapshot {
    /// The single accepted SCM stop, independent of a queued notification.
    pub requested: Option<StopRequest>,
    /// Whether an internal failure occurred before commitment.
    pub failed: bool,
    /// Earliest cleanup deadline; `None` means cleanup has not begun.
    pub deadline: Option<Instant>,
    /// Accepted external stops, always zero or one.
    pub stop_requests: u64,
    /// No further intent changes are accepted once true.
    pub terminal_committed: bool,
}

#[derive(Debug)]
struct ArbitrationState {
    snapshot: StopSnapshot,
    accepting: bool,
    cleanup_started: bool,
    timeout_ms: u64,
}

/// Poison-tolerant, bounded arbitration of SCM controls and internal failure.
/// The lock covers in-memory transitions only, never I/O, final writes or joins.
#[derive(Debug)]
pub struct StopArbitration {
    state: Mutex<ArbitrationState>,
}

impl StopArbitration {
    /// Creates a latch before the service starts. Controls remain disabled
    /// until the owner successfully reports running. `timeout_ms` must come
    /// from validated configuration; an unrepresentable deadline expires now.
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            state: Mutex::new(ArbitrationState {
                snapshot: StopSnapshot {
                    requested: None,
                    failed: false,
                    deadline: None,
                    stop_requests: 0,
                    terminal_committed: false,
                },
                accepting: false,
                cleanup_started: false,
                timeout_ms,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ArbitrationState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets the validated configuration timeout before reporting running.
    /// Refuses changes once controls or cleanup have begun, without mutation.
    pub fn configure_timeout(&self, timeout_ms: u64) -> io::Result<()> {
        let mut state = self.lock();
        if state.accepting || state.snapshot.deadline.is_some() || state.snapshot.terminal_committed
        {
            return Err(out_of_order("timeout changed after startup"));
        }
        state.timeout_ms = timeout_ms;
        Ok(())
    }

    /// Latches a control before the handler acknowledges it. Returns false
    /// before running, after any accepted control, or after commitment. The
    /// caller captures `received_at` on control receipt, before taking locks.
    /// Use `begin_cleanup` to claim cancellation and joins exactly once.
    pub fn accept(&self, request: StopRequest, received_at: Instant) -> bool {
        let mut state = self.lock();
        if !state.accepting
            || state.snapshot.requested.is_some()
            || state.snapshot.terminal_committed
        {
            return false;
        }
        let deadline = received_at
            .checked_add(Duration::from_millis(
                request.effective_deadline_ms(state.timeout_ms),
            ))
            .unwrap_or(received_at);
        let snapshot = &mut state.snapshot;
        snapshot.requested = Some(request);
        snapshot.stop_requests = 1;
        snapshot.deadline = Some(snapshot.deadline.map_or(deadline, |old| old.min(deadline)));
        true
    }

    /// Records an internal failure without consuming an external stop.
    /// Returns true only for the transition that starts cleanup; callers
    /// use `begin_cleanup` to claim cancellation/joins. After commitment this does nothing.
    pub fn fail(&self, now: Instant) -> bool {
        let mut state = self.lock();
        if state.snapshot.terminal_committed {
            return false;
        }
        let first = state.snapshot.deadline.is_none();
        let deadline = now
            .checked_add(Duration::from_millis(state.timeout_ms))
            .unwrap_or(now);
        state.snapshot.failed = true;
        if first {
            state.snapshot.deadline = Some(deadline);
        }
        first
    }

    /// Claims the one cleanup execution after a failure or accepted control.
    /// Every cause may call this; only the first gets true. The caller runs
    /// cancellation and joins outside the lock. No cleanup starts after commit.
    pub fn begin_cleanup(&self) -> bool {
        let mut state = self.lock();
        if state.cleanup_started
            || state.snapshot.deadline.is_none()
            || state.snapshot.terminal_committed
        {
            return false;
        }
        state.cleanup_started = true;
        true
    }

    /// Copies intent for final health/log writes outside the lock.
    pub fn snapshot(&self) -> StopSnapshot {
        self.lock().snapshot
    }

    /// Commits only the exact intent already finalized by the owner. A false
    /// result requires another snapshot and finalization. On success the
    /// owner must immediately perform the terminal action, without further
    /// joins, health writes or log flushes. Only that owner may call this.
    pub fn try_commit(&self, finalized: StopSnapshot) -> bool {
        let mut state = self.lock();
        if state.snapshot.terminal_committed || state.snapshot != finalized {
            return false;
        }
        state.snapshot.terminal_committed = true;
        true
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
    arbitration: &'a StopArbitration,
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
        self.arbitration.lock().accepting = true;
        Ok(())
    }

    /// The stop requests the control handler recorded.
    pub fn stop_requests(&self) -> &Receiver<StopRequest> {
        self.stops
    }

    /// Shared latched intent. The core uses `fail` to begin internal cleanup
    /// and reads the same absolute deadline when an accepted control arrives.
    pub fn arbitration(&self) -> &StopArbitration {
        self.arbitration
    }

    /// Reports pending from accepted intent, never from the notification.
    /// The wait hint uses remaining deadline rounded up plus 5,000 ms.
    /// Refuses a duplicate or a call without an accepted stop.
    pub fn stop_pending(&mut self) -> io::Result<()> {
        let snapshot = self.arbitration.snapshot();
        if self.phase != Phase::Running || snapshot.requested.is_none() {
            return Err(out_of_order(
                "stop pending without an accepted control or twice",
            ));
        }
        let remaining = snapshot.deadline.map_or(Duration::ZERO, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        let millis =
            remaining.as_millis() + u128::from(!remaining.subsec_nanos().is_multiple_of(1_000_000));
        self.wait_hint_ms = u32::try_from(millis.saturating_add(u128::from(STOP_WAIT_MARGIN_MS)))
            .unwrap_or(u32::MAX);
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

/// Runs a service body with shared arbitration and no final health/log hook.
/// Use [`run_service_main_with_finalizer`] when the owner writes final evidence.
pub fn run_service_main(
    sink: &mut dyn StatusSink,
    stops: &Receiver<StopRequest>,
    arbitration: &StopArbitration,
    body: impl FnOnce(&mut ServiceSession<'_>) -> ServiceEnd,
) -> ServiceExit {
    run_service_main_with_finalizer(sink, stops, arbitration, body, &mut |_| {})
}

/// Runs the body, snapshots intent, publishes any pending status and invokes
/// `finalize` outside the arbitration lock. If intent changes during final
/// writes, repeats finalization before commitment. The callback must finish
/// final health/log writes and flushes; no such work runs after commitment.
/// Callback panics latch failure; repeated failure cannot extend the deadline.
/// Caught panic payloads are retained without Drop until process termination,
/// because an arbitrary destructor can block or panic. This runner is terminal,
/// never a recover-and-resume boundary. If the initial status report fails,
/// uncalled body captures follow the same terminal-only retention rule.
/// The channel only wakes the body; accepted intent survives an unread wakeup.
/// The finalizer is borrowed so its captured resources cannot run destructors
/// between commitment and the caller's process exit on an unreported end.
pub fn run_service_main_with_finalizer(
    sink: &mut dyn StatusSink,
    stops: &Receiver<StopRequest>,
    arbitration: &StopArbitration,
    body: impl FnOnce(&mut ServiceSession<'_>) -> ServiceEnd,
    finalize: &mut dyn FnMut(StopSnapshot),
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
        // The body was never called. Its captures may have arbitrary Drop;
        // retain them for the same imminent process exit as panic payloads.
        std::mem::forget(body);
        let snapshot = arbitration.snapshot();
        arbitration.try_commit(snapshot);
        return ServiceExit {
            exit_code: 3,
            reported_stopped: false,
        };
    }
    let mut session = ServiceSession {
        sink,
        stops,
        arbitration,
        phase: Phase::StartPending,
        check_point: 0,
        wait_hint_ms: 0,
    };
    let end = catch_unwind(AssertUnwindSafe(|| body(&mut session))).unwrap_or_else(|payload| {
        // The process is ending. An arbitrary panic payload can block or
        // panic in Drop, so leave its storage for process termination instead
        // of running user code after commitment or consuming the deadline.
        std::mem::forget(payload);
        ServiceEnd::Other { exit_code: 1 }
    });
    let original_code = match end {
        ServiceEnd::Other { exit_code } => exit_code,
        ServiceEnd::RequestedStop { deadline_met: true }
            if arbitration.snapshot().requested.is_some() =>
        {
            0
        }
        _ => 1,
    };
    if !matches!(end, ServiceEnd::RequestedStop { deadline_met: true }) || original_code != 0 {
        arbitration.fail(Instant::now());
    }
    let finalized = loop {
        let snapshot = arbitration.snapshot();
        if snapshot.requested.is_some()
            && session.phase != Phase::StopPending
            && session.stop_pending().is_err()
        {
            arbitration.fail(Instant::now());
        }
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| finalize(snapshot))) {
            // Same terminal-only retention rule as the service body above.
            std::mem::forget(payload);
            arbitration.fail(Instant::now());
        }
        if arbitration.try_commit(snapshot) {
            break snapshot;
        }
    };
    // Commitment and the terminal action are adjacent: no final writes or
    // task joins can now race a newly accepted stop.
    if finalized.requested.is_none() {
        return ServiceExit {
            exit_code: original_code.max(1),
            reported_stopped: false,
        };
    }
    let clean = !finalized.failed
        && finalized
            .deadline
            .is_some_and(|deadline| Instant::now() <= deadline);
    let exit_code = i32::from(!clean);
    let reported_stopped = session
        .sink
        .report(StatusReport {
            current_state: SERVICE_STOPPED,
            controls_accepted: 0,
            win32_exit_code: if clean {
                NO_ERROR
            } else {
                ERROR_SERVICE_SPECIFIC_ERROR
            },
            service_specific_exit_code: u32::from(!clean),
            check_point: 0,
            wait_hint_ms: 0,
        })
        .is_ok();
    ServiceExit {
        exit_code,
        reported_stopped,
    }
}
