//! The SCM status sequence through a fake dispatcher (plan Task 4): the
//! status reports are recorded instead of sent to `SetServiceStatus`. Pure,
//! so it runs on every host; the real SCM is exercised in Task 5.

use ricevanta_os_windows::scm::{
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED, ServiceEnd,
    ServiceExit, ServiceSession, StatusReport, StatusSink, StopRequest, run_service_main,
};
use std::io;
use std::sync::mpsc::{self, Sender};

/// Records every report; can be told to fail from a given report on.
#[derive(Default)]
struct FakeScm {
    reports: Vec<StatusReport>,
    fail_from: Option<usize>,
}

impl StatusSink for FakeScm {
    fn report(&mut self, report: StatusReport) -> io::Result<()> {
        if self.fail_from.is_some_and(|n| self.reports.len() >= n) {
            return Err(io::Error::other("injected SetServiceStatus failure"));
        }
        self.reports.push(report);
        Ok(())
    }
}

impl FakeScm {
    fn states(&self) -> Vec<u32> {
        self.reports.iter().map(|r| r.current_state).collect()
    }

    fn stopped_count(&self) -> usize {
        self.states()
            .iter()
            .filter(|&&s| s == SERVICE_STOPPED)
            .count()
    }
}

/// Runs `body` the way the dispatcher's `ServiceMain` does, with the
/// control handler's channel.
fn dispatch(
    scm: &mut FakeScm,
    body: impl FnOnce(&mut ServiceSession<'_>, &Sender<StopRequest>) -> ServiceEnd,
) -> ServiceExit {
    let (handler, stops) = mpsc::channel();
    run_service_main(scm, &stops, |session| body(session, &handler))
}

/// A requested stop that completes after `ticks` checkpoints.
fn requested_stop(
    request: StopRequest,
    timeout_ms: u64,
    ticks: usize,
    deadline_met: bool,
) -> impl FnOnce(&mut ServiceSession<'_>, &Sender<StopRequest>) -> ServiceEnd {
    move |session, handler| {
        session.running().unwrap();
        // The control handler records the request and returns.
        handler.send(request).unwrap();
        let got = session.stop_requests().recv().unwrap();
        assert_eq!(got, request);
        session
            .stop_pending(got, got.effective_deadline_ms(timeout_ms))
            .unwrap();
        for _ in 0..ticks {
            session.check_point().unwrap();
        }
        ServiceEnd::RequestedStop { deadline_met }
    }
}

#[test]
fn requested_stop_in_time_reports_stopped_once_with_no_error() {
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, requested_stop(StopRequest::Stop, 10_000, 2, true));
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 0,
            reported_stopped: true
        }
    );
    assert_eq!(
        scm.states(),
        [
            SERVICE_START_PENDING,
            SERVICE_RUNNING,
            SERVICE_STOP_PENDING,
            SERVICE_STOP_PENDING,
            SERVICE_STOP_PENDING,
            SERVICE_STOPPED
        ]
    );
    assert_eq!(scm.stopped_count(), 1);
    let start = scm.reports[0];
    assert_eq!((start.wait_hint_ms, start.controls_accepted), (10_000, 0));
    let running = scm.reports[1];
    assert_eq!(
        running.controls_accepted,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    );
    let pending: Vec<_> = scm.reports[2..5]
        .iter()
        .map(|r| (r.check_point, r.wait_hint_ms, r.controls_accepted))
        .collect();
    assert_eq!(pending, [(1, 15_000, 0), (2, 15_000, 0), (3, 15_000, 0)]);
    let stopped = *scm.reports.last().unwrap();
    assert_eq!(
        (stopped.win32_exit_code, stopped.service_specific_exit_code),
        (NO_ERROR, 0)
    );
}

#[test]
fn late_requested_stop_reports_service_specific_code_1() {
    let mut scm = FakeScm::default();
    let exit = dispatch(
        &mut scm,
        requested_stop(StopRequest::Stop, 10_000, 0, false),
    );
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 1,
            reported_stopped: true
        }
    );
    assert_eq!(scm.stopped_count(), 1);
    let stopped = *scm.reports.last().unwrap();
    assert_eq!(stopped.current_state, SERVICE_STOPPED);
    assert_eq!(
        (stopped.win32_exit_code, stopped.service_specific_exit_code),
        (ERROR_SERVICE_SPECIFIC_ERROR, 1)
    );
}

#[test]
fn shutdown_deadline_is_capped_at_15_seconds() {
    assert_eq!(StopRequest::Shutdown.effective_deadline_ms(60_000), 15_000);
    assert_eq!(StopRequest::Shutdown.effective_deadline_ms(10_000), 10_000);
    assert_eq!(StopRequest::Stop.effective_deadline_ms(60_000), 60_000);
    let mut scm = FakeScm::default();
    dispatch(
        &mut scm,
        requested_stop(StopRequest::Shutdown, 60_000, 0, true),
    );
    assert_eq!(scm.reports[2].wait_hint_ms, 20_000);
}

fn assert_unreported_end(scm: &FakeScm, last_state: u32) {
    let states = scm.states();
    assert!(!states.contains(&SERVICE_STOP_PENDING), "{states:?}");
    assert!(!states.contains(&SERVICE_STOPPED), "{states:?}");
    assert_eq!(states.last(), Some(&last_state));
}

#[test]
fn panic_after_running_ends_without_stop_reports() {
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, |session, _| {
        session.running().unwrap();
        panic!("injected task panic");
    });
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 1,
            reported_stopped: false
        }
    );
    assert_unreported_end(&scm, SERVICE_RUNNING);
}

#[test]
fn configuration_error_ends_from_start_pending() {
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, |_, _| ServiceEnd::Other { exit_code: 2 });
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 2,
            reported_stopped: false
        }
    );
    assert_unreported_end(&scm, SERVICE_START_PENDING);
}

#[test]
fn startup_failure_and_panic_before_running_end_from_start_pending() {
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, |_, _| ServiceEnd::Other { exit_code: 3 });
    assert_eq!(exit.exit_code, 3);
    assert_unreported_end(&scm, SERVICE_START_PENDING);
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, |_, _| panic!("injected startup panic"));
    assert_eq!(exit.exit_code, 1);
    assert_unreported_end(&scm, SERVICE_START_PENDING);
}

#[test]
fn internal_stop_after_running_reports_nothing_more() {
    // A task panic caught by the core becomes an internal stop with exit 1:
    // the status stays SERVICE_RUNNING until the process ends.
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, |session, _| {
        session.running().unwrap();
        ServiceEnd::Other { exit_code: 1 }
    });
    assert!(!exit.reported_stopped);
    assert_unreported_end(&scm, SERVICE_RUNNING);
}

#[test]
fn out_of_order_reports_are_refused() {
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, |session, _| {
        // Stop pending and checkpoints need a running service first.
        assert!(session.stop_pending(StopRequest::Stop, 1_000).is_err());
        assert!(session.check_point().is_err());
        session.running().unwrap();
        assert!(session.running().is_err());
        assert!(session.check_point().is_err());
        // Claiming a requested stop that was never reported is not one.
        ServiceEnd::RequestedStop { deadline_met: true }
    });
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 1,
            reported_stopped: false
        }
    );
    assert_unreported_end(&scm, SERVICE_RUNNING);
}

#[test]
fn status_failures_never_claim_a_reported_stop() {
    // SetServiceStatus failing for SERVICE_START_PENDING: startup failure.
    let mut scm = FakeScm {
        fail_from: Some(0),
        ..FakeScm::default()
    };
    let exit = dispatch(&mut scm, |_, _| unreachable!("body must not run"));
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 3,
            reported_stopped: false
        }
    );
    // Failing for SERVICE_STOPPED: the process must still end unreported,
    // so the SCM restarts it rather than waiting.
    let mut scm = FakeScm {
        fail_from: Some(4),
        ..FakeScm::default()
    };
    let exit = dispatch(&mut scm, requested_stop(StopRequest::Stop, 1_000, 1, true));
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 0,
            reported_stopped: false
        }
    );
    assert_eq!(scm.stopped_count(), 0);
}

/// A body that receives an SCM stop, reports it pending, then ends with
/// `end` instead of completing the stop.
fn stop_then(
    end: impl FnOnce() -> ServiceEnd,
) -> impl FnOnce(&mut ServiceSession<'_>, &Sender<StopRequest>) -> ServiceEnd {
    move |session, handler| {
        session.running().unwrap();
        handler.send(StopRequest::Stop).unwrap();
        let request = session.stop_requests().recv().unwrap();
        session.stop_pending(request, 10_000).unwrap();
        end()
    }
}

fn assert_stopped_with_code_1(scm: &FakeScm, exit: ServiceExit) {
    assert_eq!(
        exit,
        ServiceExit {
            exit_code: 1,
            reported_stopped: true
        }
    );
    assert_eq!(scm.stopped_count(), 1);
    let stopped = *scm.reports.last().unwrap();
    assert_eq!(stopped.current_state, SERVICE_STOPPED);
    assert_eq!(
        (stopped.win32_exit_code, stopped.service_specific_exit_code),
        (ERROR_SERVICE_SPECIFIC_ERROR, 1)
    );
}

#[test]
fn panic_after_a_stop_request_still_reports_stopped() {
    let mut scm = FakeScm::default();
    let exit = dispatch(&mut scm, stop_then(|| panic!("injected panic during stop")));
    assert_stopped_with_code_1(&scm, exit);
    assert_eq!(
        scm.states(),
        [
            SERVICE_START_PENDING,
            SERVICE_RUNNING,
            SERVICE_STOP_PENDING,
            SERVICE_STOPPED
        ]
    );
}

#[test]
fn other_end_after_a_stop_request_still_reports_stopped() {
    for code in [1, 2, 3] {
        let mut scm = FakeScm::default();
        let exit = dispatch(
            &mut scm,
            stop_then(move || ServiceEnd::Other { exit_code: code }),
        );
        assert_stopped_with_code_1(&scm, exit);
    }
}
