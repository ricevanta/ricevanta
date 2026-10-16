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

struct FakeControl<'a> {
    send: Sender<StopRequest>,
    arbitration: &'a ricevanta_os_windows::scm::StopArbitration,
}

impl FakeControl<'_> {
    fn send(&self, request: StopRequest) -> io::Result<()> {
        if !self.arbitration.accept(request, std::time::Instant::now()) {
            return Err(io::Error::other("control refused"));
        }
        self.send.send(request).map_err(io::Error::other)
    }
}

/// Runs `body` the way the dispatcher's `ServiceMain` does, with the
/// control handler's channel.
fn dispatch(
    scm: &mut FakeScm,
    body: impl FnOnce(&mut ServiceSession<'_>, &FakeControl<'_>) -> ServiceEnd,
) -> ServiceExit {
    let (handler, stops) = mpsc::channel();
    let arbitration = ricevanta_os_windows::scm::StopArbitration::new(10_000);
    let control = FakeControl {
        send: handler,
        arbitration: &arbitration,
    };
    run_service_main(scm, &stops, &arbitration, |session| body(session, &control))
}

/// A requested stop that completes after `ticks` checkpoints.
fn requested_stop(
    request: StopRequest,
    timeout_ms: u64,
    ticks: usize,
    deadline_met: bool,
) -> impl FnOnce(&mut ServiceSession<'_>, &FakeControl<'_>) -> ServiceEnd {
    move |session, handler| {
        session.arbitration().configure_timeout(timeout_ms).unwrap();
        session.running().unwrap();
        // The control handler records the request and returns.
        handler.send(request).unwrap();
        let got = session.stop_requests().recv().unwrap();
        assert_eq!(got, request);
        session.stop_pending().unwrap();
        assert_eq!(session.arbitration().snapshot().stop_requests, 1);
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
        assert!(session.stop_pending().is_err());
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
) -> impl FnOnce(&mut ServiceSession<'_>, &FakeControl<'_>) -> ServiceEnd {
    move |session, handler| {
        session.running().unwrap();
        handler.send(StopRequest::Stop).unwrap();
        let request = session.stop_requests().recv().unwrap();
        assert_eq!(request, StopRequest::Stop);
        session.stop_pending().unwrap();
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

#[test]
fn accepted_unconsumed_stop_overrides_failure_in_both_orderings() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    for request in [StopRequest::Stop, StopRequest::Shutdown] {
        for failure_first in [false, true] {
            let arbitration = Arc::new(StopArbitration::new(60_000));
            let (send, receive) = mpsc::channel();
            let mut scm = FakeScm::default();
            let barrier = Arc::new(Barrier::new(2));
            let control_barrier = barrier.clone();
            let control = arbitration.clone();
            let received = Instant::now();
            let failed_at = received - Duration::from_secs(10);
            let mut cleanup_starts = 0;
            let exit = std::thread::scope(|scope| {
                let handler = scope.spawn(move || {
                    control_barrier.wait();
                    let accepted = control.accept(request, received);
                    // Leave this notification unconsumed: the latch is authority.
                    let sent = send.send(request);
                    control_barrier.wait();
                    assert!(accepted);
                    sent.unwrap();
                });
                let exit = run_service_main(&mut scm, &receive, &arbitration, |session| {
                    session.running().unwrap();
                    if failure_first {
                        arbitration.fail(failed_at);
                        cleanup_starts += usize::from(arbitration.begin_cleanup());
                    }
                    barrier.wait();
                    barrier.wait();
                    if !failure_first {
                        // The control already started the one cleanup.
                        cleanup_starts += usize::from(arbitration.begin_cleanup());
                        assert!(!arbitration.fail(received + Duration::from_secs(1)));
                    }
                    assert!(!arbitration.begin_cleanup());
                    let snapshot = arbitration.snapshot();
                    assert_eq!(snapshot.stop_requests, 1);
                    assert!(snapshot.failed);
                    assert_eq!(
                        snapshot.deadline,
                        Some(match (request, failure_first) {
                            (StopRequest::Stop, true) => failed_at + Duration::from_secs(60),
                            (StopRequest::Stop, false) => received + Duration::from_secs(60),
                            (StopRequest::Shutdown, _) => received + Duration::from_secs(15),
                        })
                    );
                    ServiceEnd::Other { exit_code: 1 }
                });
                handler.join().unwrap();
                exit
            });
            assert_eq!(cleanup_starts, 1);
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
            assert_eq!(scm.reports[2].controls_accepted, 0);
            assert!(!arbitration.accept(StopRequest::Stop, Instant::now()));
            assert_eq!(arbitration.snapshot().stop_requests, 1);
        }
    }
}

#[test]
fn control_during_final_writes_repeats_finalization_before_commit() {
    use ricevanta_os_windows::scm::{StopArbitration, run_service_main_with_finalizer};
    use std::sync::{Arc, Barrier};
    use std::time::Instant;
    let arbitration = Arc::new(StopArbitration::new(10_000));
    let control = arbitration.clone();
    let barrier = Arc::new(Barrier::new(2));
    let handler_barrier = barrier.clone();
    let (send, receive) = mpsc::channel();
    let mut scm = FakeScm::default();
    let mut finalized = Vec::new();
    let exit = std::thread::scope(|scope| {
        let handler = scope.spawn(move || {
            handler_barrier.wait();
            let accepted = control.accept(StopRequest::Stop, Instant::now());
            let sent = send.send(StopRequest::Stop);
            handler_barrier.wait();
            assert!(accepted);
            sent.unwrap();
        });
        let exit = run_service_main_with_finalizer(
            &mut scm,
            &receive,
            &arbitration,
            |session| {
                session.running().unwrap();
                ServiceEnd::Other { exit_code: 1 }
            },
            &mut |snapshot| {
                finalized.push(snapshot);
                if finalized.len() == 1 {
                    barrier.wait();
                    barrier.wait();
                }
            },
        );
        handler.join().unwrap();
        exit
    });
    assert_eq!(finalized.len(), 2);
    assert_eq!(finalized[0].stop_requests, 0);
    assert_eq!(finalized[1].stop_requests, 1);
    assert!(finalized[1].failed);
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
fn control_after_terminal_commit_is_rejected_before_acknowledgement() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::sync::{Arc, Barrier};
    use std::time::Instant;
    let arbitration = Arc::new(StopArbitration::new(10_000));
    let control = arbitration.clone();
    let barrier = Arc::new(Barrier::new(2));
    let handler_barrier = barrier.clone();
    let mut scm = FakeScm::default();
    let (_send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        let handler = scope.spawn(move || {
            handler_barrier.wait();
            let accepted = control.accept(StopRequest::Stop, Instant::now());
            handler_barrier.wait();
            assert!(!accepted);
        });
        let exit = run_service_main(&mut scm, &receive, &arbitration, |session| {
            session.running().unwrap();
            ServiceEnd::Other { exit_code: 1 }
        });
        barrier.wait();
        barrier.wait();
        handler.join().unwrap();
        assert!(!exit.reported_stopped);
    });
    assert_eq!(arbitration.snapshot().stop_requests, 0);
    assert_unreported_end(&scm, SERVICE_RUNNING);
}

#[test]
fn accepted_stop_never_extends_an_existing_cleanup_deadline() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::time::{Duration, Instant};
    let arbitration = StopArbitration::new(10_000);
    let (_send, receive) = mpsc::channel();
    let mut scm = FakeScm::default();
    let now = Instant::now();
    let exit = run_service_main(&mut scm, &receive, &arbitration, |session| {
        session.running().unwrap();
        assert!(arbitration.fail(now));
        assert!(arbitration.accept(StopRequest::Shutdown, now + Duration::from_secs(5)));
        assert_eq!(
            arbitration.snapshot().deadline,
            Some(now + Duration::from_secs(10))
        );
        assert!(!arbitration.fail(now + Duration::from_secs(8)));
        assert!(!arbitration.accept(StopRequest::Stop, now + Duration::from_secs(9)));
        assert_eq!(arbitration.snapshot().stop_requests, 1);
        ServiceEnd::Other { exit_code: 1 }
    });
    assert_stopped_with_code_1(&scm, exit);
}

#[test]
fn cleanup_is_claimed_once_across_failure_and_control() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::time::Instant;
    let arbitration = StopArbitration::new(10_000);
    let (_send, receive) = mpsc::channel();
    let mut scm = FakeScm::default();
    let exit = run_service_main(&mut scm, &receive, &arbitration, |session| {
        assert!(!arbitration.begin_cleanup());
        assert!(!arbitration.accept(StopRequest::Stop, Instant::now()));
        session.running().unwrap();
        arbitration.fail(Instant::now());
        assert!(arbitration.begin_cleanup());
        assert!(arbitration.accept(StopRequest::Stop, Instant::now()));
        assert!(!arbitration.begin_cleanup());
        assert!(arbitration.configure_timeout(60_000).is_err());
        ServiceEnd::Other { exit_code: 1 }
    });
    assert!(!arbitration.begin_cleanup());
    assert_stopped_with_code_1(&scm, exit);
}

#[test]
fn commitment_closes_controls_before_terminal_status_io() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::sync::{Arc, Barrier};
    use std::time::Instant;
    struct TerminalBarrier {
        scm: FakeScm,
        barrier: Arc<Barrier>,
    }
    impl StatusSink for TerminalBarrier {
        fn report(&mut self, report: StatusReport) -> io::Result<()> {
            if report.current_state == SERVICE_STOPPED {
                self.barrier.wait();
                self.barrier.wait();
            }
            self.scm.report(report)
        }
    }
    let barrier = Arc::new(Barrier::new(2));
    let arbitration = Arc::new(StopArbitration::new(10_000));
    let mut sink = TerminalBarrier {
        scm: FakeScm::default(),
        barrier: barrier.clone(),
    };
    let (_send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        let control = arbitration.clone();
        let handler = scope.spawn(move || {
            barrier.wait();
            let committed = control.snapshot().terminal_committed;
            let accepted = control.accept(StopRequest::Shutdown, Instant::now());
            barrier.wait();
            assert!(committed);
            assert!(!accepted);
        });
        let exit = run_service_main(&mut sink, &receive, &arbitration, |session| {
            session.running().unwrap();
            assert!(arbitration.accept(StopRequest::Stop, Instant::now()));
            ServiceEnd::RequestedStop { deadline_met: true }
        });
        handler.join().unwrap();
        assert_eq!(exit.exit_code, 0);
        assert!(exit.reported_stopped);
    });
    assert_eq!(
        sink.scm.states(),
        [
            SERVICE_START_PENDING,
            SERVICE_RUNNING,
            SERVICE_STOP_PENDING,
            SERVICE_STOPPED
        ]
    );
    assert_eq!(arbitration.snapshot().stop_requests, 1);
}

#[test]
fn terminal_owner_detects_actual_deadline_miss_even_when_body_claims_success() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::time::{Duration, Instant};
    let arbitration = StopArbitration::new(1000);
    let (_send, receive) = mpsc::channel();
    let mut scm = FakeScm::default();
    let exit = run_service_main(&mut scm, &receive, &arbitration, |session| {
        session.running().unwrap();
        assert!(arbitration.accept(StopRequest::Stop, Instant::now() - Duration::from_secs(2)));
        ServiceEnd::RequestedStop { deadline_met: true }
    });
    assert_stopped_with_code_1(&scm, exit);
}

#[test]
fn caught_panic_payload_cannot_run_a_destructor_after_commit() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Payload(Arc<AtomicUsize>);
    impl Drop for Payload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let arbitration = StopArbitration::new(10_000);
    let (_send, receive) = mpsc::channel();
    let mut scm = FakeScm::default();
    let exit = run_service_main(&mut scm, &receive, &arbitration, |session| {
        session.running().unwrap();
        std::panic::panic_any(Payload(drops.clone()));
    });
    assert_eq!(exit.exit_code, 1);
    assert!(!exit.reported_stopped);
    assert!(arbitration.snapshot().terminal_committed);
    // Terminal service exit follows immediately. Dropping a user panic
    // payload could block or panic, so retain it until process termination.
    assert_eq!(drops.load(Ordering::SeqCst), 0);
}

#[test]
fn finalizer_panic_payload_cannot_block_terminal_exit() {
    use ricevanta_os_windows::scm::{StopArbitration, run_service_main_with_finalizer};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;
    struct Payload(Arc<AtomicUsize>);
    impl Drop for Payload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let arbitration = StopArbitration::new(10_000);
    let (_send, receive) = mpsc::channel();
    let mut scm = FakeScm::default();
    let mut calls = 0;
    let exit = run_service_main_with_finalizer(
        &mut scm,
        &receive,
        &arbitration,
        |session| {
            session.running().unwrap();
            assert!(arbitration.accept(StopRequest::Stop, Instant::now()));
            ServiceEnd::RequestedStop { deadline_met: true }
        },
        &mut |_| {
            calls += 1;
            if calls == 1 {
                std::panic::panic_any(Payload(drops.clone()));
            }
        },
    );
    assert_eq!(calls, 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_stopped_with_code_1(&scm, exit);
}

#[test]
fn initial_status_failure_cannot_drop_unused_body_after_commit() {
    use ricevanta_os_windows::scm::StopArbitration;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Capture(Arc<AtomicUsize>);
    impl Drop for Capture {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let capture = Capture(drops.clone());
    let arbitration = StopArbitration::new(10_000);
    let (_send, receive) = mpsc::channel();
    let mut scm = FakeScm {
        fail_from: Some(0),
        ..FakeScm::default()
    };
    let exit = run_service_main(&mut scm, &receive, &arbitration, move |_| {
        let _capture = capture;
        panic!("body must not run after initial status failure");
    });
    assert_eq!(exit.exit_code, 3);
    assert!(!exit.reported_stopped);
    assert!(arbitration.snapshot().terminal_committed);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
}
