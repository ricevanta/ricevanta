//! The native Service Control Manager glue and the Application event log
//! writer (spec sections 5.4 and 6). The status sequence itself lives in
//! the portable [`crate::scm`] module; this module only connects it to
//! `StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW` and
//! `SetServiceStatus`, and writes event log lines with
//! `RegisterEventSourceW`, `ReportEventW` and `DeregisterEventSource`.

use crate::eventlog::{self, EventKind};
use crate::scm::{
    self, ServiceEnd, ServiceExit, ServiceSession, StatusReport, StatusSink, StopArbitration,
    StopRequest, StopSnapshot,
};
use std::ffi::c_void;
use std::io;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_SPECIFIC_ERROR, HANDLE, NO_ERROR,
};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW,
    ReportEventW,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    StartServiceCtrlDispatcherW,
};

// The portable constants are the documented Win32 values.
const _: () = {
    assert!(scm::SERVICE_STOPPED == SERVICE_STOPPED);
    assert!(scm::SERVICE_START_PENDING == SERVICE_START_PENDING);
    assert!(scm::SERVICE_STOP_PENDING == SERVICE_STOP_PENDING);
    assert!(scm::SERVICE_RUNNING == SERVICE_RUNNING);
    assert!(scm::SERVICE_ACCEPT_STOP == SERVICE_ACCEPT_STOP);
    assert!(scm::SERVICE_ACCEPT_SHUTDOWN == SERVICE_ACCEPT_SHUTDOWN);
    assert!(scm::NO_ERROR == NO_ERROR);
    assert!(scm::ERROR_SERVICE_SPECIFIC_ERROR == ERROR_SERVICE_SPECIFIC_ERROR);
};

/// The service body the core runs inside `ServiceMain`.
pub type ServiceBody = Box<dyn FnOnce(&mut ServiceSession<'_>) -> ServiceEnd + Send>;

/// Final health/log writes performed before terminal commitment. The core
/// must use the supplied snapshot, including its latched stop counter.
pub type ServiceFinalizer = Box<dyn FnMut(StopSnapshot) + Send>;

static BODY: Mutex<Option<(ServiceBody, ServiceFinalizer)>> = Mutex::new(None);
static STOPS: Mutex<Option<(Sender<StopRequest>, Arc<StopArbitration>)>> = Mutex::new(None);
static EXIT: Mutex<Option<ServiceExit>> = Mutex::new(None);

/// Why the dispatcher could not run the service.
#[derive(Debug)]
pub enum DispatchError {
    /// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: the process was not
    /// started by the SCM; the hint is to use `run` (exit 3).
    NotStartedBySCM,
    /// Any other dispatcher failure (exit 3).
    Os(io::Error),
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Runs `body` as the `ServiceMain` of the own-process service
/// `RicevantaAgent`; call from the main thread within 30 seconds of
/// process start. Returns the exit code after a requested stop that was
/// reported as `SERVICE_STOPPED`. Every other end ends the process inside
/// `ServiceMain` with its exit code and without a `SERVICE_STOPPED` report,
/// so this function does not return then.
pub fn dispatch(body: ServiceBody) -> Result<i32, DispatchError> {
    dispatch_with_finalizer(body, Box::new(|_| {}))
}

/// Runs the service with final evidence writes outside the arbitration lock.
/// Finalization repeats if a stop is accepted during those writes. Configure
/// the validated timeout through the session's arbitration before `running`.
pub fn dispatch_with_finalizer(
    body: ServiceBody,
    finalize: ServiceFinalizer,
) -> Result<i32, DispatchError> {
    *BODY.lock().unwrap_or_else(PoisonError::into_inner) = Some((body, finalize));
    let mut name = wide(eventlog::SOURCE);
    start_dispatcher(&mut name).map_err(|e| {
        if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) {
            DispatchError::NotStartedBySCM
        } else {
            DispatchError::Os(e)
        }
    })?;
    let exit = EXIT.lock().unwrap_or_else(PoisonError::into_inner).take();
    Ok(exit.map_or(3, |e| e.exit_code))
}

#[expect(
    unsafe_code,
    reason = "StartServiceCtrlDispatcherW: the table and the NUL-terminated name outlive the blocking call; the table ends with a null entry"
)]
fn start_dispatcher(name: &mut [u16]) -> io::Result<()> {
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` and the name it points to stay alive and unmoved for
    // the whole call, which returns only after the service stopped; the
    // last entry is the required null terminator.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `ServiceMain`: registers the control handler first, then runs the body
/// through [`scm::run_service_main_with_finalizer`].
extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let (send, receive) = mpsc::channel();
    let arbitration = Arc::new(StopArbitration::new(10_000));
    *STOPS.lock().unwrap_or_else(PoisonError::into_inner) = Some((send, arbitration.clone()));
    let Some(handle) = register_handler() else {
        // Nothing can be reported without a status handle.
        std::process::exit(3);
    };
    let Some((body, mut finalize)) = BODY.lock().unwrap_or_else(PoisonError::into_inner).take()
    else {
        std::process::exit(3);
    };
    let mut sink = ScmSink { handle };
    let exit = scm::run_service_main_with_finalizer(
        &mut sink,
        &receive,
        &arbitration,
        body,
        &mut finalize,
    );
    if !exit.reported_stopped {
        // Not a requested stop: end without SERVICE_STOPPED so the SCM
        // treats the end like a crash and runs the restart action.
        std::process::exit(exit.exit_code);
    }
    *EXIT.lock().unwrap_or_else(PoisonError::into_inner) = Some(exit);
}

/// `HandlerEx`: latches stop intent before queuing a wakeup and
/// returns at once; answers interrogation with `NO_ERROR`, since the SCM
/// already holds the current status.
extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    let request = match control {
        SERVICE_CONTROL_STOP => StopRequest::Stop,
        SERVICE_CONTROL_SHUTDOWN => StopRequest::Shutdown,
        SERVICE_CONTROL_INTERROGATE => return NO_ERROR,
        _ => return ERROR_CALL_NOT_IMPLEMENTED,
    };
    let received_at = Instant::now();
    let control = STOPS.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let Some((send, arbitration)) = control else {
        return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
    };
    if !arbitration.accept(request, received_at) {
        return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
    }
    // A dropped or unconsumed notification cannot erase accepted intent.
    let _ = send.send(request);
    NO_ERROR
}

#[expect(
    unsafe_code,
    reason = "RegisterServiceCtrlHandlerExW: the NUL-terminated name lives for the call; the handler is a static function and needs no context"
)]
fn register_handler() -> Option<SERVICE_STATUS_HANDLE> {
    let name = wide(eventlog::SOURCE);
    // SAFETY: `name` is NUL-terminated and alive for the call; the handler
    // is a `'static` function item; the context pointer is unused (null).
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), std::ptr::null())
    };
    (!handle.is_null()).then_some(handle)
}

/// Reports through `SetServiceStatus` on the registered handle.
struct ScmSink {
    handle: SERVICE_STATUS_HANDLE,
}

impl StatusSink for ScmSink {
    #[expect(
        unsafe_code,
        reason = "SetServiceStatus: the status handle came from RegisterServiceCtrlHandlerExW and is never closed; the SERVICE_STATUS is a stack value"
    )]
    fn report(&mut self, report: StatusReport) -> io::Result<()> {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: report.current_state,
            dwControlsAccepted: report.controls_accepted,
            dwWin32ExitCode: report.win32_exit_code,
            dwServiceSpecificExitCode: report.service_specific_exit_code,
            dwCheckPoint: report.check_point,
            dwWaitHint: report.wait_hint_ms,
        };
        // SAFETY: the handle is the valid status handle of this service;
        // `status` is alive for the call.
        if unsafe { SetServiceStatus(self.handle, &raw const status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The Application event log under source `RicevantaAgent`, for the lines
/// written before the log file opens. Deregistered on drop.
#[derive(Debug)]
pub struct EventLog {
    handle: HANDLE,
}

impl EventLog {
    /// Registers the event source on the local computer.
    pub fn open() -> io::Result<EventLog> {
        Self::open_native()
    }

    #[expect(
        unsafe_code,
        reason = "RegisterEventSourceW: a null server name means the local computer; the NUL-terminated source name lives for the call"
    )]
    fn open_native() -> io::Result<EventLog> {
        let source = wide(eventlog::SOURCE);
        // SAFETY: null selects the local computer; `source` is
        // NUL-terminated and alive for the call.
        let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(EventLog { handle })
    }

    /// Writes one JSON log line as the single insertion string, with every
    /// `%` escaped and the length bounded (see [`eventlog::event_text`]).
    pub fn write(&self, line: &str, kind: EventKind) -> io::Result<()> {
        self.write_native(line, kind)
    }

    #[expect(
        unsafe_code,
        reason = "ReportEventW: one NUL-terminated insertion string that lives for the call, no SID and no raw data"
    )]
    fn write_native(&self, line: &str, kind: EventKind) -> io::Result<()> {
        let text = wide(&eventlog::event_text(line));
        let strings = [text.as_ptr()];
        let event_type = match kind {
            EventKind::Error => EVENTLOG_ERROR_TYPE,
            EventKind::Information => EVENTLOG_INFORMATION_TYPE,
        };
        // SAFETY: the handle is a registered event source; `strings` holds
        // one pointer to a NUL-terminated string, both alive for the call;
        // the SID and raw data are null with size 0.
        let ok = unsafe {
            ReportEventW(
                self.handle,
                event_type,
                0,
                0,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for EventLog {
    #[expect(
        unsafe_code,
        reason = "DeregisterEventSource: the handle came from RegisterEventSourceW and is released once"
    )]
    fn drop(&mut self) {
        // SAFETY: the handle is valid and owned by this value.
        unsafe { DeregisterEventSource(self.handle) };
    }
}
