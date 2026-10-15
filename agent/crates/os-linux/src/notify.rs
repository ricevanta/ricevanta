//! The systemd notification protocol, reimplemented as `sd_notify(3)`
//! permits: one datagram per message to the `NOTIFY_SOCKET` address.

use ricevanta_os::{LifecycleState, NotifyError, ServiceManager};
use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;

/// Sends `READY=1`, `STATUS=<state>`, `WATCHDOG=1` and `STOPPING=1`
/// datagrams to the service manager.
///
/// Without `NOTIFY_SOCKET` every method succeeds and sends nothing.
/// `WATCHDOG=1` is sent only when `WATCHDOG_USEC` is set and `WATCHDOG_PID`
/// is unset or names the own process, as `sd_watchdog_enabled(3)` defines.
#[derive(Debug)]
pub struct SystemdNotifier {
    channel: Option<(UnixDatagram, SocketAddr)>,
    watchdog_usec: Option<u64>,
}

impl SystemdNotifier {
    /// A notifier that sends nothing, for `run` mode.
    pub fn disabled() -> SystemdNotifier {
        SystemdNotifier {
            channel: None,
            watchdog_usec: None,
        }
    }

    /// Reads exactly `NOTIFY_SOCKET`, `WATCHDOG_USEC` and `WATCHDOG_PID`
    /// from the environment. Call only in `service` mode.
    pub fn from_env(own_pid: u32) -> Result<SystemdNotifier, NotifyError> {
        let socket = std::env::var_os("NOTIFY_SOCKET");
        let usec = std::env::var_os("WATCHDOG_USEC");
        let pid = std::env::var_os("WATCHDOG_PID");
        SystemdNotifier::from_vars(socket.as_deref(), usec.as_deref(), pid.as_deref(), own_pid)
    }

    /// Builds a notifier from the three variable values.
    ///
    /// Errors: [`NotifyError::Environment`] for a `WATCHDOG_PID` or
    /// `WATCHDOG_USEC` that is not a positive decimal integer (the pid is
    /// checked first, and `WATCHDOG_USEC` only when the watchdog applies to
    /// `own_pid`); [`NotifyError::Address`] for a `NOTIFY_SOCKET` that is
    /// neither a path starting with `/` nor an abstract name starting with
    /// `@`; [`NotifyError::Io`] when the socket cannot be created.
    pub fn from_vars(
        notify_socket: Option<&OsStr>,
        watchdog_usec: Option<&OsStr>,
        watchdog_pid: Option<&OsStr>,
        own_pid: u32,
    ) -> Result<SystemdNotifier, NotifyError> {
        let applies = match watchdog_pid {
            None => true,
            Some(text) => {
                let pid = positive(text).ok_or(NotifyError::Environment {
                    variable: "WATCHDOG_PID",
                })?;
                pid == u64::from(own_pid)
            }
        };
        let watchdog_usec = match watchdog_usec {
            Some(text) if applies => Some(positive(text).ok_or(NotifyError::Environment {
                variable: "WATCHDOG_USEC",
            })?),
            _ => None,
        };
        let channel = match notify_socket {
            None => None,
            Some(text) => {
                let bytes = text.as_bytes();
                let address = match bytes.first() {
                    Some(b'/') => SocketAddr::from_pathname(Path::new(text))
                        .map_err(|_| NotifyError::Address)?,
                    Some(b'@') => SocketAddr::from_abstract_name(&bytes[1..])
                        .map_err(|_| NotifyError::Address)?,
                    _ => return Err(NotifyError::Address),
                };
                let socket = UnixDatagram::unbound().map_err(|e| NotifyError::io(&e))?;
                Some((socket, address))
            }
        };
        Ok(SystemdNotifier {
            channel,
            watchdog_usec,
        })
    }

    /// The watchdog period in microseconds when the watchdog applies to this
    /// process; the configuration loader bounds `health.interval_ms` by it.
    pub fn watchdog_usec(&self) -> Option<u64> {
        self.watchdog_usec
    }

    fn send(&self, message: &str) -> Result<(), NotifyError> {
        let Some((socket, address)) = &self.channel else {
            return Ok(());
        };
        let sent = socket
            .send_to_addr(message.as_bytes(), address)
            .map_err(|e| NotifyError::io(&e))?;
        if sent == message.len() {
            Ok(())
        } else {
            Err(NotifyError::Io {
                kind: std::io::ErrorKind::WriteZero,
                code: None,
            })
        }
    }
}

fn positive(text: &OsStr) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = bytes.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })?;
    (n > 0).then_some(n)
}

impl ServiceManager for SystemdNotifier {
    fn ready(&self) -> Result<(), NotifyError> {
        self.send("READY=1")
    }

    fn status(&self, state: LifecycleState) -> Result<(), NotifyError> {
        let message = match state {
            LifecycleState::Starting => "STATUS=starting",
            LifecycleState::Ready => "STATUS=ready",
            LifecycleState::Stopping => "STATUS=stopping",
            LifecycleState::Stopped => "STATUS=stopped",
        };
        self.send(message)
    }

    fn watchdog(&self) -> Result<(), NotifyError> {
        if self.watchdog_usec.is_some() {
            self.send("WATCHDOG=1")
        } else {
            Ok(())
        }
    }

    fn stopping(&self) -> Result<(), NotifyError> {
        self.send("STOPPING=1")
    }
}
