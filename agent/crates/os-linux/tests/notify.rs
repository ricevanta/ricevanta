//! The `sd_notify` datagram client of spec section 5.2.
#![cfg(target_os = "linux")]

use ricevanta_os::{LifecycleState, NotifyError, ServiceManager};
use ricevanta_os_linux::SystemdNotifier;
use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn unique(tag: &str) -> String {
    format!(
        "rv-notify-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

struct Listener {
    socket: UnixDatagram,
    address: String,
    path: Option<PathBuf>,
}

impl Listener {
    fn path() -> Listener {
        let path = std::env::temp_dir().join(unique("path"));
        let _ = std::fs::remove_file(&path);
        let socket = UnixDatagram::bind(&path).unwrap();
        Listener {
            socket,
            address: path.to_str().unwrap().to_owned(),
            path: Some(path),
        }
    }

    fn abstract_name() -> Listener {
        let name = unique("abstract");
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let socket = UnixDatagram::bind_addr(&address).unwrap();
        Listener {
            socket,
            address: format!("@{name}"),
            path: None,
        }
    }

    fn receive(&self) -> String {
        self.socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buffer = [0u8; 256];
        let n = self.socket.recv(&mut buffer).expect("datagram expected");
        String::from_utf8(buffer[..n].to_vec()).unwrap()
    }

    fn assert_empty(&self) {
        self.socket.set_nonblocking(true).unwrap();
        let mut buffer = [0u8; 256];
        let result = self.socket.recv(&mut buffer);
        assert!(
            matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "unexpected datagram {:?}",
            result.map(|n| String::from_utf8_lossy(&buffer[..n]).into_owned())
        );
        self.socket.set_nonblocking(false).unwrap();
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn os(text: &str) -> Option<&OsStr> {
    Some(OsStr::new(text))
}

fn full_sequence(listener: &Listener) {
    let pid = std::process::id();
    let notifier =
        SystemdNotifier::from_vars(os(&listener.address), os("180000000"), None, pid).unwrap();
    assert_eq!(notifier.watchdog_usec(), Some(180_000_000));
    notifier.ready().unwrap();
    notifier.status(LifecycleState::Ready).unwrap();
    notifier.watchdog().unwrap();
    notifier.stopping().unwrap();
    notifier.status(LifecycleState::Stopping).unwrap();
    assert_eq!(listener.receive(), "READY=1");
    assert_eq!(listener.receive(), "STATUS=ready");
    assert_eq!(listener.receive(), "WATCHDOG=1");
    assert_eq!(listener.receive(), "STOPPING=1");
    assert_eq!(listener.receive(), "STATUS=stopping");
    listener.assert_empty();
}

#[test]
fn datagrams_to_a_path_socket() {
    full_sequence(&Listener::path());
}

#[test]
fn datagrams_to_an_abstract_socket() {
    full_sequence(&Listener::abstract_name());
}

#[test]
fn absent_socket_sends_nothing_and_succeeds() {
    let notifier = SystemdNotifier::from_vars(None, None, None, std::process::id()).unwrap();
    assert_eq!(notifier.watchdog_usec(), None);
    notifier.ready().unwrap();
    notifier.status(LifecycleState::Starting).unwrap();
    notifier.watchdog().unwrap();
    notifier.stopping().unwrap();
    let disabled = SystemdNotifier::disabled();
    disabled.ready().unwrap();
    assert_eq!(disabled.watchdog_usec(), None);
}

#[test]
fn one_watchdog_ping_per_call() {
    let listener = Listener::path();
    let notifier = SystemdNotifier::from_vars(
        os(&listener.address),
        os("60000000"),
        os(&std::process::id().to_string()),
        std::process::id(),
    )
    .unwrap();
    assert_eq!(notifier.watchdog_usec(), Some(60_000_000));
    for _ in 0..3 {
        notifier.watchdog().unwrap();
    }
    for _ in 0..3 {
        assert_eq!(listener.receive(), "WATCHDOG=1");
    }
    listener.assert_empty();
}

#[test]
fn watchdog_for_another_pid_is_disabled() {
    let listener = Listener::path();
    let own = std::process::id();
    let other = (own + 1).to_string();
    let notifier =
        SystemdNotifier::from_vars(os(&listener.address), os("180000000"), os(&other), own)
            .unwrap();
    assert_eq!(notifier.watchdog_usec(), None);
    notifier.watchdog().unwrap();
    listener.assert_empty();
    // Other messages still go to the manager.
    notifier.ready().unwrap();
    assert_eq!(listener.receive(), "READY=1");
}

#[test]
fn invalid_environment_values_are_errors() {
    let pid = std::process::id();
    for bad in ["", "abc", "0", "-5", "18446744073709551616", " 1"] {
        assert_eq!(
            SystemdNotifier::from_vars(None, os(bad), None, pid).err(),
            Some(NotifyError::Environment {
                variable: "WATCHDOG_USEC"
            }),
            "{bad:?}"
        );
    }
    assert_eq!(
        SystemdNotifier::from_vars(None, os("1000"), os("x"), pid).err(),
        Some(NotifyError::Environment {
            variable: "WATCHDOG_PID"
        })
    );
    for bad in ["relative/socket", "", "vsock:2:1"] {
        assert_eq!(
            SystemdNotifier::from_vars(os(bad), None, None, pid).err(),
            Some(NotifyError::Address),
            "{bad:?}"
        );
    }
    let not_utf8 = OsStr::from_bytes(b"/tmp/\xff");
    assert!(SystemdNotifier::from_vars(Some(not_utf8), None, None, pid).is_ok());
}

#[test]
fn send_failure_is_reported() {
    let missing = std::env::temp_dir().join(unique("missing"));
    let notifier =
        SystemdNotifier::from_vars(Some(missing.as_os_str()), None, None, std::process::id())
            .unwrap();
    assert!(matches!(notifier.ready(), Err(NotifyError::Io { .. })));
}

#[test]
fn environment_is_read_by_from_env() {
    let listener = Listener::path();
    let exe = std::env::current_exe().unwrap();
    let output = Command::new(exe)
        .args(["from_env_child", "--exact", "--ignored", "--test-threads=1"])
        .env_remove("WATCHDOG_PID")
        .env("NOTIFY_SOCKET", &listener.address)
        .env("WATCHDOG_USEC", "180000000")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(listener.receive(), "READY=1");
    assert_eq!(listener.receive(), "WATCHDOG=1");
    listener.assert_empty();
}

#[test]
#[ignore = "child of environment_is_read_by_from_env"]
fn from_env_child() {
    let notifier = SystemdNotifier::from_env(std::process::id()).unwrap();
    notifier.ready().unwrap();
    notifier.watchdog().unwrap();
}
