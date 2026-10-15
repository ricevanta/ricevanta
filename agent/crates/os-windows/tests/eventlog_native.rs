//! The Application event log writer on Windows (spec section 6): one
//! `startup_failed` line whose `%` characters arrive as JSON escapes, read
//! back with `Get-WinEvent`. Needs the runner's administrator to register
//! the source the way the AG-12 installer does.
#![cfg(windows)]

use ricevanta_os_windows::EventLog;
use ricevanta_os_windows::eventlog::{EventKind, SOURCE};
use std::process::Command;

fn powershell(script: &str) -> String {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn startup_failed_line_is_written_with_escaped_percent() {
    // Registering may fail when the source already exists; that is fine.
    let _ = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("New-EventLog -LogName Application -Source {SOURCE}"),
        ])
        .output();
    let marker = format!("rv-eventlog-{}-{}", std::process::id(), line!());
    let line =
        format!(r#"{{"detail":"{marker} 100% done %n","event":"startup_failed","level":"error"}}"#);
    let log = EventLog::open().unwrap();
    log.write(&line, EventKind::for_event("startup_failed"))
        .unwrap();
    drop(log);

    let script = format!(
        "Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='{SOURCE}'}} \
         -MaxEvents 50 | Where-Object {{ $_.Properties[0].Value -like '*{marker}*' }} | \
         ForEach-Object {{ \"$($_.Level)|$($_.Properties[0].Value)\" }}"
    );
    let found = powershell(&script);
    let found = found.lines().next().expect("event not found");
    let (level, text) = found.split_once('|').unwrap();
    // Level 2 is Error.
    assert_eq!(level.trim(), "2");
    let escape = format!("{}u0025", '\\');
    assert!(!text.contains('%'), "{text}");
    assert!(
        text.contains(&format!("100{escape} done {escape}n")),
        "{text}"
    );
    assert_eq!(
        ricevanta_json::parse(text.trim().as_bytes()).unwrap(),
        ricevanta_json::parse(line.as_bytes()).unwrap()
    );
}
