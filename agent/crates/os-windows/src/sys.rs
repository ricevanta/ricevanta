//! The only `unsafe` code of this crate: private wrappers over the locked
//! `windows-sys` declarations named in the licensing row. Each function
//! carries `#[expect(unsafe_code, reason = "...")]` and a `// SAFETY:`
//! comment for every unsafe block (spec section 1.1). No handle, pointer or
//! `extern` item leaves this module; callers get owned Rust values.

use crate::dacl::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, Ace, SecurityFacts};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, FILETIME, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessHandleCount, GetProcessTimes,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

/// The longest wide string read from a system-allocated buffer, in units:
/// the maximum extended-length path.
const MAX_WIDE: usize = 32_768;

#[expect(
    unsafe_code,
    reason = "reads a NUL-terminated wide string the caller guarantees valid for at most MAX_WIDE units"
)]
fn wide_to_os(text: *const u16) -> Option<OsString> {
    if text.is_null() {
        return None;
    }
    let mut len = 0;
    // SAFETY: the caller passes a NUL-terminated string allocated by the
    // system; reading stops at the terminator and never beyond MAX_WIDE.
    while len < MAX_WIDE && unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_WIDE {
        return None;
    }
    // SAFETY: `len` units starting at `text` were just read as initialised.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    Some(OsString::from_wide(units))
}

#[expect(
    unsafe_code,
    reason = "SHGetKnownFolderPath: the out PWSTR is freed with CoTaskMemFree whether the call succeeds or not"
)]
pub(crate) fn program_data() -> io::Result<OsString> {
    let mut path: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the GUID is a static, the token is null (the calling
    // process), and `path` is a valid out pointer.
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &raw mut path,
        )
    };
    let result = if hr >= 0 {
        wide_to_os(path).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
    } else {
        Err(io::Error::from_raw_os_error(hr))
    };
    // SAFETY: "whether SHGetKnownFolderPath succeeds or not" the buffer is
    // freed with CoTaskMemFree; freeing null is a no-op.
    unsafe { CoTaskMemFree(path.cast_const().cast()) };
    result
}

/// Frees a `LocalAlloc` buffer the system returned, on every path.
struct LocalBuffer(*mut core::ffi::c_void);

impl Drop for LocalBuffer {
    #[expect(
        unsafe_code,
        reason = "LocalFree: the pointer came from a system call that documents LocalFree as its release, and is freed once"
    )]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the buffer was allocated by GetSecurityInfo or
            // ConvertSidToStringSidW and is released exactly once here.
            unsafe { LocalFree(self.0) };
        }
    }
}

#[expect(
    unsafe_code,
    reason = "ConvertSidToStringSidW: the SID is validated first; the returned string is freed with LocalFree"
)]
fn sid_string(sid: PSID) -> Option<String> {
    // SAFETY: `sid` points into a security descriptor that outlives this
    // call; IsValidSid only reads it.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` is valid and `text` is a valid out pointer.
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut text) };
    let _guard = LocalBuffer(text.cast());
    if ok == 0 {
        return None;
    }
    wide_to_os(text).and_then(|s| s.into_string().ok())
}

#[expect(
    unsafe_code,
    reason = "GetSecurityInfo and GetAce: the handle is borrowed open for the call; the descriptor is freed with LocalFree after every entry is decoded"
)]
pub(crate) fn security(file: &File) -> io::Result<SecurityFacts> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is open with READ_CONTROL for the whole call because
    // `file` is borrowed; every out pointer is valid; group and SACL are
    // not requested and passed as null.
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    let _guard = LocalBuffer(descriptor);
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let owner = sid_string(owner);
    if dacl.is_null() {
        return Ok(SecurityFacts { owner, dacl: None });
    }
    // SAFETY: a non-null DACL points into `descriptor`, alive until
    // `_guard` drops; ACL is a plain header read by value.
    let count = unsafe { (*dacl).AceCount };
    let mut entries = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `index` is below the ACL's own count; `ace` is a valid out
        // pointer.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returns a pointer to an entry inside the ACL, which
        // starts with an ACE_HEADER.
        let header = unsafe { std::ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        let decoded = if matches!(
            header.AceType,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) && usize::from(header.AceSize)
            >= std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            // SAFETY: allowed and denied entries share the ACCESS_ALLOWED_ACE
            // layout, and AceSize covers it; the SID starts at SidStart and
            // lies within the entry.
            let entry = unsafe { std::ptr::read_unaligned(ace.cast::<ACCESS_ALLOWED_ACE>()) };
            // SAFETY: `ace` points to a live ACCESS_ALLOWED_ACE-layout entry;
            // taking the field's address creates no reference, so alignment
            // is not required.
            let sid = unsafe { &raw mut (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart };
            Ace {
                ace_type: header.AceType,
                flags: header.AceFlags,
                mask: entry.Mask,
                sid: sid_string(sid.cast()),
            }
        } else {
            Ace {
                ace_type: header.AceType,
                flags: header.AceFlags,
                mask: 0,
                sid: None,
            }
        };
        entries.push(decoded);
    }
    Ok(SecurityFacts {
        owner,
        dacl: Some(entries),
    })
}

/// The process memory counters the sampler and the growth test read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Memory {
    pub(crate) private_working_set: u64,
    pub(crate) private_usage: u64,
}

#[expect(
    unsafe_code,
    reason = "GetProcessMemoryInfo: the buffer is a stack PROCESS_MEMORY_COUNTERS_EX2 whose size is passed as cb"
)]
pub(crate) fn memory() -> io::Result<Memory> {
    let mut counters = PROCESS_MEMORY_COUNTERS_EX2 {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32,
        ..Default::default()
    };
    // SAFETY: the pseudo-handle needs no closing; the pointer and `cb`
    // describe `counters`, which starts with PROCESS_MEMORY_COUNTERS.
    let ok = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&raw mut counters).cast::<PROCESS_MEMORY_COUNTERS>(),
            counters.cb,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Memory {
        private_working_set: counters.PrivateWorkingSetSize as u64,
        private_usage: counters.PrivateUsage as u64,
    })
}

fn filetime_100ns(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

#[expect(
    unsafe_code,
    reason = "GetProcessTimes: four stack FILETIME out values for the current-process pseudo-handle"
)]
pub(crate) fn times() -> io::Result<(u64, u64)> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: every out pointer refers to a live stack FILETIME.
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((filetime_100ns(user), filetime_100ns(kernel)))
}

#[expect(
    unsafe_code,
    reason = "GetProcessHandleCount: one stack u32 out value for the current-process pseudo-handle"
)]
pub(crate) fn handle_count() -> io::Result<u32> {
    let mut count = 0u32;
    // SAFETY: `count` is a valid out pointer.
    if unsafe { GetProcessHandleCount(GetCurrentProcess(), &raw mut count) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(count)
}

/// Closes a snapshot handle on every path.
struct Snapshot(HANDLE);

impl Drop for Snapshot {
    #[expect(
        unsafe_code,
        reason = "CloseHandle: the snapshot handle is owned here and closed once"
    )]
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateToolhelp32Snapshot, is valid,
        // and is closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

#[expect(
    unsafe_code,
    reason = "CreateToolhelp32Snapshot and Process32FirstW/NextW: one stack PROCESSENTRY32W with dwSize set; the snapshot handle is closed by its guard"
)]
pub(crate) fn thread_count(pid: u32) -> io::Result<u32> {
    // SAFETY: plain flags; the returned handle is checked before use.
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let snapshot = Snapshot(handle);
    // SAFETY: PROCESSENTRY32W is plain data; all-zero is a valid value.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: the snapshot handle is valid and `entry` has dwSize set.
    let mut ok = unsafe { Process32FirstW(snapshot.0, &raw mut entry) };
    while ok != 0 {
        if entry.th32ProcessID == pid {
            return Ok(entry.cntThreads);
        }
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snapshot.0, &raw mut entry) };
    }
    Err(io::Error::from(io::ErrorKind::NotFound))
}
