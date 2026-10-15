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
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorLength, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID,
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

/// How a [`WideBuffer`] is released.
#[derive(Clone, Copy)]
enum Release {
    /// `CoTaskMemFree` (`SHGetKnownFolderPath`).
    CoTaskMem,
    /// `LocalFree` (`ConvertSidToStringSidW`).
    Local,
}

/// A NUL-terminated wide string that a system call allocated and wrote
/// through the out pointer `&raw mut buffer.ptr`, and this value owns.
///
/// Invariant: `ptr` is null or such a string, valid until `drop`, which
/// frees it with the matching function exactly once. The pointer is only
/// ever written by the system call itself, never passed in by a caller.
struct WideBuffer {
    ptr: windows_sys::core::PWSTR,
    release: Release,
}

impl WideBuffer {
    fn empty(release: Release) -> WideBuffer {
        WideBuffer {
            ptr: std::ptr::null_mut(),
            release,
        }
    }

    #[expect(
        unsafe_code,
        reason = "reads the owned NUL-terminated system string, at most MAX_WIDE units, per the type invariant"
    )]
    fn to_os(&self) -> Option<OsString> {
        if self.ptr.is_null() {
            return None;
        }
        let mut len = 0;
        // SAFETY: by the type invariant `ptr` is a NUL-terminated string
        // alive while `self` is borrowed; reading stops at the terminator and
        // never beyond MAX_WIDE units.
        while len < MAX_WIDE && unsafe { self.ptr.add(len).read() } != 0 {
            len += 1;
        }
        if len == MAX_WIDE {
            return None;
        }
        // SAFETY: the `len` units before the terminator were just read as
        // initialised and stay alive while `self` is borrowed.
        let units = unsafe { std::slice::from_raw_parts(self.ptr, len) };
        Some(OsString::from_wide(units))
    }
}

impl Drop for WideBuffer {
    #[expect(
        unsafe_code,
        reason = "CoTaskMemFree or LocalFree: releases the owned system string once, with the function its allocator documents"
    )]
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        match self.release {
            // SAFETY: allocated by SHGetKnownFolderPath, released once.
            Release::CoTaskMem => unsafe { CoTaskMemFree(self.ptr.cast_const().cast()) },
            // SAFETY: allocated by ConvertSidToStringSidW, released once.
            Release::Local => unsafe {
                LocalFree(self.ptr.cast());
            },
        }
    }
}

#[expect(
    unsafe_code,
    reason = "SHGetKnownFolderPath: writes the out PWSTR owned by a WideBuffer, which frees it with CoTaskMemFree whether the call succeeds or not"
)]
pub(crate) fn program_data() -> io::Result<OsString> {
    let mut path = WideBuffer::empty(Release::CoTaskMem);
    // SAFETY: the GUID is a static, the token is null (the calling
    // process), and the out pointer is the buffer's own field.
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &raw mut path.ptr,
        )
    };
    // `path` is dropped, and so freed, on every path below.
    if hr < 0 {
        return Err(io::Error::from_raw_os_error(hr));
    }
    path.to_os()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

/// The self-relative security descriptor `GetSecurityInfo` allocated.
///
/// Invariant: `start` is null or the descriptor, `len` its
/// `GetSecurityDescriptorLength`, all of it readable until `drop`, which
/// frees it with `LocalFree` once.
struct Descriptor {
    start: PSECURITY_DESCRIPTOR,
    len: usize,
}

impl Descriptor {
    /// Whether `len` bytes from `ptr` lie inside the descriptor; address
    /// arithmetic only, no access.
    fn contains(&self, ptr: *const core::ffi::c_void, len: usize) -> bool {
        let start = self.start.addr();
        let at = ptr.addr();
        !self.start.is_null()
            && at >= start
            && at
                .checked_add(len)
                .is_some_and(|end| end <= start.saturating_add(self.len))
    }

    /// A SID at `ptr` with at most `limit` bytes available, bounded by the
    /// end of the descriptor too; `None` when `ptr` is outside it.
    fn sid_at(&self, ptr: *const core::ffi::c_void, limit: usize) -> Option<SidRef<'_>> {
        if !self.contains(ptr, 1) {
            return None;
        }
        let available = self.start.addr().saturating_add(self.len) - ptr.addr();
        Some(SidRef {
            ptr: ptr.cast(),
            max_len: available.min(limit),
            _descriptor: std::marker::PhantomData,
        })
    }
}

impl Drop for Descriptor {
    #[expect(
        unsafe_code,
        reason = "LocalFree: the descriptor came from GetSecurityInfo, which documents LocalFree as its release, and is freed once"
    )]
    fn drop(&mut self) {
        if !self.start.is_null() {
            // SAFETY: allocated by GetSecurityInfo and released once here.
            unsafe { LocalFree(self.start) };
        }
    }
}

/// A SID inside a borrowed [`Descriptor`].
///
/// Invariant: `max_len` bytes from `ptr` lie inside the descriptor, which
/// the borrow keeps alive.
struct SidRef<'a> {
    ptr: *const u8,
    max_len: usize,
    _descriptor: std::marker::PhantomData<&'a Descriptor>,
}

impl SidRef<'_> {
    /// The SID in string form, or `None` when it does not fit its bound,
    /// is not a valid SID, or cannot be converted. The SID's own length,
    /// 8 bytes plus 4 per sub-authority, must fit the bound before any API
    /// reads it.
    #[expect(
        unsafe_code,
        reason = "reads the sub-authority count inside the bound, then IsValidSid and ConvertSidToStringSidW on a SID that fits it; the string is owned by a WideBuffer"
    )]
    fn to_text(&self) -> Option<String> {
        if self.max_len < 8 {
            return None;
        }
        // SAFETY: byte 1 (SubAuthorityCount) lies inside the bound, which
        // lies inside the live descriptor.
        let count = usize::from(unsafe { self.ptr.add(1).read() });
        if 8 + 4 * count > self.max_len {
            return None;
        }
        let sid: PSID = self.ptr.cast_mut().cast();
        // SAFETY: the whole SID lies inside the live descriptor.
        if unsafe { IsValidSid(sid) } == 0 {
            return None;
        }
        let mut text = WideBuffer::empty(Release::Local);
        // SAFETY: `sid` is valid as above; the out pointer is the buffer's
        // own field, which frees the string on drop.
        if unsafe { ConvertSidToStringSidW(sid, &raw mut text.ptr) } == 0 {
            return None;
        }
        text.to_os().and_then(|s| s.into_string().ok())
    }
}

/// Offsets inside an access-allowed or access-denied entry.
const ACE_MASK_OFFSET: usize = std::mem::offset_of!(ACCESS_ALLOWED_ACE, Mask);
const ACE_SID_OFFSET: usize = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
/// The smallest SID: revision, count and the 6-byte authority.
const MIN_SID_BYTES: usize = 8;

#[expect(
    unsafe_code,
    reason = "GetSecurityInfo, GetSecurityDescriptorLength and GetAce: the handle is borrowed open for the call; every read of the ACL and its entries is unaligned and bounded by the descriptor, which is freed with LocalFree"
)]
pub(crate) fn security(file: &File) -> io::Result<SecurityFacts> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = Descriptor {
        start: std::ptr::null_mut(),
        len: 0,
    };
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
            &raw mut descriptor.start,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if descriptor.start.is_null() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    // SAFETY: the descriptor is the valid self-relative descriptor just
    // returned; the call only reads its header.
    descriptor.len = unsafe { GetSecurityDescriptorLength(descriptor.start) } as usize;
    let owner = descriptor
        .sid_at(owner.cast_const(), usize::MAX)
        .and_then(|sid| sid.to_text());
    if dacl.is_null() {
        return Ok(SecurityFacts { owner, dacl: None });
    }
    if !descriptor.contains(dacl.cast_const().cast(), std::mem::size_of::<ACL>()) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    // SAFETY: the ACL header lies inside the live descriptor (checked);
    // the read is unaligned.
    let header = unsafe { std::ptr::read_unaligned(dacl.cast_const()) };
    let mut entries = Vec::with_capacity(usize::from(header.AceCount));
    for index in 0..u32::from(header.AceCount) {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `index` is below the ACL's own count; `ace` is a valid out
        // pointer.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if !descriptor.contains(ace.cast_const(), std::mem::size_of::<ACE_HEADER>()) {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        // SAFETY: the entry header lies inside the live descriptor; the
        // read is unaligned.
        let ace_header = unsafe { std::ptr::read_unaligned(ace.cast_const().cast::<ACE_HEADER>()) };
        let size = usize::from(ace_header.AceSize);
        let decodable = matches!(
            ace_header.AceType,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) && size >= ACE_SID_OFFSET + MIN_SID_BYTES
            && descriptor.contains(ace.cast_const(), size);
        let decoded = if decodable {
            // SAFETY: the whole entry, mask included, lies inside the live
            // descriptor (checked); the read is unaligned.
            let mask = unsafe {
                std::ptr::read_unaligned(
                    ace.cast_const()
                        .cast::<u8>()
                        .add(ACE_MASK_OFFSET)
                        .cast::<u32>(),
                )
            };
            // The SID is bounded by the entry's own size.
            // SAFETY: the offset lies inside the entry checked above.
            let sid_ptr = unsafe { ace.cast_const().cast::<u8>().add(ACE_SID_OFFSET) };
            Ace {
                ace_type: ace_header.AceType,
                flags: ace_header.AceFlags,
                mask,
                sid: descriptor
                    .sid_at(sid_ptr.cast(), size - ACE_SID_OFFSET)
                    .and_then(|sid| sid.to_text()),
            }
        } else {
            // Undecoded: other types fail closed, and an allowed entry
            // without a decodable trustee fails closed too.
            Ace {
                ace_type: ace_header.AceType,
                flags: ace_header.AceFlags,
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
