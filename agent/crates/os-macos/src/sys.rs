//! The only `unsafe` code of this crate: private wrappers over the locked
//! `libc` declarations named in the licensing row. Each function carries
//! `#[expect(unsafe_code, reason = "...")]` and a `// SAFETY:` comment for
//! every unsafe block (spec section 1.1). No pointer, descriptor or `extern`
//! item leaves this module except as an owned `File` or plain values.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) use crate::RUSAGE_INFO_V4_BYTES;
const _: () = assert!(std::mem::size_of::<libc::rusage_info_v4>() == RUSAGE_INFO_V4_BYTES);

/// Descriptor entries read per sample: a fixed 4 KiB stack buffer.
pub(crate) const FD_ENTRIES: usize = 4096 / std::mem::size_of::<libc::proc_fdinfo>();

fn result(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[expect(
    unsafe_code,
    reason = "openat: `dir` is a live descriptor and `name` a NUL-terminated string, both borrowed for the call; the returned descriptor is new and owned once"
)]
pub(crate) fn openat(dir: &File, name: &CStr, flags: libc::c_int, mode: u16) -> io::Result<File> {
    // SAFETY: `dir.as_raw_fd()` is open for the whole call because `dir` is
    // borrowed; `name.as_ptr()` points to a NUL-terminated buffer that
    // outlives the call; the variadic mode is passed as `c_uint`, the
    // promoted type of `mode_t`, and is ignored without `O_CREAT`.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `openat`, is valid, and no other
    // owner exists, so `OwnedFd` may take sole ownership and close it once.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

#[expect(
    unsafe_code,
    reason = "mkdirat: `dir` is a live descriptor and `name` a NUL-terminated string, both borrowed for the call"
)]
pub(crate) fn mkdirat(dir: &File, name: &CStr, mode: u16) -> io::Result<()> {
    // SAFETY: both pointers and the descriptor stay valid for the call;
    // `mode` is a plain `mode_t` value.
    result(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) })
}

#[expect(
    unsafe_code,
    reason = "renameat: one live directory descriptor and two NUL-terminated names, all borrowed for the call"
)]
pub(crate) fn renameat(dir: &File, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: the descriptor and both NUL-terminated buffers stay valid for
    // the call; the same directory is source and target.
    result(unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) })
}

#[expect(
    unsafe_code,
    reason = "unlinkat: a live directory descriptor and a NUL-terminated name, both borrowed for the call"
)]
pub(crate) fn unlinkat(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: the descriptor and the NUL-terminated buffer stay valid for
    // the call; flag 0 removes a non-directory entry only.
    result(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) })
}

#[expect(
    unsafe_code,
    reason = "proc_pid_rusage: the buffer is a stack rusage_info_v4 of the size RUSAGE_INFO_V4 writes, read only after success"
)]
pub(crate) fn rusage_v4(pid: i32) -> io::Result<libc::rusage_info_v4> {
    let mut info = MaybeUninit::<libc::rusage_info_v4>::zeroed();
    // SAFETY: `info` is a properly aligned `rusage_info_v4` (296 bytes,
    // checked at compile time), the size the kernel writes for flavor
    // `RUSAGE_INFO_V4`; the out pointer type is the `rusage_info_t *` the
    // declaration takes.
    let code = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    };
    result(code)?;
    // SAFETY: the buffer was zero-initialised, every bit pattern is a valid
    // `rusage_info_v4` (integers only), and the call succeeded.
    Ok(unsafe { info.assume_init() })
}

#[expect(
    unsafe_code,
    reason = "proc_pidinfo(PROC_PIDTASKINFO): the buffer is a stack proc_taskinfo whose exact size is passed, read only after the full size was written"
)]
pub(crate) fn task_info(pid: i32) -> io::Result<libc::proc_taskinfo> {
    let mut info = MaybeUninit::<libc::proc_taskinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_taskinfo>();
    let size_c =
        libc::c_int::try_from(size).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the pointer and length describe the `info` buffer exactly.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast::<libc::c_void>(),
            size_c,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(written).ok() != Some(size) {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    // SAFETY: the zeroed buffer holds integers only and was fully written.
    Ok(unsafe { info.assume_init() })
}

#[expect(
    unsafe_code,
    reason = "proc_pidinfo(PROC_PIDLISTFDS): the buffer is a fixed stack array whose byte length is passed; only the returned byte count is used"
)]
pub(crate) fn listed_fd_bytes(pid: i32) -> io::Result<usize> {
    let mut entries = [libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    }; FD_ENTRIES];
    let bytes = std::mem::size_of_val(&entries);
    let bytes_c =
        libc::c_int::try_from(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the pointer and length describe `entries` exactly; the kernel
    // writes at most `bytes` bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast::<libc::c_void>(),
            bytes_c,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    let written =
        usize::try_from(written).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if written == 0 {
        // proc_pidinfo reports failure as 0 with errno set.
        return Err(io::Error::last_os_error());
    }
    if written >= bytes {
        // The fixed buffer is full: the count could be cut, so report no
        // count rather than a wrong one.
        return Err(io::Error::from(io::ErrorKind::OutOfMemory));
    }
    Ok(written)
}

#[expect(
    unsafe_code,
    reason = "mach_timebase_info: the out pointer is a stack mach_timebase_info read only after success"
)]
#[expect(
    deprecated,
    reason = "libc marks mach_timebase_info deprecated in favour of the mach2 crate, which is not a licensed dependency; the spec names this declaration"
)]
pub(crate) fn timebase() -> io::Result<(u32, u32)> {
    let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
    // SAFETY: `info` is a valid, aligned `mach_timebase_info` for the call.
    let code = unsafe { libc::mach_timebase_info(&raw mut info) };
    if code != 0 || info.denom == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok((info.numer, info.denom))
}
