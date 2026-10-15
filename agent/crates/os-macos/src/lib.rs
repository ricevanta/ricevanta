//! macOS implementations of the `ricevanta-os` traits
//! (docs/specs/agent-runtime.md sections 1.1, 3.1 and 7).
//!
//! - [`MacSampler`]: `proc_pid_rusage`, `proc_pidinfo` and
//!   `mach_timebase_info` through the locked `libc`.
//! - [`MacPlatform`]: descriptor-based file protection with `openat`,
//!   `mkdirat`, `renameat` and `unlinkat` relative to checked directories.
//!
//! This is one of the two crates where `unsafe` is denied rather than
//! forbidden. Every unsafe block lives in the private `sys` module, in a
//! function annotated `#[expect(unsafe_code, reason = "...")]` with a
//! `// SAFETY:` comment; nothing raw is public. On other targets the crate
//! is empty, so the workspace builds everywhere.

#[cfg(target_os = "macos")]
mod platform;
#[cfg(target_os = "macos")]
mod sampler;
#[cfg(target_os = "macos")]
mod sys;

#[cfg(target_os = "macos")]
pub use platform::MacPlatform;
#[cfg(target_os = "macos")]
pub use sampler::MacSampler;

/// The size of `libc::rusage_info_v4` the sampler relies on (16 bytes of
/// `ri_uuid` plus 35 `uint64_t` fields); checked at compile time on macOS.
pub const RUSAGE_INFO_V4_BYTES: usize = 296;
