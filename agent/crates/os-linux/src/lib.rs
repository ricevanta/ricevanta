//! Linux implementations of the `ricevanta-os` traits
//! (docs/specs/agent-runtime.md sections 3.1, 5.2 and 7).
//!
//! - [`LinuxSampler`]: `/proc/self` readers with fixed-size buffers.
//! - [`SystemdNotifier`]: the `sd_notify` datagram protocol over
//!   `std::os::unix::net`, without `libsystemd`.
//! - [`LinuxPlatform`]: descriptor-based file protection.
//!
//! The crate uses the standard library plus the `libc` constants
//! `O_NOFOLLOW`, `O_CLOEXEC`, `O_DIRECTORY` and `O_NONBLOCK`; it makes no
//! `libc` call and inherits the workspace `forbid(unsafe_code)`. On other
//! targets it is empty, so the workspace builds everywhere.

#[cfg(target_os = "linux")]
mod fd_count;
#[cfg(target_os = "linux")]
mod notify;
#[cfg(target_os = "linux")]
mod platform;
#[cfg(target_os = "linux")]
pub mod procfs;
#[cfg(target_os = "linux")]
mod sampler;

#[cfg(target_os = "linux")]
pub use notify::SystemdNotifier;
#[cfg(target_os = "linux")]
pub use platform::LinuxPlatform;
#[cfg(target_os = "linux")]
pub use sampler::LinuxSampler;
