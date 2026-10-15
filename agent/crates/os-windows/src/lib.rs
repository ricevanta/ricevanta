//! Windows implementations of the `ricevanta-os` traits
//! (docs/specs/agent-runtime.md sections 1.1, 3.1 and 7).
//!
//! - [`WindowsSampler`]: process memory counters, times, handle count and
//!   thread count through the locked `windows-sys`.
//! - [`WindowsPlatform`]: the `FOLDERID_ProgramData` data root and, in
//!   `service` mode, the owner and DACL rule of spec section 3.1 checked with
//!   `GetSecurityInfo` on opened handles, with reparse points refused.
//!
//! This is one of the two crates where `unsafe` is denied rather than
//! forbidden. Every unsafe block lives in the private `sys` module, in a
//! function annotated `#[expect(unsafe_code, reason = "...")]` with a
//! `// SAFETY:` comment; nothing raw is public. The rule evaluator
//! ([`dacl`]) and the sampler conversions ([`convert`]) are pure and build
//! on every host; the rest exists on Windows only.

pub mod convert;
pub mod dacl;

#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod sampler;
#[cfg(windows)]
mod sys;

#[cfg(windows)]
pub use platform::WindowsPlatform;
#[cfg(windows)]
pub use sampler::{WindowsSampler, private_usage_bytes};
