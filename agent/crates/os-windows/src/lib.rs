//! Windows implementations of the `ricevanta-os` traits
//! (docs/specs/agent-runtime.md sections 1.1, 3.1 and 7).
//!
//! - [`WindowsSampler`]: process memory counters, times, handle count and
//!   thread count through the locked `windows-sys`.
//! - [`WindowsPlatform`]: the `FOLDERID_ProgramData` data root and, in
//!   `service` mode, the owner and DACL rule of spec section 3.1 checked with
//!   `GetSecurityInfo` on opened handles, with reparse points refused.
//! - `dispatch`: the Service Control Manager dispatcher, control handler
//!   and status reporter of spec section 5.4, over the portable status
//!   sequence in [`scm`].
//! - `EventLog`: the Application event log writer of spec section 6 for
//!   lines written before the log file opens ([`eventlog`]).
//!
//! This is one of the two crates where `unsafe` is denied rather than
//! forbidden. Every unsafe block lives in the private `sys` and `service`
//! modules, in a function annotated `#[expect(unsafe_code, reason = "...")]` with a
//! `// SAFETY:` comment; nothing raw is public. The rule evaluator
//! ([`dacl`]), the sampler conversions ([`convert`]), the service status
//! sequence ([`scm`]) and the event log line rules ([`eventlog`]) are pure
//! and build and test on every host; the rest exists on Windows only.

pub mod convert;
pub mod dacl;
pub mod eventlog;
pub mod scm;

#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod sampler;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod sys;

#[cfg(windows)]
pub use platform::WindowsPlatform;
#[cfg(windows)]
pub use sampler::{WindowsSampler, private_usage_bytes};
#[cfg(windows)]
pub use service::{DispatchError, EventLog, ServiceBody, dispatch};
