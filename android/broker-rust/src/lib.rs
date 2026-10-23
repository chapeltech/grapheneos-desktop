//! Privileged broker decision core, not an installed Android service.
//!
//! No allocation, platform calls, global state, unsafe code, or third-party
//! dependencies. The Kotlin adapter owns Android objects and serializes calls.
//! Caller identity, clock and environment MUST come from the OS, not the APK.
//! The adapter must reconcile on every request and perform actual WM recovery
//! when this core revokes a lease. A successful decision is not a WM result.
#![no_std]
#![forbid(unsafe_code)]

pub mod authority;
pub mod completion;
pub mod external_ui;
pub mod layout;
pub mod native_authority;
pub mod native_frame;
pub mod native_picker;
pub mod native_shell;
pub mod native_wire;
pub mod shortcuts;

pub const API_VERSION: i32 = 3;
pub const MAX_TASKS: usize = 128;
pub const CLIENT_TIMEOUT_MILLIS: i64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ResultCode {
    Applied = 0,
    Stale = 1,
    Invalid = 2,
    Unsupported = 3,
    Revoked = 4,
    Busy = 5,
    PlatformConstraint = 6,
}
