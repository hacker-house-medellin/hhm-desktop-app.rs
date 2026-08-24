//! HHM desktop domain model, observability, and stable C ABI.
//!
//! The library does not make access-control decisions. Shared Auth proves
//! identity and assurance, HHM's backend decides product permissions, and the
//! desktop UI renders only the resulting bounded state.

pub mod auth;
pub mod domain;
pub mod ffi;
pub mod observability;

pub use domain::{AppSnapshot, AuthDisplayState, DoorProximity, ProductAccess, QrLease, QrPurpose};

/// Major/minor ABI version encoded as `major << 16 | minor`.
pub const HHM_DESKTOP_ABI_VERSION: u32 = 1 << 16;
