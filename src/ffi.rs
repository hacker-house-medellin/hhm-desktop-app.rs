//! Stable C ABI for Dart FFI and alternative desktop UI skins.
//!
//! Inputs use integers rather than Rust enums so an unknown value is rejected
//! instead of becoming undefined behavior. Every function that can execute
//! application code contains unwinding; panics never cross the ABI boundary.

use std::{
    ffi::{CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::Mutex,
};

use crate::{
    HHM_DESKTOP_ABI_VERSION,
    domain::{AppSnapshot, AuthDisplayState, DoorProximity, ProductAccess, QrLease, QrPurpose},
    observability::Observability,
};

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HhmDesktopStatus {
    Ok = 0,
    NullPointer = 1,
    InvalidValue = 2,
    LockFailed = 3,
    SerializationFailed = 4,
    PanicContained = 255,
}

pub struct HhmDesktopHandle {
    state: Mutex<AppSnapshot>,
    observability: Observability,
}

impl HhmDesktopHandle {
    fn new() -> Self {
        Self {
            state: Mutex::new(AppSnapshot::default()),
            observability: Observability::new(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hhm_desktop_abi_version() -> u32 {
    HHM_DESKTOP_ABI_VERSION
}

/// Returns the static NUL-terminated canonical P2P protocol identifier.
///
/// The pointer remains valid for the life of the process and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn hhm_desktop_p2p_protocol_version() -> *const c_char {
    c"hhm.p2p.v1".as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn hhm_desktop_handle_new() -> *mut HhmDesktopHandle {
    catch_unwind(AssertUnwindSafe(|| {
        Box::into_raw(Box::new(HhmDesktopHandle::new()))
    }))
    .unwrap_or(ptr::null_mut())
}

/// Releases a handle returned by [`hhm_desktop_handle_new`].
///
/// # Safety
///
/// `handle` must be null or a live pointer returned by this library. A live
/// handle must be released exactly once and must not be used concurrently while
/// this function runs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hhm_desktop_handle_free(handle: *mut HhmDesktopHandle) {
    if handle.is_null() {
        return;
    }
    let _contained = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: upheld by the caller contract above.
        drop(unsafe { Box::from_raw(handle) });
    }));
}

/// Updates the display-only authentication outcome.
///
/// Accepted values are 0 anonymous, 1 unauthenticated, 2 degraded, and 3
/// authenticated. This state is never itself an authorization grant.
///
/// # Safety
///
/// `handle` must be a live pointer returned by this library for the duration of
/// the call, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hhm_desktop_set_auth_state(
    handle: *mut HhmDesktopHandle,
    value: i32,
) -> HhmDesktopStatus {
    let Some(value) = auth_state(value) else {
        return HhmDesktopStatus::InvalidValue;
    };
    // SAFETY: forwarded caller contract; `mutate` performs the null check.
    unsafe {
        mutate(handle, "auth", auth_label(value), |state| {
            state.set_auth(value);
        })
    }
}

/// Updates the product-authorization outcome returned by HHM's backend.
///
/// Accepted values are 0 unknown, 1 denied, and 2 allowed.
///
/// # Safety
///
/// `handle` must be a live pointer returned by this library for the duration of
/// the call, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hhm_desktop_set_product_access(
    handle: *mut HhmDesktopHandle,
    value: i32,
) -> HhmDesktopStatus {
    let Some(value) = product_access(value) else {
        return HhmDesktopStatus::InvalidValue;
    };
    // SAFETY: forwarded caller contract; `mutate` performs the null check.
    unsafe {
        mutate(handle, "product_access", access_label(value), |state| {
            state.set_product_access(value);
        })
    }
}

/// Updates the opt-in proximity hint.
///
/// Accepted values are 0 unknown, 1 outside range, and 2 nearby. Proximity is
/// never accepted as identity proof or as evidence that a door transition
/// completed.
///
/// # Safety
///
/// `handle` must be a live pointer returned by this library for the duration of
/// the call, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hhm_desktop_set_proximity(
    handle: *mut HhmDesktopHandle,
    value: i32,
) -> HhmDesktopStatus {
    let Some(value) = proximity(value) else {
        return HhmDesktopStatus::InvalidValue;
    };
    // SAFETY: forwarded caller contract; `mutate` performs the null check.
    unsafe {
        mutate(handle, "proximity", proximity_label(value), |state| {
            state.set_proximity(value);
        })
    }
}

/// Updates the safe metadata for a backend-issued rotating visitor QR lease.
///
/// `active` is 0 to clear or 1 to set. When set, `purpose` is 0 for sign-in or
/// 1 for sign-out and `seconds_remaining` must be in 1..=60. The opaque QR
/// payload is intentionally not accepted by this state/telemetry ABI.
///
/// # Safety
///
/// `handle` must be a live pointer returned by this library for the duration of
/// the call, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hhm_desktop_set_qr_lease(
    handle: *mut HhmDesktopHandle,
    active: i32,
    purpose: i32,
    seconds_remaining: u16,
) -> HhmDesktopStatus {
    let lease = match active {
        0 => None,
        1 => {
            let Some(purpose) = qr_purpose(purpose) else {
                return HhmDesktopStatus::InvalidValue;
            };
            let Some(lease) = QrLease::new(purpose, seconds_remaining) else {
                return HhmDesktopStatus::InvalidValue;
            };
            Some(lease)
        }
        _ => return HhmDesktopStatus::InvalidValue,
    };
    let outcome = lease.map_or("cleared", |_| "active");
    // SAFETY: forwarded caller contract; `mutate` performs the null check.
    unsafe {
        mutate(handle, "qr_lease", outcome, |state| {
            state.set_qr_lease(lease);
        })
    }
}

/// Serializes a display-only state snapshot as UTF-8 JSON.
///
/// On success, `out_json` receives an allocated NUL-terminated string that must
/// be released with [`hhm_desktop_string_free`].
///
/// # Safety
///
/// `handle` must be a live pointer returned by this library for the duration of
/// the call, or null. `out_json` must be null or point to writable storage for
/// one `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hhm_desktop_snapshot_json(
    handle: *const HhmDesktopHandle,
    out_json: *mut *mut c_char,
) -> HhmDesktopStatus {
    if out_json.is_null() {
        return HhmDesktopStatus::NullPointer;
    }
    // SAFETY: `out_json` was checked and its writable storage is guaranteed by
    // the caller contract.
    unsafe { out_json.write(ptr::null_mut()) };

    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller guarantees provenance/liveness; null is handled.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return HhmDesktopStatus::NullPointer;
        };
        let snapshot = match handle.state.lock() {
            Ok(state) => state.clone(),
            Err(_) => return HhmDesktopStatus::LockFailed,
        };
        let Ok(json) = serde_json::to_string(&snapshot) else {
            return HhmDesktopStatus::SerializationFailed;
        };
        let Ok(json) = CString::new(json) else {
            return HhmDesktopStatus::SerializationFailed;
        };
        // SAFETY: `out_json` points to writable pointer storage by contract.
        unsafe { out_json.write(json.into_raw()) };
        HhmDesktopStatus::Ok
    }))
    .unwrap_or(HhmDesktopStatus::PanicContained)
}

/// Releases a string returned by [`hhm_desktop_snapshot_json`].
///
/// # Safety
///
/// `value` must be null or a live pointer returned through `out_json` by this
/// library. Each live string must be released exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hhm_desktop_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    let _contained = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: upheld by the caller contract above.
        drop(unsafe { CString::from_raw(value) });
    }));
}

unsafe fn mutate(
    handle: *mut HhmDesktopHandle,
    category: &'static str,
    outcome: &'static str,
    operation: impl FnOnce(&mut AppSnapshot),
) -> HhmDesktopStatus {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller guarantees provenance/liveness; null is handled.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return HhmDesktopStatus::NullPointer;
        };
        let Ok(mut state) = handle.state.lock() else {
            return HhmDesktopStatus::LockFailed;
        };
        operation(&mut state);
        drop(state);
        handle.observability.state_transition(category, outcome);
        HhmDesktopStatus::Ok
    }))
    .unwrap_or(HhmDesktopStatus::PanicContained)
}

const fn auth_state(value: i32) -> Option<AuthDisplayState> {
    match value {
        0 => Some(AuthDisplayState::Anonymous),
        1 => Some(AuthDisplayState::Unauthenticated),
        2 => Some(AuthDisplayState::Degraded),
        3 => Some(AuthDisplayState::Authenticated),
        _ => None,
    }
}

const fn product_access(value: i32) -> Option<ProductAccess> {
    match value {
        0 => Some(ProductAccess::Unknown),
        1 => Some(ProductAccess::Denied),
        2 => Some(ProductAccess::Allowed),
        _ => None,
    }
}

const fn proximity(value: i32) -> Option<DoorProximity> {
    match value {
        0 => Some(DoorProximity::Unknown),
        1 => Some(DoorProximity::OutsideRange),
        2 => Some(DoorProximity::Nearby),
        _ => None,
    }
}

const fn qr_purpose(value: i32) -> Option<QrPurpose> {
    match value {
        0 => Some(QrPurpose::VisitorSignIn),
        1 => Some(QrPurpose::VisitorSignOut),
        _ => None,
    }
}

const fn auth_label(value: AuthDisplayState) -> &'static str {
    match value {
        AuthDisplayState::Anonymous => "anonymous",
        AuthDisplayState::Unauthenticated => "unauthenticated",
        AuthDisplayState::Degraded => "degraded",
        AuthDisplayState::Authenticated => "authenticated",
    }
}

const fn access_label(value: ProductAccess) -> &'static str {
    match value {
        ProductAccess::Unknown => "unknown",
        ProductAccess::Denied => "denied",
        ProductAccess::Allowed => "allowed",
    }
}

const fn proximity_label(value: DoorProximity) -> &'static str {
    match value {
        DoorProximity::Unknown => "unknown",
        DoorProximity::OutsideRange => "outside_range",
        DoorProximity::Nearby => "nearby",
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn opaque_handle_is_safe_to_share_behind_the_ffi_lifetime_contract() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HhmDesktopHandle>();
    }

    #[test]
    fn ffi_rejects_unknown_values_and_never_authorizes_on_proximity_alone() {
        let handle = hhm_desktop_handle_new();
        assert!(!handle.is_null());

        // SAFETY: the handle comes from this library and is freed once below.
        unsafe {
            assert_eq!(
                hhm_desktop_set_auth_state(handle, 99),
                HhmDesktopStatus::InvalidValue
            );
            assert_eq!(hhm_desktop_set_proximity(handle, 2), HhmDesktopStatus::Ok);

            let mut json = ptr::null_mut();
            assert_eq!(
                hhm_desktop_snapshot_json(handle, &raw mut json),
                HhmDesktopStatus::Ok
            );
            assert!(!json.is_null());
            let snapshot = CStr::from_ptr(json).to_string_lossy().into_owned();
            assert!(snapshot.contains("\"may_request_presence_transition\":false"));
            hhm_desktop_string_free(json);
            hhm_desktop_handle_free(handle);
        }
    }

    #[test]
    fn null_pointers_fail_closed() {
        // SAFETY: null is explicitly supported by the ABI contract.
        unsafe {
            assert_eq!(
                hhm_desktop_set_auth_state(ptr::null_mut(), 3),
                HhmDesktopStatus::NullPointer
            );
            assert_eq!(
                hhm_desktop_snapshot_json(ptr::null(), ptr::null_mut()),
                HhmDesktopStatus::NullPointer
            );
            hhm_desktop_handle_free(ptr::null_mut());
            hhm_desktop_string_free(ptr::null_mut());
        }
    }
}
