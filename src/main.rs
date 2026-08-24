use hhm_desktop_app::{AppSnapshot, AuthDisplayState, DoorProximity, ProductAccess};
use slint::{ComponentHandle, SharedString};

// Slint owns this generated implementation. Keep its internal invariant
// assertions isolated from the handwritten crate, whose strict lints remain in
// force everywhere else.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod ui_generated {
    slint::include_modules!();
}

use ui_generated::AppWindow;

fn main() -> Result<(), slint::PlatformError> {
    let _telemetry = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hhm_desktop_app=info".into()),
        )
        .try_init();

    let state = AppSnapshot::default();
    let window = AppWindow::new()?;
    window.set_auth_status(auth_label(state.auth).into());
    window.set_access_status(access_label(state.product_access).into());
    window.set_proximity_status(proximity_label(state.proximity).into());
    window.set_qr_status(SharedString::from("No backend-issued visitor QR lease"));
    window.set_presence_request_ready(state.may_request_presence_transition);
    window.run()
}

const fn auth_label(value: AuthDisplayState) -> &'static str {
    match value {
        AuthDisplayState::Anonymous => "Anonymous",
        AuthDisplayState::Unauthenticated => "Sign-in required",
        AuthDisplayState::Degraded => "Authentication unavailable",
        AuthDisplayState::Authenticated => "Authenticated",
    }
}

const fn access_label(value: ProductAccess) -> &'static str {
    match value {
        ProductAccess::Unknown => "Not yet checked",
        ProductAccess::Denied => "Denied by HHM",
        ProductAccess::Allowed => "Allowed by HHM",
    }
}

const fn proximity_label(value: DoorProximity) -> &'static str {
    match value {
        DoorProximity::Unknown => "No opt-in signal",
        DoorProximity::OutsideRange => "Outside door range",
        DoorProximity::Nearby => "Near a registered door",
    }
}
