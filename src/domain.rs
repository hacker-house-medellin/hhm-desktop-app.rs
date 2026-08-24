//! UI-independent application state.
//!
//! This module deliberately contains no bearer tokens, cookies, QR payloads,
//! raw beacon identifiers, names, email addresses, or provider subjects.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthDisplayState {
    #[default]
    Anonymous,
    Unauthenticated,
    Degraded,
    Authenticated,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductAccess {
    #[default]
    Unknown,
    Denied,
    Allowed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoorProximity {
    #[default]
    Unknown,
    OutsideRange,
    Nearby,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QrPurpose {
    VisitorSignIn,
    VisitorSignOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QrLease {
    pub purpose: QrPurpose,
    pub seconds_remaining: u16,
}

impl QrLease {
    #[must_use]
    pub const fn new(purpose: QrPurpose, seconds_remaining: u16) -> Option<Self> {
        if seconds_remaining == 0 || seconds_remaining > 60 {
            return None;
        }
        Some(Self {
            purpose,
            seconds_remaining,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppSnapshot {
    pub auth: AuthDisplayState,
    pub product_access: ProductAccess,
    pub proximity: DoorProximity,
    pub qr_lease: Option<QrLease>,
    /// This permits the client to request a transition from the backend. It is
    /// never proof that the transition is authorized or completed.
    pub may_request_presence_transition: bool,
}

impl Default for AppSnapshot {
    fn default() -> Self {
        Self {
            auth: AuthDisplayState::Anonymous,
            product_access: ProductAccess::Unknown,
            proximity: DoorProximity::Unknown,
            qr_lease: None,
            may_request_presence_transition: false,
        }
    }
}

impl AppSnapshot {
    pub fn set_auth(&mut self, auth: AuthDisplayState) {
        self.auth = auth;
        self.recompute_request_hint();
    }

    pub fn set_product_access(&mut self, product_access: ProductAccess) {
        self.product_access = product_access;
        self.recompute_request_hint();
    }

    pub fn set_proximity(&mut self, proximity: DoorProximity) {
        self.proximity = proximity;
        self.recompute_request_hint();
    }

    pub fn set_qr_lease(&mut self, qr_lease: Option<QrLease>) {
        self.qr_lease = qr_lease;
    }

    fn recompute_request_hint(&mut self) {
        self.may_request_presence_transition = self.auth == AuthDisplayState::Authenticated
            && self.product_access == ProductAccess::Allowed
            && self.proximity == DoorProximity::Nearby;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proximity_never_bypasses_identity_or_product_authority() {
        let mut state = AppSnapshot::default();
        state.set_proximity(DoorProximity::Nearby);
        assert!(!state.may_request_presence_transition);

        state.set_auth(AuthDisplayState::Authenticated);
        assert!(!state.may_request_presence_transition);

        state.set_product_access(ProductAccess::Allowed);
        assert!(state.may_request_presence_transition);

        state.set_auth(AuthDisplayState::Degraded);
        assert!(!state.may_request_presence_transition);
    }

    #[test]
    fn qr_lease_is_bounded_to_one_minute() {
        assert_eq!(QrLease::new(QrPurpose::VisitorSignIn, 0), None);
        assert!(QrLease::new(QrPurpose::VisitorSignIn, 60).is_some());
        assert_eq!(QrLease::new(QrPurpose::VisitorSignOut, 61), None);
    }

    #[test]
    fn serialized_snapshot_contains_no_identity_or_credential_fields() {
        let json = serde_json::to_string(&AppSnapshot::default()).unwrap_or_default();
        for forbidden in [
            "token",
            "cookie",
            "email",
            "subject",
            "beacon_id",
            "qr_payload",
        ] {
            assert!(!json.contains(forbidden), "unexpected field: {forbidden}");
        }
    }
}
