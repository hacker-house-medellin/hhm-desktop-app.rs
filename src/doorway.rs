//! Managed-doorway evidence policy over the canonical HHM wire contract.
//!
//! This module is deliberately outside the C ABI. Bluetooth is only a way to
//! observe a registered doorway challenge; it is not identity, exact human
//! location, presence authorization, or a door-unlock factor.

use std::{collections::HashSet, fmt};

use chrono::{DateTime, Utc};
pub use hhm_interfaces::{
    CorroborationEvidence, DoorwayChallenge, DoorwayDirection, DoorwayObservation,
    PresenceDecision, PresenceDecisionKind, PresenceSubmissionNonce,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoorwayVerificationOutcome {
    Verified,
    Invalid,
    Unavailable,
}

/// Implemented only by reviewed registered-key and official device-attestation
/// adapters. No permissive default exists, and native apps never hold a
/// protected-introspection service credential.
pub trait DoorwayEvidenceVerifier {
    fn verify_challenge_and_corroboration(
        &self,
        challenge: &DoorwayChallenge,
        corroboration: &CorroborationEvidence,
    ) -> DoorwayVerificationOutcome;

    fn verify_enrolled_device_observation(
        &self,
        observation: &DoorwayObservation,
    ) -> DoorwayVerificationOutcome;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopDoorwayConsent {
    allowed_door_ids: HashSet<String>,
    automatic_transitions: bool,
    background_collection_approved: bool,
}

impl DesktopDoorwayConsent {
    /// Creates an explicit local collection policy. Empty or malformed door
    /// allowlists fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`DoorwayPolicyError::ConsentDenied`] for invalid door IDs.
    pub fn try_new(
        allowed_door_ids: impl IntoIterator<Item = String>,
        automatic_transitions: bool,
        background_collection_approved: bool,
    ) -> Result<Self, DoorwayPolicyError> {
        let allowed_door_ids = allowed_door_ids.into_iter().collect::<HashSet<_>>();
        if allowed_door_ids.is_empty()
            || allowed_door_ids
                .iter()
                .any(|door_id| !valid_identifier(door_id))
        {
            return Err(DoorwayPolicyError::ConsentDenied);
        }
        Ok(Self {
            allowed_door_ids,
            automatic_transitions,
            background_collection_approved,
        })
    }

    fn permits(&self, door_id: &str, automatic: bool, application_in_foreground: bool) -> bool {
        self.allowed_door_ids.contains(door_id)
            && (!automatic || self.automatic_transitions)
            && (application_in_foreground || self.background_collection_approved)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDoorwayEvidence {
    pub challenge: DoorwayChallenge,
    pub corroboration: CorroborationEvidence,
    pub submission_nonce: PresenceSubmissionNonce,
}

pub struct DoorwayPreparationRequest<'a> {
    pub consent: &'a DesktopDoorwayConsent,
    pub challenge: &'a DoorwayChallenge,
    pub corroboration: &'a CorroborationEvidence,
    pub submission_nonce: &'a PresenceSubmissionNonce,
    pub now: DateTime<Utc>,
    pub automatic: bool,
    pub application_in_foreground: bool,
}

/// Validates local consent, closed contract shape, short time windows,
/// independent source keys, and registered-key proofs before a hardware-backed
/// signer is allowed to create a device observation.
///
/// # Errors
///
/// Fails closed on consent, shape, expiry, invalid proof, or verifier outage.
pub fn prepare_doorway_evidence(
    request: &DoorwayPreparationRequest<'_>,
    verifier: &impl DoorwayEvidenceVerifier,
) -> Result<VerifiedDoorwayEvidence, DoorwayPolicyError> {
    if !request.consent.permits(
        &request.challenge.door_id,
        request.automatic,
        request.application_in_foreground,
    ) {
        return Err(DoorwayPolicyError::ConsentDenied);
    }
    request
        .challenge
        .validate_shape(request.now)
        .map_err(|_| DoorwayPolicyError::EvidenceInvalid)?;
    request
        .corroboration
        .validate_against(request.challenge)
        .map_err(|_| DoorwayPolicyError::EvidenceInvalid)?;
    request
        .submission_nonce
        .validate_shape(request.now)
        .map_err(|_| DoorwayPolicyError::EvidenceInvalid)?;
    require_verified(
        verifier.verify_challenge_and_corroboration(request.challenge, request.corroboration),
    )?;
    Ok(VerifiedDoorwayEvidence {
        challenge: request.challenge.clone(),
        corroboration: request.corroboration.clone(),
        submission_nonce: request.submission_nonce.clone(),
    })
}

/// Checks a completed desktop observation before it is sent to the HHM API.
/// The backend repeats every check and owns the authoritative decision.
///
/// # Errors
///
/// Rejects wrong app/nonce, missing consent, invalid shape/proof, or verifier
/// unavailability.
pub fn validate_desktop_observation(
    consent: &DesktopDoorwayConsent,
    observation: &DoorwayObservation,
    expected_nonce: &PresenceSubmissionNonce,
    now: DateTime<Utc>,
    automatic: bool,
    application_in_foreground: bool,
    verifier: &impl DoorwayEvidenceVerifier,
) -> Result<(), DoorwayPolicyError> {
    observation
        .validate_shape(now)
        .map_err(|_| DoorwayPolicyError::EvidenceInvalid)?;
    if observation.app_id != hhm_interfaces::PeerApplication::HhmDesktopAppRs
        || observation.submission_nonce != expected_nonce.nonce
        || !consent.permits(
            &observation.challenge.door_id,
            automatic,
            application_in_foreground,
        )
    {
        return Err(DoorwayPolicyError::ConsentDenied);
    }
    expected_nonce
        .validate_shape(now)
        .map_err(|_| DoorwayPolicyError::EvidenceInvalid)?;
    require_verified(
        verifier
            .verify_challenge_and_corroboration(&observation.challenge, &observation.corroboration),
    )?;
    require_verified(verifier.verify_enrolled_device_observation(observation))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendPresenceOutcome {
    AcceptedTransition,
    ConfirmationRequired,
    Rejected,
}

/// Applies only a response bound to the exact submitted observation and next
/// monotonic sequence. The caller may advance local display state only for
/// [`BackendPresenceOutcome::AcceptedTransition`].
///
/// # Errors
///
/// Rejects malformed, cross-observation, cross-door, cross-policy, direction,
/// and sequence-conflicting responses.
pub fn validate_backend_decision(
    observation: &DoorwayObservation,
    decision: &PresenceDecision,
) -> Result<BackendPresenceOutcome, DoorwayPolicyError> {
    decision
        .validate_shape()
        .map_err(|_| DoorwayPolicyError::DecisionInvalid)?;
    let Some(expected_sequence) = observation.previous_presence_sequence.checked_add(1) else {
        return Err(DoorwayPolicyError::DecisionInvalid);
    };
    if decision.observation_id != observation.observation_id
        || decision.house_id != observation.challenge.house_id
        || decision.door_id != observation.challenge.door_id
        || decision.policy_version != observation.policy_version
        || decision.direction != observation.direction
        || decision.presence_sequence != expected_sequence
    {
        return Err(DoorwayPolicyError::DecisionInvalid);
    }
    Ok(match decision.decision {
        PresenceDecisionKind::Accepted => BackendPresenceOutcome::AcceptedTransition,
        PresenceDecisionKind::ConfirmationRequired => BackendPresenceOutcome::ConfirmationRequired,
        PresenceDecisionKind::Rejected => BackendPresenceOutcome::Rejected,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoorwayPolicyError {
    ConsentDenied,
    EvidenceInvalid,
    VerificationInvalid,
    VerificationUnavailable,
    DecisionInvalid,
}

impl fmt::Display for DoorwayPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConsentDenied => "managed-doorway collection consent denied",
            Self::EvidenceInvalid => "managed-doorway evidence invalid",
            Self::VerificationInvalid => "managed-doorway verification failed",
            Self::VerificationUnavailable => "managed-doorway verification unavailable",
            Self::DecisionInvalid => "backend presence decision invalid",
        })
    }
}

impl std::error::Error for DoorwayPolicyError {}

fn require_verified(outcome: DoorwayVerificationOutcome) -> Result<(), DoorwayPolicyError> {
    match outcome {
        DoorwayVerificationOutcome::Verified => Ok(()),
        DoorwayVerificationOutcome::Invalid => Err(DoorwayPolicyError::VerificationInvalid),
        DoorwayVerificationOutcome::Unavailable => Err(DoorwayPolicyError::VerificationUnavailable),
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hhm_interfaces::{DoorwayDirectionHint, PresenceDecisionReason};

    struct TestVerifier(DoorwayVerificationOutcome);

    impl DoorwayEvidenceVerifier for TestVerifier {
        fn verify_challenge_and_corroboration(
            &self,
            _challenge: &DoorwayChallenge,
            _corroboration: &CorroborationEvidence,
        ) -> DoorwayVerificationOutcome {
            self.0
        }

        fn verify_enrolled_device_observation(
            &self,
            _observation: &DoorwayObservation,
        ) -> DoorwayVerificationOutcome {
            self.0
        }
    }

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../contracts/fixtures/doorway-observation.json"
        ))
        .unwrap_or_default()
    }

    fn fixture_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-24T19:00:10Z")
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_default()
    }

    fn consent() -> DesktopDoorwayConsent {
        DesktopDoorwayConsent::try_new(["front-door".to_owned()], true, false)
            .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn canonical_fixture_prepares_only_after_valid_available_verification() {
        let fixture = fixture();
        let nonce =
            serde_json::from_value::<PresenceSubmissionNonce>(fixture["submission_nonce"].clone());
        let observation =
            serde_json::from_value::<DoorwayObservation>(fixture["observation"].clone());
        assert!(nonce.is_ok());
        assert!(observation.is_ok());
        if let (Ok(nonce), Ok(observation)) = (nonce, observation) {
            assert!(
                prepare_doorway_evidence(
                    &DoorwayPreparationRequest {
                        consent: &consent(),
                        challenge: &observation.challenge,
                        corroboration: &observation.corroboration,
                        submission_nonce: &nonce,
                        now: fixture_now(),
                        automatic: true,
                        application_in_foreground: true,
                    },
                    &TestVerifier(DoorwayVerificationOutcome::Verified),
                )
                .is_ok()
            );
            assert!(matches!(
                prepare_doorway_evidence(
                    &DoorwayPreparationRequest {
                        consent: &consent(),
                        challenge: &observation.challenge,
                        corroboration: &observation.corroboration,
                        submission_nonce: &nonce,
                        now: fixture_now(),
                        automatic: true,
                        application_in_foreground: true,
                    },
                    &TestVerifier(DoorwayVerificationOutcome::Unavailable),
                ),
                Err(DoorwayPolicyError::VerificationUnavailable)
            ));
        }
    }

    #[test]
    fn same_key_and_ambiguous_direction_never_gain_local_trust() {
        let fixture = fixture();
        let mut observation =
            serde_json::from_value::<DoorwayObservation>(fixture["observation"].clone())
                .unwrap_or_else(|_| unreachable!());
        observation.corroboration.source_key_id = observation.challenge.beacon_key_id.clone();
        assert!(observation.validate_shape(fixture_now()).is_err());

        observation.corroboration.source_key_id = "door-controller:front-1".to_owned();
        observation.challenge.direction_hint = DoorwayDirectionHint::Ambiguous;
        assert!(observation.direction_requires_confirmation());
    }

    #[test]
    fn desktop_observation_requires_desktop_app_and_exact_nonce() {
        let fixture = fixture();
        let nonce =
            serde_json::from_value::<PresenceSubmissionNonce>(fixture["submission_nonce"].clone())
                .unwrap_or_else(|_| unreachable!());
        let mut observation =
            serde_json::from_value::<DoorwayObservation>(fixture["observation"].clone())
                .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            validate_desktop_observation(
                &consent(),
                &observation,
                &nonce,
                fixture_now(),
                false,
                true,
                &TestVerifier(DoorwayVerificationOutcome::Verified),
            ),
            Err(DoorwayPolicyError::ConsentDenied)
        ));
        observation.app_id = hhm_interfaces::PeerApplication::HhmDesktopAppRs;
        assert!(
            validate_desktop_observation(
                &consent(),
                &observation,
                &nonce,
                fixture_now(),
                false,
                true,
                &TestVerifier(DoorwayVerificationOutcome::Verified),
            )
            .is_ok()
        );
        observation.submission_nonce = "x".repeat(43);
        assert!(matches!(
            validate_desktop_observation(
                &consent(),
                &observation,
                &nonce,
                fixture_now(),
                false,
                true,
                &TestVerifier(DoorwayVerificationOutcome::Verified),
            ),
            Err(DoorwayPolicyError::ConsentDenied)
        ));
    }

    #[test]
    fn only_exact_accepted_backend_decision_advances_display_state() {
        let fixture = fixture();
        let observation =
            serde_json::from_value::<DoorwayObservation>(fixture["observation"].clone())
                .unwrap_or_else(|_| unreachable!());
        let mut decision = serde_json::from_value::<PresenceDecision>(fixture["decision"].clone())
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            validate_backend_decision(&observation, &decision),
            Ok(BackendPresenceOutcome::AcceptedTransition)
        );
        decision.decision = PresenceDecisionKind::ConfirmationRequired;
        decision.reason = PresenceDecisionReason::AmbiguousDirection;
        assert_eq!(
            validate_backend_decision(&observation, &decision),
            Ok(BackendPresenceOutcome::ConfirmationRequired)
        );
        decision.presence_sequence = 99;
        assert_eq!(
            validate_backend_decision(&observation, &decision),
            Err(DoorwayPolicyError::DecisionInvalid)
        );
    }
}
