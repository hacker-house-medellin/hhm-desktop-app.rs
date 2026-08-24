//! Desktop policy over the canonical HHM peer-session wire contract.
//!
//! `hhm-interfaces` owns the wire types. BLE is transport evidence only. This
//! module adds explicit peer consent, fail-closed device/Shared Auth adapter
//! boundaries, replay and rate controls, and stricter desktop limits. It does
//! not implement authentication, cryptography, code loading, or installation.

use std::{collections::VecDeque, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
pub use hhm_interfaces::{
    PEER_PROTOCOL_VERSION, PeerApplication, PeerCapability, PeerDecision, PeerEncryptedEnvelope,
    PeerHandshakeRequest, PeerHandshakeResponse, PeerPayloadType, PeerPlatform, ReleaseChannel,
    SignedUpdateManifest,
};
use url::Url;
use uuid::Uuid;

pub const HHM_DESKTOP_P2P_PROTOCOL_VERSION: &str = PEER_PROTOCOL_VERSION;
pub const HHM_INTERFACES_P2P_REVISION: &str = "f694bc9b58907db918f0449b5d04a5763f8fa745";
pub const MAX_ENVELOPE_CIPHERTEXT_BYTES: usize = 32 * 1024;
pub const MAX_MESSAGES_PER_MINUTE: u16 = 30;
pub const MAX_BYTES_PER_MINUTE: usize = 256 * 1024;

const MAX_CONSENT_TTL_SECONDS: i64 = 5 * 60;
const MAX_SESSION_TTL_SECONDS: i64 = 15 * 60;
const MAX_ENVELOPE_TTL_SECONDS: i64 = 60;
const MAX_REMEMBERED_REPLAY_VALUES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Verified,
    Invalid,
    Unavailable,
}

/// Authority implemented only by the reviewed device-bound Shared Auth and
/// project release-key adapters. There is intentionally no permissive default.
pub trait PeerCryptoVerifier {
    fn verify_handshake(
        &self,
        request: &PeerHandshakeRequest,
        response: &PeerHandshakeResponse,
    ) -> VerificationOutcome;

    fn verify_and_authenticate_envelope(
        &self,
        envelope: &PeerEncryptedEnvelope,
    ) -> VerificationOutcome;

    fn verify_update_manifest(&self, manifest: &SignedUpdateManifest) -> VerificationOutcome;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerSelection {
    peer_device_key_id: String,
    consent_expires_at: DateTime<Utc>,
}

impl PeerSelection {
    /// Records explicit, expiring local consent for one user-selected peer.
    ///
    /// # Errors
    ///
    /// Rejects malformed key identifiers and consent outside 1–300 seconds.
    pub fn try_new(
        peer_device_key_id: &str,
        now: DateTime<Utc>,
        consent_ttl_seconds: i64,
    ) -> Result<Self, P2pPolicyError> {
        if !valid_key_id(peer_device_key_id) {
            return Err(P2pPolicyError::InvalidPeerKey);
        }
        if !(1..=MAX_CONSENT_TTL_SECONDS).contains(&consent_ttl_seconds) {
            return Err(P2pPolicyError::InvalidConsentWindow);
        }
        let Some(consent_expires_at) =
            now.checked_add_signed(Duration::seconds(consent_ttl_seconds))
        else {
            return Err(P2pPolicyError::InvalidConsentWindow);
        };
        Ok(Self {
            peer_device_key_id: peer_device_key_id.to_owned(),
            consent_expires_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedEnvelope {
    pub payload_type: PeerPayloadType,
    pub sequence: u32,
    pub ciphertext_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdateMetadata {
    pub version: String,
    pub anti_rollback_counter: u64,
    pub artifact_size: u64,
    pub artifact_sha256: String,
    pub artifact_url: String,
}

pub struct PeerSessionGuard {
    peer_device_key_id: String,
    session_id: Uuid,
    selected_capabilities: Vec<PeerCapability>,
    expires_at: DateTime<Utc>,
    last_sequence: Option<u32>,
    seen_nonces: VecDeque<String>,
    seen_message_ids: VecDeque<Uuid>,
    rate_window_started_at: DateTime<Utc>,
    messages_in_window: u16,
    bytes_in_window: usize,
}

impl PeerSessionGuard {
    /// Establishes local policy state for a canonical accepted handshake only
    /// after explicit peer selection and official adapter verification.
    ///
    /// # Errors
    ///
    /// Fails closed on malformed/mismatched transcripts, expired consent,
    /// missing capability consent, invalid local binding, invalid crypto, or an
    /// unavailable verification authority.
    pub fn establish(
        selection: &PeerSelection,
        expected_local_device_key_id: &str,
        request: &PeerHandshakeRequest,
        response: &PeerHandshakeResponse,
        now: DateTime<Utc>,
        session_ttl_seconds: i64,
        verifier: &impl PeerCryptoVerifier,
    ) -> Result<Self, P2pPolicyError> {
        request
            .validate_shape(now)
            .map_err(|_| P2pPolicyError::InvalidHandshakeShape)?;
        response
            .validate_shape(now)
            .map_err(|_| P2pPolicyError::InvalidHandshakeShape)?;
        if selection.consent_expires_at <= now {
            return Err(P2pPolicyError::ConsentExpired);
        }
        if selection.peer_device_key_id != request.device_key_id {
            return Err(P2pPolicyError::PeerNotSelected);
        }
        if !valid_key_id(expected_local_device_key_id)
            || response.device_key_id.as_deref() != Some(expected_local_device_key_id)
        {
            return Err(P2pPolicyError::InvalidLocalKey);
        }
        if response.decision != PeerDecision::Accepted
            || request.protocol_version != response.protocol_version
            || request.session_id != response.session_id
            || request.offer_id != response.offer_id
            || response.selected_capabilities.is_empty()
            || !response
                .selected_capabilities
                .iter()
                .all(|capability| request.requested_capabilities.contains(capability))
        {
            return Err(P2pPolicyError::HandshakeMismatch);
        }
        if !(1..=MAX_SESSION_TTL_SECONDS).contains(&session_ttl_seconds) {
            return Err(P2pPolicyError::InvalidSessionWindow);
        }
        let Some(expires_at) = now.checked_add_signed(Duration::seconds(session_ttl_seconds))
        else {
            return Err(P2pPolicyError::InvalidSessionWindow);
        };
        require_verified(verifier.verify_handshake(request, response))?;

        Ok(Self {
            peer_device_key_id: request.device_key_id.clone(),
            session_id: request.session_id,
            selected_capabilities: response.selected_capabilities.clone(),
            expires_at,
            last_sequence: None,
            seen_nonces: VecDeque::with_capacity(MAX_REMEMBERED_REPLAY_VALUES),
            seen_message_ids: VecDeque::with_capacity(MAX_REMEMBERED_REPLAY_VALUES),
            rate_window_started_at: now,
            messages_in_window: 0,
            bytes_in_window: 0,
        })
    }

    /// Applies canonical shape validation plus the stricter desktop policy to
    /// one encrypted allowlisted envelope.
    ///
    /// # Errors
    ///
    /// Fails closed on session/capability mismatch, expiry, replay, excessive
    /// size/rate, invalid authentication, or unavailable verification.
    pub fn accept_envelope(
        &mut self,
        envelope: &PeerEncryptedEnvelope,
        now: DateTime<Utc>,
        verifier: &impl PeerCryptoVerifier,
    ) -> Result<AcceptedEnvelope, P2pPolicyError> {
        if now >= self.expires_at {
            return Err(P2pPolicyError::SessionExpired);
        }
        envelope
            .validate_shape(now)
            .map_err(|_| P2pPolicyError::InvalidEnvelopeShape)?;
        if envelope.session_id != self.session_id
            || envelope.sender_key_id != self.peer_device_key_id
        {
            return Err(P2pPolicyError::SessionMismatch);
        }
        if !self.allows_payload(envelope.payload_type) {
            return Err(P2pPolicyError::CapabilityDenied);
        }
        if envelope.expires_at > self.expires_at
            || envelope.expires_at - envelope.created_at
                > Duration::seconds(MAX_ENVELOPE_TTL_SECONDS)
        {
            return Err(P2pPolicyError::EnvelopeExpired);
        }
        if self
            .last_sequence
            .is_some_and(|sequence| envelope.sequence <= sequence)
            || self.seen_nonces.contains(&envelope.nonce)
            || self.seen_message_ids.contains(&envelope.message_id)
        {
            return Err(P2pPolicyError::ReplayDetected);
        }
        let ciphertext_bytes = decoded_len(&envelope.ciphertext)?;

        let reset_window = now
            .signed_duration_since(self.rate_window_started_at)
            .num_seconds()
            >= 60;
        let (messages, bytes) = if reset_window {
            (1, ciphertext_bytes)
        } else {
            (
                self.messages_in_window.saturating_add(1),
                self.bytes_in_window.saturating_add(ciphertext_bytes),
            )
        };
        if messages > MAX_MESSAGES_PER_MINUTE || bytes > MAX_BYTES_PER_MINUTE {
            return Err(P2pPolicyError::RateLimited);
        }
        require_verified(verifier.verify_and_authenticate_envelope(envelope))?;

        if reset_window {
            self.rate_window_started_at = now;
        }
        self.messages_in_window = messages;
        self.bytes_in_window = bytes;
        self.last_sequence = Some(envelope.sequence);
        remember(&mut self.seen_nonces, envelope.nonce.clone());
        remember(&mut self.seen_message_ids, envelope.message_id);

        Ok(AcceptedEnvelope {
            payload_type: envelope.payload_type,
            sequence: envelope.sequence,
            ciphertext_bytes,
        })
    }

    fn allows_payload(&self, payload_type: PeerPayloadType) -> bool {
        let capability = match payload_type {
            PeerPayloadType::ResidentMessage => Some(PeerCapability::ResidentMessage),
            PeerPayloadType::ContactCard => Some(PeerCapability::ContactCard),
            PeerPayloadType::FileManifest => Some(PeerCapability::FileManifest),
            PeerPayloadType::UpdateManifest => Some(PeerCapability::UpdateManifest),
            PeerPayloadType::Receipt => None,
        };
        capability.is_none_or(|value| self.selected_capabilities.contains(&value))
    }
}

/// Verifies canonical peer-discovered update metadata. An accepted result is
/// metadata only; this module never downloads, loads, or installs an artifact.
///
/// # Errors
///
/// Rejects wrong app/platform/channel/key/origin, rollback, invalid shape or
/// signature, and unavailable verification authority.
pub fn consider_update_manifest(
    manifest: &SignedUpdateManifest,
    expected_platform: PeerPlatform,
    expected_channel: ReleaseChannel,
    pinned_release_key_id: &str,
    installed_anti_rollback_counter: u64,
    official_release_origin: &str,
    verifier: &impl PeerCryptoVerifier,
) -> Result<VerifiedUpdateMetadata, P2pPolicyError> {
    manifest
        .validate_shape()
        .map_err(|_| P2pPolicyError::InvalidReleaseMetadata)?;
    if manifest.app_id != PeerApplication::HhmDesktopAppRs {
        return Err(P2pPolicyError::WrongApplication);
    }
    if manifest.platform != expected_platform {
        return Err(P2pPolicyError::WrongPlatform);
    }
    if manifest.channel != expected_channel {
        return Err(P2pPolicyError::WrongChannel);
    }
    if !valid_key_id(pinned_release_key_id) || manifest.signing_key_id != pinned_release_key_id {
        return Err(P2pPolicyError::WrongReleaseKey);
    }
    if manifest.anti_rollback_counter <= installed_anti_rollback_counter {
        return Err(P2pPolicyError::RollbackRejected);
    }
    validate_official_origin(&manifest.artifact_url, official_release_origin)?;
    require_verified(verifier.verify_update_manifest(manifest))?;

    Ok(VerifiedUpdateMetadata {
        version: manifest.version.clone(),
        anti_rollback_counter: manifest.anti_rollback_counter,
        artifact_size: manifest.artifact_size,
        artifact_sha256: manifest.artifact_sha256.clone(),
        artifact_url: manifest.artifact_url.clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pPolicyError {
    InvalidPeerKey,
    InvalidLocalKey,
    InvalidConsentWindow,
    ConsentExpired,
    PeerNotSelected,
    InvalidHandshakeShape,
    HandshakeMismatch,
    InvalidSessionWindow,
    SessionExpired,
    SessionMismatch,
    CapabilityDenied,
    InvalidEnvelopeShape,
    ReplayDetected,
    EnvelopeExpired,
    EnvelopeTooLarge,
    RateLimited,
    VerificationInvalid,
    VerificationUnavailable,
    InvalidReleaseMetadata,
    WrongApplication,
    WrongPlatform,
    WrongChannel,
    WrongReleaseKey,
    UntrustedReleaseOrigin,
    RollbackRejected,
}

impl fmt::Display for P2pPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPeerKey => "invalid peer key identifier",
            Self::InvalidLocalKey => "invalid local key identifier",
            Self::InvalidConsentWindow => "invalid peer consent window",
            Self::ConsentExpired => "peer consent expired",
            Self::PeerNotSelected => "peer was not explicitly selected",
            Self::InvalidHandshakeShape => "invalid canonical handshake shape",
            Self::HandshakeMismatch => "peer handshake transcript does not match",
            Self::InvalidSessionWindow => "invalid peer session window",
            Self::SessionExpired => "peer session expired",
            Self::SessionMismatch => "peer session does not match",
            Self::CapabilityDenied => "peer payload capability was not selected",
            Self::InvalidEnvelopeShape => "invalid canonical encrypted envelope shape",
            Self::ReplayDetected => "peer envelope replay detected",
            Self::EnvelopeExpired => "peer envelope expired",
            Self::EnvelopeTooLarge => "peer envelope exceeds the desktop size bound",
            Self::RateLimited => "peer envelope rate exceeded",
            Self::VerificationInvalid => "peer cryptographic verification failed",
            Self::VerificationUnavailable => "peer cryptographic verification unavailable",
            Self::InvalidReleaseMetadata => "invalid release metadata",
            Self::WrongApplication => "update is for a different application",
            Self::WrongPlatform => "update is for a different platform",
            Self::WrongChannel => "update is for a different release channel",
            Self::WrongReleaseKey => "release key is not project-pinned",
            Self::UntrustedReleaseOrigin => "update origin is not an official allowlisted origin",
            Self::RollbackRejected => "release rollback rejected",
        })
    }
}

impl std::error::Error for P2pPolicyError {}

fn decoded_len(value: &str) -> Result<usize, P2pPolicyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| P2pPolicyError::InvalidEnvelopeShape)?;
    if bytes.is_empty() {
        return Err(P2pPolicyError::InvalidEnvelopeShape);
    }
    if bytes.len() > MAX_ENVELOPE_CIPHERTEXT_BYTES {
        return Err(P2pPolicyError::EnvelopeTooLarge);
    }
    Ok(bytes.len())
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validate_official_origin(
    artifact_url: &str,
    official_release_origin: &str,
) -> Result<(), P2pPolicyError> {
    let artifact = Url::parse(artifact_url).map_err(|_| P2pPolicyError::UntrustedReleaseOrigin)?;
    let official =
        Url::parse(official_release_origin).map_err(|_| P2pPolicyError::UntrustedReleaseOrigin)?;
    let valid = artifact.scheme() == "https"
        && official.scheme() == "https"
        && artifact.host_str().is_some()
        && official.host_str().is_some()
        && artifact.username().is_empty()
        && official.username().is_empty()
        && artifact.password().is_none()
        && official.password().is_none()
        && artifact.query().is_none()
        && artifact.fragment().is_none()
        && official.query().is_none()
        && official.fragment().is_none()
        && official.path() == "/"
        && artifact.origin() == official.origin();
    if valid {
        Ok(())
    } else {
        Err(P2pPolicyError::UntrustedReleaseOrigin)
    }
}

fn require_verified(outcome: VerificationOutcome) -> Result<(), P2pPolicyError> {
    match outcome {
        VerificationOutcome::Verified => Ok(()),
        VerificationOutcome::Invalid => Err(P2pPolicyError::VerificationInvalid),
        VerificationOutcome::Unavailable => Err(P2pPolicyError::VerificationUnavailable),
    }
}

fn remember<T>(values: &mut VecDeque<T>, value: T) {
    if values.len() == MAX_REMEMBERED_REPLAY_VALUES {
        drop(values.pop_front());
    }
    values.push_back(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_UNIX: i64 = 2_000_000_000;

    struct TestVerifier(VerificationOutcome);

    impl PeerCryptoVerifier for TestVerifier {
        fn verify_handshake(
            &self,
            _request: &PeerHandshakeRequest,
            _response: &PeerHandshakeResponse,
        ) -> VerificationOutcome {
            self.0
        }

        fn verify_and_authenticate_envelope(
            &self,
            _envelope: &PeerEncryptedEnvelope,
        ) -> VerificationOutcome {
            self.0
        }

        fn verify_update_manifest(&self, _manifest: &SignedUpdateManifest) -> VerificationOutcome {
            self.0
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(NOW_UNIX, 0).unwrap_or_default()
    }

    fn request(peer: &str) -> PeerHandshakeRequest {
        PeerHandshakeRequest {
            protocol_version: PEER_PROTOCOL_VERSION.to_owned(),
            session_id: Uuid::from_u128(1),
            offer_id: Uuid::from_u128(2),
            challenge_nonce: "n".repeat(22),
            ephemeral_public_key: "e".repeat(43),
            device_key_id: peer.to_owned(),
            device_attestation: "a".repeat(64),
            requested_capabilities: vec![
                PeerCapability::ResidentMessage,
                PeerCapability::UpdateManifest,
            ],
            expires_at: now() + Duration::seconds(60),
        }
    }

    fn response(local: &str) -> PeerHandshakeResponse {
        PeerHandshakeResponse {
            protocol_version: PEER_PROTOCOL_VERSION.to_owned(),
            session_id: Uuid::from_u128(1),
            offer_id: Uuid::from_u128(2),
            decision: PeerDecision::Accepted,
            selected_capabilities: vec![PeerCapability::ResidentMessage],
            ephemeral_public_key: Some("f".repeat(43)),
            device_key_id: Some(local.to_owned()),
            device_attestation: Some("c".repeat(64)),
            transcript_signature: Some("s".repeat(64)),
            rejection_code: None,
            expires_at: now() + Duration::seconds(60),
        }
    }

    fn envelope(peer: &str, sequence: u32, nonce_byte: u8) -> PeerEncryptedEnvelope {
        PeerEncryptedEnvelope {
            protocol_version: PEER_PROTOCOL_VERSION.to_owned(),
            session_id: Uuid::from_u128(1),
            message_id: Uuid::from_u128(u128::from(sequence) + 100),
            sequence,
            payload_type: PeerPayloadType::ResidentMessage,
            nonce: URL_SAFE_NO_PAD.encode(vec![nonce_byte; 16]),
            ciphertext: URL_SAFE_NO_PAD.encode(vec![9; 128]),
            sender_key_id: peer.to_owned(),
            created_at: now(),
            expires_at: now() + Duration::seconds(30),
        }
    }

    fn established_guard() -> PeerSessionGuard {
        let peer = "device:peer-1";
        let local = "device:local-1";
        let selection = PeerSelection::try_new(peer, now(), 120);
        assert!(selection.is_ok());
        let result = selection.and_then(|selection| {
            PeerSessionGuard::establish(
                &selection,
                local,
                &request(peer),
                &response(local),
                now(),
                600,
                &TestVerifier(VerificationOutcome::Verified),
            )
        });
        assert!(result.is_ok());
        result.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn session_requires_selected_peer_and_available_valid_crypto() {
        let local = "device:local-1";
        let selection = PeerSelection::try_new("device:other", now(), 120);
        assert!(selection.is_ok());
        if let Ok(selection) = selection {
            assert!(matches!(
                PeerSessionGuard::establish(
                    &selection,
                    local,
                    &request("device:peer-1"),
                    &response(local),
                    now(),
                    600,
                    &TestVerifier(VerificationOutcome::Verified),
                ),
                Err(P2pPolicyError::PeerNotSelected)
            ));
        }

        let selection = PeerSelection::try_new("device:peer-1", now(), 120);
        assert!(selection.is_ok());
        if let Ok(selection) = selection {
            assert!(matches!(
                PeerSessionGuard::establish(
                    &selection,
                    local,
                    &request("device:peer-1"),
                    &response(local),
                    now(),
                    600,
                    &TestVerifier(VerificationOutcome::Unavailable),
                ),
                Err(P2pPolicyError::VerificationUnavailable)
            ));
        }
    }

    #[test]
    fn rejects_replay_expiry_oversize_and_unselected_payload() {
        let peer = "device:peer-1";
        let verifier = TestVerifier(VerificationOutcome::Verified);
        let mut guard = established_guard();
        let first = envelope(peer, 1, 7);
        assert!(guard.accept_envelope(&first, now(), &verifier).is_ok());
        assert!(matches!(
            guard.accept_envelope(&first, now(), &verifier),
            Err(P2pPolicyError::ReplayDetected)
        ));

        let mut expired = envelope(peer, 2, 8);
        expired.expires_at = now() + Duration::seconds(61);
        assert!(matches!(
            guard.accept_envelope(&expired, now(), &verifier),
            Err(P2pPolicyError::EnvelopeExpired)
        ));

        let mut oversized = envelope(peer, 2, 8);
        oversized.ciphertext = URL_SAFE_NO_PAD.encode(vec![9; MAX_ENVELOPE_CIPHERTEXT_BYTES + 1]);
        assert!(matches!(
            guard.accept_envelope(&oversized, now(), &verifier),
            Err(P2pPolicyError::EnvelopeTooLarge)
        ));

        let mut denied = envelope(peer, 2, 8);
        denied.payload_type = PeerPayloadType::ContactCard;
        assert!(matches!(
            guard.accept_envelope(&denied, now(), &verifier),
            Err(P2pPolicyError::CapabilityDenied)
        ));
    }

    #[test]
    fn failed_crypto_does_not_commit_replay_state() {
        let candidate = envelope("device:peer-1", 1, 7);
        let mut guard = established_guard();
        assert!(matches!(
            guard.accept_envelope(
                &candidate,
                now(),
                &TestVerifier(VerificationOutcome::Invalid),
            ),
            Err(P2pPolicyError::VerificationInvalid)
        ));
        assert!(
            guard
                .accept_envelope(
                    &candidate,
                    now(),
                    &TestVerifier(VerificationOutcome::Verified),
                )
                .is_ok()
        );
    }

    #[test]
    fn rate_limit_is_enforced() {
        let verifier = TestVerifier(VerificationOutcome::Verified);
        let mut guard = established_guard();
        for sequence in 1..=u32::from(MAX_MESSAGES_PER_MINUTE) {
            let message = envelope(
                "device:peer-1",
                sequence,
                u8::try_from(sequence).unwrap_or(1),
            );
            assert!(guard.accept_envelope(&message, now(), &verifier).is_ok());
        }
        let limited = envelope("device:peer-1", u32::from(MAX_MESSAGES_PER_MINUTE) + 1, 99);
        assert!(matches!(
            guard.accept_envelope(&limited, now(), &verifier),
            Err(P2pPolicyError::RateLimited)
        ));
    }

    fn update_manifest() -> SignedUpdateManifest {
        SignedUpdateManifest {
            schema: hhm_interfaces::PEER_UPDATE_MANIFEST_SCHEMA.to_owned(),
            app_id: PeerApplication::HhmDesktopAppRs,
            platform: PeerPlatform::Linux,
            channel: ReleaseChannel::Stable,
            version: "1.2.3".to_owned(),
            anti_rollback_counter: 8,
            artifact_size: 1024,
            artifact_sha256: "a".repeat(64),
            artifact_url: "https://releases.hhm.example/desktop/app.tar.zst".to_owned(),
            signing_key_id: "release:hhm-1".to_owned(),
            signature: "s".repeat(64),
            published_at: now(),
        }
    }

    #[test]
    fn update_metadata_requires_pinned_key_origin_and_anti_rollback() {
        let verifier = TestVerifier(VerificationOutcome::Verified);
        let mut manifest = update_manifest();
        assert!(
            consider_update_manifest(
                &manifest,
                PeerPlatform::Linux,
                ReleaseChannel::Stable,
                "release:hhm-1",
                7,
                "https://releases.hhm.example/",
                &verifier,
            )
            .is_ok()
        );
        assert!(matches!(
            consider_update_manifest(
                &manifest,
                PeerPlatform::Linux,
                ReleaseChannel::Stable,
                "release:hhm-1",
                8,
                "https://releases.hhm.example/",
                &verifier,
            ),
            Err(P2pPolicyError::RollbackRejected)
        ));
        manifest.artifact_url = "https://nearby-peer.invalid/app".to_owned();
        assert!(matches!(
            consider_update_manifest(
                &manifest,
                PeerPlatform::Linux,
                ReleaseChannel::Stable,
                "release:hhm-1",
                7,
                "https://releases.hhm.example/",
                &verifier,
            ),
            Err(P2pPolicyError::UntrustedReleaseOrigin)
        ));
    }

    #[test]
    fn canonical_peer_fixture_deserializes_and_validates() {
        let fixture = serde_json::from_str::<serde_json::Value>(include_str!(
            "../contracts/fixtures/peer-session.json"
        ));
        assert!(fixture.is_ok());
        let Ok(fixture) = fixture else {
            return;
        };
        let request =
            serde_json::from_value::<PeerHandshakeRequest>(fixture["handshake_request"].clone());
        let response =
            serde_json::from_value::<PeerHandshakeResponse>(fixture["handshake_response"].clone());
        let envelope =
            serde_json::from_value::<PeerEncryptedEnvelope>(fixture["encrypted_envelope"].clone());
        let manifest = serde_json::from_value::<SignedUpdateManifest>(
            fixture["signed_update_manifest"].clone(),
        );
        assert!(request.is_ok());
        assert!(response.is_ok());
        assert!(envelope.is_ok());
        assert!(manifest.is_ok());

        let fixture_now = DateTime::parse_from_rfc3339("2026-08-24T18:00:30Z")
            .map(|value| value.with_timezone(&Utc));
        assert!(fixture_now.is_ok());
        if let (Ok(request), Ok(response), Ok(envelope), Ok(manifest), Ok(fixture_now)) =
            (request, response, envelope, manifest, fixture_now)
        {
            assert!(request.validate_shape(fixture_now).is_ok());
            assert!(response.validate_shape(fixture_now).is_ok());
            assert!(envelope.validate_shape(fixture_now).is_ok());
            assert!(manifest.validate_shape().is_ok());
        }
    }

    #[test]
    fn canonical_allowlist_has_no_presence_or_secret_payload_type() {
        let values = [
            PeerPayloadType::ResidentMessage,
            PeerPayloadType::ContactCard,
            PeerPayloadType::FileManifest,
            PeerPayloadType::UpdateManifest,
            PeerPayloadType::Receipt,
        ];
        let json = serde_json::to_string(&values).unwrap_or_default();
        assert!(!json.contains("presence"));
        for forbidden in [
            "token",
            "password",
            "private_key",
            "otp",
            "camera",
            "audio",
            "location",
        ] {
            assert!(
                !json.contains(forbidden),
                "unexpected payload type: {forbidden}"
            );
        }
    }

    #[test]
    fn vendored_contract_records_exact_canonical_revision() {
        assert_eq!(
            HHM_INTERFACES_P2P_REVISION,
            "f694bc9b58907db918f0449b5d04a5763f8fa745"
        );
        assert_eq!(HHM_DESKTOP_P2P_PROTOCOL_VERSION, "hhm.p2p.v1");
    }
}
