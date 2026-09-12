//! Portable peer-to-peer policy foundation for BLE and future transports.
//!
//! BLE discovery is transport evidence only. This module requires explicit
//! peer selection, bounded consent, device-bound cryptographic verification,
//! replay/expiry/rate controls, and allowlisted encrypted envelope kinds. It
//! does not implement cryptography, authentication, code loading, or updates.

use std::{collections::VecDeque, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

pub const HHM_DESKTOP_P2P_PROTOCOL_VERSION: u32 = 1;
pub const MAX_ENVELOPE_CIPHERTEXT_BYTES: usize = 32 * 1024;
pub const MAX_MESSAGES_PER_MINUTE: u16 = 30;
pub const MAX_BYTES_PER_MINUTE: usize = 256 * 1024;

const MAX_CONSENT_TTL_SECONDS: u64 = 5 * 60;
const MAX_SESSION_TTL_SECONDS: u64 = 15 * 60;
const MAX_ENVELOPE_TTL_SECONDS: u64 = 60;
const MAX_CLOCK_SKEW_SECONDS: u64 = 30;
const MAX_REMEMBERED_NONCES: usize = 128;
const PEER_KEY_ID_HEX_BYTES: usize = 64;
const DIGEST_HEX_BYTES: usize = 64;
const SESSION_ID_BYTES: usize = 16;
const CHALLENGE_NONCE_BYTES: usize = 32;
const ENVELOPE_NONCE_BYTES: usize = 24;
const MIN_SIGNATURE_BYTES: usize = 48;
const MAX_SIGNATURE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum P2pPayloadKind {
    PresenceRequestHint,
    HouseNotice,
    ResidentMessage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionOffer {
    pub protocol_version: u32,
    pub peer_key_id: String,
    pub local_key_id: String,
    pub session_id_b64: String,
    pub challenge_nonce_b64: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub device_signature_b64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub protocol_version: u32,
    pub peer_key_id: String,
    pub session_id_b64: String,
    pub sequence: u64,
    pub expires_at_unix: u64,
    pub kind: P2pPayloadKind,
    pub aead_nonce_b64: String,
    pub ciphertext_b64: String,
    pub device_signature_b64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateAnnouncement {
    pub protocol_version: u32,
    pub release_sequence: u64,
    pub version: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub release_key_id: String,
    pub signature_b64: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Verified,
    Invalid,
    Unavailable,
}

/// Cryptographic authority implemented only by the reviewed device/Shared Auth
/// adapter. The domain intentionally provides no permissive production
/// implementation.
pub trait PeerCryptoVerifier {
    fn verify_session_offer(&self, offer: &SessionOffer) -> VerificationOutcome;
    fn verify_and_authenticate_envelope(&self, envelope: &EncryptedEnvelope)
    -> VerificationOutcome;
    fn verify_update_announcement(&self, announcement: &UpdateAnnouncement) -> VerificationOutcome;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerSelection {
    peer_key_id: String,
    consent_expires_at_unix: u64,
}

impl PeerSelection {
    /// Records explicit local consent for one selected peer.
    ///
    /// # Errors
    ///
    /// Rejects malformed peer key identifiers, zero-length consent, consent
    /// longer than five minutes, and timestamp overflow.
    pub fn try_new(
        peer_key_id: &str,
        now_unix: u64,
        consent_ttl_seconds: u64,
    ) -> Result<Self, P2pPolicyError> {
        if !valid_hex(peer_key_id, PEER_KEY_ID_HEX_BYTES) {
            return Err(P2pPolicyError::InvalidPeerKey);
        }
        if !(1..=MAX_CONSENT_TTL_SECONDS).contains(&consent_ttl_seconds) {
            return Err(P2pPolicyError::InvalidConsentWindow);
        }
        let Some(consent_expires_at_unix) = now_unix.checked_add(consent_ttl_seconds) else {
            return Err(P2pPolicyError::InvalidConsentWindow);
        };
        Ok(Self {
            peer_key_id: peer_key_id.to_owned(),
            consent_expires_at_unix,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedEnvelope {
    pub kind: P2pPayloadKind,
    pub sequence: u64,
    pub ciphertext_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdateMetadata {
    pub release_sequence: u64,
    pub version: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
}

pub struct PeerSessionGuard {
    peer_key_id: String,
    session_id_b64: String,
    expires_at_unix: u64,
    last_sequence: Option<u64>,
    seen_nonces: VecDeque<String>,
    rate_window_started_at_unix: u64,
    messages_in_window: u16,
    bytes_in_window: usize,
}

impl PeerSessionGuard {
    /// Establishes policy state only after consent and device-bound signature
    /// verification by the official adapter.
    ///
    /// # Errors
    ///
    /// Rejects protocol mismatch, malformed/boundary-breaking metadata,
    /// unselected peers, expired consent/offers, excessive session lifetime,
    /// invalid signatures, and unavailable verification authority.
    pub fn establish(
        selection: &PeerSelection,
        expected_local_key_id: &str,
        offer: &SessionOffer,
        now_unix: u64,
        verifier: &impl PeerCryptoVerifier,
    ) -> Result<Self, P2pPolicyError> {
        validate_session_offer(offer, expected_local_key_id, now_unix)?;
        if selection.consent_expires_at_unix <= now_unix {
            return Err(P2pPolicyError::ConsentExpired);
        }
        if selection.peer_key_id != offer.peer_key_id {
            return Err(P2pPolicyError::PeerNotSelected);
        }
        require_verified(verifier.verify_session_offer(offer))?;
        Ok(Self {
            peer_key_id: offer.peer_key_id.clone(),
            session_id_b64: offer.session_id_b64.clone(),
            expires_at_unix: offer.expires_at_unix,
            last_sequence: None,
            seen_nonces: VecDeque::with_capacity(MAX_REMEMBERED_NONCES),
            rate_window_started_at_unix: now_unix,
            messages_in_window: 0,
            bytes_in_window: 0,
        })
    }

    /// Validates an encrypted, signed allowlisted envelope and commits replay
    /// and rate-limit state only after cryptographic verification succeeds.
    ///
    /// # Errors
    ///
    /// Fails closed on malformed metadata, session/peer mismatch, expiry,
    /// replay, excessive size/rate, invalid authentication, or unavailable
    /// verification authority.
    pub fn accept_envelope(
        &mut self,
        envelope: &EncryptedEnvelope,
        now_unix: u64,
        verifier: &impl PeerCryptoVerifier,
    ) -> Result<AcceptedEnvelope, P2pPolicyError> {
        if now_unix >= self.expires_at_unix {
            return Err(P2pPolicyError::SessionExpired);
        }
        validate_envelope_shape(envelope, now_unix, self.expires_at_unix)?;
        if envelope.peer_key_id != self.peer_key_id
            || envelope.session_id_b64 != self.session_id_b64
        {
            return Err(P2pPolicyError::SessionMismatch);
        }
        if self
            .last_sequence
            .is_some_and(|sequence| envelope.sequence <= sequence)
            || self.seen_nonces.contains(&envelope.aead_nonce_b64)
        {
            return Err(P2pPolicyError::ReplayDetected);
        }
        let ciphertext_bytes =
            decoded_len(&envelope.ciphertext_b64, 1, MAX_ENVELOPE_CIPHERTEXT_BYTES)?;

        let reset_window = now_unix.saturating_sub(self.rate_window_started_at_unix) >= 60;
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
            self.rate_window_started_at_unix = now_unix;
        }
        self.messages_in_window = messages;
        self.bytes_in_window = bytes;
        self.last_sequence = Some(envelope.sequence);
        if self.seen_nonces.len() == MAX_REMEMBERED_NONCES {
            drop(self.seen_nonces.pop_front());
        }
        self.seen_nonces.push_back(envelope.aead_nonce_b64.clone());

        Ok(AcceptedEnvelope {
            kind: envelope.kind,
            sequence: envelope.sequence,
            ciphertext_bytes,
        })
    }
}

/// Validates signed peer-discovered update metadata without accepting artifact
/// bytes, URLs, executable code, or install instructions.
///
/// The caller must pass the project-pinned release-key identifier and the
/// locally installed release sequence. An accepted result is metadata only;
/// an official updater must fetch and verify the manifest/artifact from its
/// configured trusted origin before any installation.
///
/// # Errors
///
/// Rejects malformed metadata, wrong release keys, rollback/equal sequences,
/// invalid signatures, and unavailable verification authority.
pub fn consider_update_announcement(
    announcement: &UpdateAnnouncement,
    pinned_release_key_id: &str,
    installed_release_sequence: u64,
    verifier: &impl PeerCryptoVerifier,
) -> Result<VerifiedUpdateMetadata, P2pPolicyError> {
    if announcement.protocol_version != HHM_DESKTOP_P2P_PROTOCOL_VERSION {
        return Err(P2pPolicyError::UnsupportedProtocol);
    }
    if !valid_hex(pinned_release_key_id, PEER_KEY_ID_HEX_BYTES)
        || !valid_hex(&announcement.release_key_id, PEER_KEY_ID_HEX_BYTES)
    {
        return Err(P2pPolicyError::InvalidReleaseMetadata);
    }
    if announcement.release_key_id != pinned_release_key_id {
        return Err(P2pPolicyError::WrongReleaseKey);
    }
    if announcement.release_sequence <= installed_release_sequence {
        return Err(P2pPolicyError::RollbackRejected);
    }
    if !valid_version(&announcement.version)
        || !valid_hex(&announcement.manifest_sha256, DIGEST_HEX_BYTES)
        || !valid_hex(&announcement.artifact_sha256, DIGEST_HEX_BYTES)
    {
        return Err(P2pPolicyError::InvalidReleaseMetadata);
    }
    decoded_len(
        &announcement.signature_b64,
        MIN_SIGNATURE_BYTES,
        MAX_SIGNATURE_BYTES,
    )?;
    require_verified(verifier.verify_update_announcement(announcement))?;
    Ok(VerifiedUpdateMetadata {
        release_sequence: announcement.release_sequence,
        version: announcement.version.clone(),
        manifest_sha256: announcement.manifest_sha256.clone(),
        artifact_sha256: announcement.artifact_sha256.clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pPolicyError {
    UnsupportedProtocol,
    InvalidPeerKey,
    InvalidLocalKey,
    InvalidEncoding,
    InvalidConsentWindow,
    ConsentExpired,
    PeerNotSelected,
    OfferExpired,
    InvalidSessionWindow,
    SessionExpired,
    SessionMismatch,
    ReplayDetected,
    EnvelopeExpired,
    EnvelopeTooLarge,
    RateLimited,
    VerificationInvalid,
    VerificationUnavailable,
    InvalidReleaseMetadata,
    WrongReleaseKey,
    RollbackRejected,
}

impl fmt::Display for P2pPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedProtocol => "unsupported P2P protocol",
            Self::InvalidPeerKey => "invalid peer key identifier",
            Self::InvalidLocalKey => "invalid local key identifier",
            Self::InvalidEncoding => "invalid bounded P2P encoding",
            Self::InvalidConsentWindow => "invalid peer consent window",
            Self::ConsentExpired => "peer consent expired",
            Self::PeerNotSelected => "peer was not explicitly selected",
            Self::OfferExpired => "peer session offer expired",
            Self::InvalidSessionWindow => "invalid peer session window",
            Self::SessionExpired => "peer session expired",
            Self::SessionMismatch => "peer session does not match",
            Self::ReplayDetected => "peer envelope replay detected",
            Self::EnvelopeExpired => "peer envelope expired",
            Self::EnvelopeTooLarge => "peer envelope exceeds the size bound",
            Self::RateLimited => "peer envelope rate exceeded",
            Self::VerificationInvalid => "peer cryptographic verification failed",
            Self::VerificationUnavailable => "peer cryptographic verification unavailable",
            Self::InvalidReleaseMetadata => "invalid release metadata",
            Self::WrongReleaseKey => "release key is not project-pinned",
            Self::RollbackRejected => "release rollback rejected",
        })
    }
}

impl std::error::Error for P2pPolicyError {}

fn validate_session_offer(
    offer: &SessionOffer,
    expected_local_key_id: &str,
    now_unix: u64,
) -> Result<(), P2pPolicyError> {
    if offer.protocol_version != HHM_DESKTOP_P2P_PROTOCOL_VERSION {
        return Err(P2pPolicyError::UnsupportedProtocol);
    }
    if !valid_hex(&offer.peer_key_id, PEER_KEY_ID_HEX_BYTES) {
        return Err(P2pPolicyError::InvalidPeerKey);
    }
    if !valid_hex(expected_local_key_id, PEER_KEY_ID_HEX_BYTES)
        || offer.local_key_id != expected_local_key_id
    {
        return Err(P2pPolicyError::InvalidLocalKey);
    }
    decoded_len(&offer.session_id_b64, SESSION_ID_BYTES, SESSION_ID_BYTES)?;
    decoded_len(
        &offer.challenge_nonce_b64,
        CHALLENGE_NONCE_BYTES,
        CHALLENGE_NONCE_BYTES,
    )?;
    decoded_len(
        &offer.device_signature_b64,
        MIN_SIGNATURE_BYTES,
        MAX_SIGNATURE_BYTES,
    )?;
    if offer.expires_at_unix <= now_unix {
        return Err(P2pPolicyError::OfferExpired);
    }
    if offer.issued_at_unix > now_unix.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        || offer.expires_at_unix <= offer.issued_at_unix
        || offer.expires_at_unix.saturating_sub(offer.issued_at_unix) > MAX_SESSION_TTL_SECONDS
    {
        return Err(P2pPolicyError::InvalidSessionWindow);
    }
    Ok(())
}

fn validate_envelope_shape(
    envelope: &EncryptedEnvelope,
    now_unix: u64,
    session_expires_at_unix: u64,
) -> Result<(), P2pPolicyError> {
    if envelope.protocol_version != HHM_DESKTOP_P2P_PROTOCOL_VERSION {
        return Err(P2pPolicyError::UnsupportedProtocol);
    }
    if !valid_hex(&envelope.peer_key_id, PEER_KEY_ID_HEX_BYTES) {
        return Err(P2pPolicyError::InvalidPeerKey);
    }
    decoded_len(&envelope.session_id_b64, SESSION_ID_BYTES, SESSION_ID_BYTES)?;
    decoded_len(
        &envelope.aead_nonce_b64,
        ENVELOPE_NONCE_BYTES,
        ENVELOPE_NONCE_BYTES,
    )?;
    decoded_len(
        &envelope.device_signature_b64,
        MIN_SIGNATURE_BYTES,
        MAX_SIGNATURE_BYTES,
    )?;
    if envelope.expires_at_unix <= now_unix
        || envelope.expires_at_unix > session_expires_at_unix
        || envelope.expires_at_unix.saturating_sub(now_unix) > MAX_ENVELOPE_TTL_SECONDS
    {
        return Err(P2pPolicyError::EnvelopeExpired);
    }
    Ok(())
}

fn require_verified(outcome: VerificationOutcome) -> Result<(), P2pPolicyError> {
    match outcome {
        VerificationOutcome::Verified => Ok(()),
        VerificationOutcome::Invalid => Err(P2pPolicyError::VerificationInvalid),
        VerificationOutcome::Unavailable => Err(P2pPolicyError::VerificationUnavailable),
    }
}

fn decoded_len(value: &str, minimum: usize, maximum: usize) -> Result<usize, P2pPolicyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| P2pPolicyError::InvalidEncoding)?;
    if bytes.len() < minimum {
        return Err(P2pPolicyError::InvalidEncoding);
    }
    if bytes.len() > maximum {
        return Err(P2pPolicyError::EnvelopeTooLarge);
    }
    Ok(bytes.len())
}

fn valid_hex(value: &str, exact_bytes: usize) -> bool {
    value.len() == exact_bytes && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 2_000_000_000;

    struct TestVerifier(VerificationOutcome);

    impl PeerCryptoVerifier for TestVerifier {
        fn verify_session_offer(&self, _offer: &SessionOffer) -> VerificationOutcome {
            self.0
        }

        fn verify_and_authenticate_envelope(
            &self,
            _envelope: &EncryptedEnvelope,
        ) -> VerificationOutcome {
            self.0
        }

        fn verify_update_announcement(
            &self,
            _announcement: &UpdateAnnouncement,
        ) -> VerificationOutcome {
            self.0
        }
    }

    fn key(byte: &str) -> String {
        byte.repeat(32)
    }

    fn encoded(byte: u8, length: usize) -> String {
        URL_SAFE_NO_PAD.encode(vec![byte; length])
    }

    fn offer(peer: &str, local: &str) -> SessionOffer {
        SessionOffer {
            protocol_version: HHM_DESKTOP_P2P_PROTOCOL_VERSION,
            peer_key_id: peer.to_owned(),
            local_key_id: local.to_owned(),
            session_id_b64: encoded(1, SESSION_ID_BYTES),
            challenge_nonce_b64: encoded(2, CHALLENGE_NONCE_BYTES),
            issued_at_unix: NOW,
            expires_at_unix: NOW + 300,
            device_signature_b64: encoded(3, 64),
        }
    }

    fn envelope(peer: &str, sequence: u64, nonce_byte: u8) -> EncryptedEnvelope {
        EncryptedEnvelope {
            protocol_version: HHM_DESKTOP_P2P_PROTOCOL_VERSION,
            peer_key_id: peer.to_owned(),
            session_id_b64: encoded(1, SESSION_ID_BYTES),
            sequence,
            expires_at_unix: NOW + 30,
            kind: P2pPayloadKind::HouseNotice,
            aead_nonce_b64: encoded(nonce_byte, ENVELOPE_NONCE_BYTES),
            ciphertext_b64: encoded(9, 128),
            device_signature_b64: encoded(4, 64),
        }
    }

    fn established_guard() -> PeerSessionGuard {
        let peer = key("11");
        let local = key("22");
        let selection = PeerSelection::try_new(&peer, NOW, 120);
        assert!(selection.is_ok());
        let result = selection.and_then(|selection| {
            PeerSessionGuard::establish(
                &selection,
                &local,
                &offer(&peer, &local),
                NOW,
                &TestVerifier(VerificationOutcome::Verified),
            )
        });
        assert!(result.is_ok());
        result.unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn session_requires_explicit_selected_peer_and_valid_crypto() {
        let peer = key("11");
        let other = key("33");
        let local = key("22");
        let selection = PeerSelection::try_new(&other, NOW, 120);
        assert!(selection.is_ok());
        if let Ok(selection) = selection {
            assert!(matches!(
                PeerSessionGuard::establish(
                    &selection,
                    &local,
                    &offer(&peer, &local),
                    NOW,
                    &TestVerifier(VerificationOutcome::Verified),
                ),
                Err(P2pPolicyError::PeerNotSelected)
            ));
        }

        let selection = PeerSelection::try_new(&peer, NOW, 120);
        assert!(selection.is_ok());
        if let Ok(selection) = selection {
            assert!(matches!(
                PeerSessionGuard::establish(
                    &selection,
                    &local,
                    &offer(&peer, &local),
                    NOW,
                    &TestVerifier(VerificationOutcome::Unavailable),
                ),
                Err(P2pPolicyError::VerificationUnavailable)
            ));
        }
    }

    #[test]
    fn rejects_replay_expiry_and_oversized_ciphertext() {
        let peer = key("11");
        let verifier = TestVerifier(VerificationOutcome::Verified);
        let mut guard = established_guard();
        let first = envelope(&peer, 1, 7);
        assert!(guard.accept_envelope(&first, NOW + 1, &verifier).is_ok());
        assert!(matches!(
            guard.accept_envelope(&first, NOW + 2, &verifier),
            Err(P2pPolicyError::ReplayDetected)
        ));

        let mut expired = envelope(&peer, 2, 8);
        expired.expires_at_unix = NOW;
        assert!(matches!(
            guard.accept_envelope(&expired, NOW + 2, &verifier),
            Err(P2pPolicyError::EnvelopeExpired)
        ));

        let mut oversized = envelope(&peer, 2, 8);
        oversized.ciphertext_b64 = encoded(9, MAX_ENVELOPE_CIPHERTEXT_BYTES + 1);
        assert!(matches!(
            guard.accept_envelope(&oversized, NOW + 2, &verifier),
            Err(P2pPolicyError::EnvelopeTooLarge)
        ));
    }

    #[test]
    fn rate_limit_and_failed_crypto_do_not_commit_replay_state() {
        let peer = key("11");
        let mut guard = established_guard();
        let candidate = envelope(&peer, 1, 7);
        assert!(matches!(
            guard.accept_envelope(
                &candidate,
                NOW + 1,
                &TestVerifier(VerificationOutcome::Invalid),
            ),
            Err(P2pPolicyError::VerificationInvalid)
        ));
        assert!(
            guard
                .accept_envelope(
                    &candidate,
                    NOW + 1,
                    &TestVerifier(VerificationOutcome::Verified),
                )
                .is_ok()
        );

        for sequence in 2..=u64::from(MAX_MESSAGES_PER_MINUTE) {
            let nonce = u8::try_from(sequence.saturating_add(10)).unwrap_or(10);
            let message = envelope(&peer, sequence, nonce);
            assert!(
                guard
                    .accept_envelope(
                        &message,
                        NOW + 2,
                        &TestVerifier(VerificationOutcome::Verified),
                    )
                    .is_ok()
            );
        }
        let limited = envelope(&peer, u64::from(MAX_MESSAGES_PER_MINUTE) + 1, 99);
        assert!(matches!(
            guard.accept_envelope(
                &limited,
                NOW + 2,
                &TestVerifier(VerificationOutcome::Verified),
            ),
            Err(P2pPolicyError::RateLimited)
        ));
    }

    #[test]
    fn byte_rate_limit_is_independent_from_message_count() {
        let peer = key("11");
        let verifier = TestVerifier(VerificationOutcome::Verified);
        let mut guard = established_guard();
        for sequence in 1..=8 {
            let mut message = envelope(&peer, sequence, u8::try_from(sequence).unwrap_or(1));
            message.ciphertext_b64 = encoded(9, MAX_ENVELOPE_CIPHERTEXT_BYTES);
            assert!(guard.accept_envelope(&message, NOW + 1, &verifier).is_ok());
        }
        let mut limited = envelope(&peer, 9, 9);
        limited.ciphertext_b64 = encoded(9, MAX_ENVELOPE_CIPHERTEXT_BYTES);
        assert!(matches!(
            guard.accept_envelope(&limited, NOW + 1, &verifier),
            Err(P2pPolicyError::RateLimited)
        ));
    }

    #[test]
    fn update_discovery_is_signed_metadata_only_and_anti_rollback() {
        let release_key = key("aa");
        let mut announcement = UpdateAnnouncement {
            protocol_version: HHM_DESKTOP_P2P_PROTOCOL_VERSION,
            release_sequence: 8,
            version: "1.2.3".to_owned(),
            manifest_sha256: key("bb"),
            artifact_sha256: key("cc"),
            release_key_id: release_key.clone(),
            signature_b64: encoded(5, 64),
        };
        assert!(
            consider_update_announcement(
                &announcement,
                &release_key,
                7,
                &TestVerifier(VerificationOutcome::Verified),
            )
            .is_ok()
        );
        assert!(matches!(
            consider_update_announcement(
                &announcement,
                &release_key,
                7,
                &TestVerifier(VerificationOutcome::Unavailable),
            ),
            Err(P2pPolicyError::VerificationUnavailable)
        ));
        assert!(matches!(
            consider_update_announcement(
                &announcement,
                &release_key,
                8,
                &TestVerifier(VerificationOutcome::Verified),
            ),
            Err(P2pPolicyError::RollbackRejected)
        ));
        announcement.release_key_id = key("dd");
        assert!(matches!(
            consider_update_announcement(
                &announcement,
                &release_key,
                7,
                &TestVerifier(VerificationOutcome::Verified),
            ),
            Err(P2pPolicyError::WrongReleaseKey)
        ));
    }

    #[test]
    fn flutter_fixtures_match_the_rust_wire_types() {
        let schema = serde_json::from_str::<serde_json::Value>(include_str!(
            "../contracts/p2p-v1.schema.json"
        ));
        assert!(schema.is_ok());
        let envelope = serde_json::from_str::<EncryptedEnvelope>(include_str!(
            "../contracts/fixtures/encrypted-envelope-v1.json"
        ));
        assert!(envelope.is_ok());
        let update = serde_json::from_str::<UpdateAnnouncement>(include_str!(
            "../contracts/fixtures/update-announcement-v1.json"
        ));
        assert!(update.is_ok());
    }

    #[test]
    fn wire_model_has_no_forbidden_payload_kinds_or_secret_fields() {
        let json = serde_json::to_string(&envelope(&key("11"), 1, 7)).unwrap_or_default();
        for forbidden in [
            "token",
            "password",
            "private_key",
            "otp",
            "camera",
            "audio",
            "location",
        ] {
            assert!(!json.contains(forbidden), "unexpected field: {forbidden}");
        }
    }
}
