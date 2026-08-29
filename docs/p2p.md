# Authenticated P2P over nearby transports

`hhm-interfaces` is the sole wire-contract authority. This repository consumes
the public Rust crate at exact commit
`ffc1df71d1d89202b431f4830cc2a43e4a451da3` and vendors byte-for-byte copies
for non-Rust clients:

- `contracts/p2p-v1.schema.json` is upstream
  `schemas/peer-session.json` (Git blob
  `94e72f5fbf65815f28ba718cabceb93ebf9b744c`);
- `contracts/fixtures/peer-session.json` is upstream
  `fixtures/peer-session.json` (Git blob
  `75df4f5435b67d278f8ea19286b192e8eca0cf10`);
- `contracts/fixtures/p2p-json-records.json` and
  `contracts/fixtures/doorway-observation.json` are byte-identical upstream v1
  fixtures with SHA-256 digests
  `d49aa5ee80e33603f82700b98488bf67af20885fe87c2ab8698647662aab9ba0`
  and `b4f70e954accecfec58fcbe9e8504f1bf7be104cfacdd209cd1c80c06773fb63`.

The compatibility test deserializes every canonical fixture object through the
pinned `hhm-interfaces` types and runs their shape validation. The protocol
identifier is the string `hhm.p2p.v1`, not a local numeric version.

## Trust and consent boundary

Bluetooth Low Energy is only a possible discovery and frame transport. RSSI,
proximity, pairing, device names, and a successful connection are not identity,
authentication, authorization, assurance, resident status, or proof of a door
transition. Discovery and sharing require a foreground opt-in and explicit peer
and capability selection. Consent expires within five minutes.

Automatic resident arrival/departure is a separate corroborated presence
workflow. The P2P allowlist contains no presence payload.

The canonical handshake binds fresh offers, challenges, ephemeral public keys,
device key identifiers, a short expiry, and the requested/selected capability
set. `PeerCryptoVerifier` is a typed boundary for the reviewed device-bound
Shared Auth adapter. The domain has no production verifier, JWT parser,
introspection client, or success stub. Both `invalid` and `unavailable` fail
closed. An accepted handshake must select at least one requested capability.

## Encrypted envelopes

Only the canonical payload types are accepted:

- `hhm.resident-message.v1`;
- `hhm.contact-card.v1`;
- `hhm.file-manifest.v1`;
- `hhm.update-manifest.v1`;
- `hhm.receipt.v1`.

The selected handshake capabilities gate those types. Each envelope carries a
session ID, message ID, monotonic sequence, authenticated timestamps, sender
key ID, nonce, and end-to-end ciphertext. The desktop policy is intentionally
stricter than the shared ceiling:

- at most 32 KiB of decoded ciphertext;
- at most 60 seconds from creation to expiry;
- at most 15 minutes per local session;
- at most 30 envelopes and 256 KiB per minute;
- replay rejection by message ID, nonce, and sequence, retaining 128 IDs and
  128 nonces in addition to the monotonic sequence.

Failed cryptographic verification does not consume a nonce or advance the
sequence, avoiding an unauthenticated denial-of-service primitive. Decrypted
contact cards, plain-text resident messages, and receipts must additionally
pass `validate_peer_json_record` before the envelope is committed: local
sharing consent defaults off, envelope type must equal the inner schema, and
the canonical validator rejects unknown fields, non-HTTPS website values,
control characters, expiry, and lifetimes over ten minutes. Arbitrary JSON,
HTML execution, and implicit file transfer are not extensions.

Passwords, access or refresh tokens, cookies, service credentials, private
keys, OTP/TOTP values or seeds, biometrics, door challenges, visitor QR bearer
values, payment material, camera/video, conversations/audio, and precise
location must never be sent or tunneled inside an allowlisted payload.

## Peer-assisted update discovery

A peer may carry only a canonical `SignedUpdateManifest`; the peer remains an
untrusted discovery/cache hint. The desktop policy additionally requires:

1. application ID `hhm-desktop-app.rs` and the configured platform/channel;
2. a project-pinned release signing key ID and official verifier result;
3. a strictly increasing anti-rollback counter; and
4. an allowlisted official HTTPS origin with no credentials, query, or
   fragment.

Acceptance yields metadata only. This module never fetches, installs, loads, or
executes an artifact. A reviewed updater must independently retrieve the bytes
from the official origin, verify the canonical manifest, digest, release
signature, platform signature/notarization, and OS installation policy. Peer
input never authorizes scripts, WASM, native libraries, UI blobs, or executable
code.

## FFI and release gate

The C ABI exposes only the static canonical protocol identifier. It does not
expose setters that can manufacture verified handshakes, sessions, envelopes,
or updates.

Production P2P remains disabled until the official Shared Auth client and
device-bound verifier are publicly consumable, platform permission and privacy
reviews are complete, and interoperable hostile tests/fuzzing have passed in
`hhm-interfaces`, `hhm-flutter`, and this repository.
