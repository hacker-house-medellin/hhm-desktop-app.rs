# Portable peer-to-peer protocol v1

The Rust desktop and Flutter apps share
[`contracts/p2p-v1.schema.json`](../contracts/p2p-v1.schema.json) and its
synthetic fixtures. BLE is one possible discovery/transport layer; it is not a
trust source, authentication factor, authorization grant, or reliable proof of
distance or doorway crossing.

## Session gate

1. The user opts in and explicitly selects one displayed peer.
2. Consent is local, peer-specific, revocable, and expires within five minutes.
3. A session offer binds protocol version, both device public-key fingerprints,
   a 128-bit session ID, a 256-bit challenge nonce, issue/expiry times, and a
   device-bound signature.
4. The reviewed crypto adapter validates the device binding and Shared Auth
   session policy. `invalid` and `unavailable` both fail closed; the domain
   preserves the distinction for diagnostics.
5. A session lasts at most 15 minutes and must be re-established after expiry.

There is no production crypto adapter in this scaffold. The contract does not
parse Shared Auth tokens, mint a verified outcome, or simulate success.

## Envelopes

Every envelope binds the selected peer, session, strictly increasing sequence,
short expiry, 192-bit AEAD nonce, allowlisted kind, ciphertext, and device
signature. The crypto adapter must authenticate both the signature and the
end-to-end encrypted payload before the guard commits replay/rate state.

Bounds:

- ciphertext: 1–32 KiB;
- expiry: no more than 60 seconds and never beyond session expiry;
- rate: 30 messages and 256 KiB per rolling minute;
- remembered nonce replay set: 128 entries, in addition to monotonic sequence;
- payload kinds: presence request *hint*, house notice, resident message.

Presence hints still require a fresh authoritative HHM backend request. The
protocol has no payload kinds for access/refresh tokens, cookies, private keys,
passwords, OTPs, camera/video, conversations/audio, precise location, biometric
material, visitor QR bearer values, or arbitrary executable data. Applications
must not tunnel those values inside an allowlisted ciphertext kind.

## Peer update discovery

A peer may advertise signed metadata only: monotonically increasing release
sequence, display version, manifest SHA-256, artifact SHA-256, project release
key identifier, and signature. The policy requires the pinned project release
key and rejects equal/older sequences.

Acceptance returns metadata, never a URL, artifact bytes, script, dynamic
library, or install instruction. An official updater must independently fetch
the manifest/artifact from its configured trusted origin, verify both digests
and the pinned release signature, enforce platform/channel policy, and use the
normal reviewed installer. Peer-supplied code is never loaded or executed.

## FFI

The stable C ABI exposes only `hhm_desktop_p2p_protocol_version()`. Session,
crypto, and envelope mutation are not exposed until the official device-bound
crypto adapter exists, preventing foreign callers from manufacturing a
`verified` state. This additive function advances the ABI from 1.0 to 1.1.
