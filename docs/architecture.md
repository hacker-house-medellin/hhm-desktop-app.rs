# Architecture

```text
Slint/winit skin       Flutter desktop       future native skin
       |                     |                       |
       +------------- stable C ABI ----------------+
                             |
                      display-safe state
                             |
            +----------------+----------------+
            |                |                |
      Shared Auth       HHM API adapter   BLE/QR adapters
      public client      (authoritative)    (untrusted hints)
```

## Ownership

- `src/domain.rs` owns deterministic, UI-independent display state and the
  fail-closed eligibility hint for *requesting* a presence transition.
- `src/ffi.rs` owns the stable cross-language boundary, allocation ownership,
  integer validation, synchronization, JSON snapshot, and panic containment.
- `src/auth.rs` validates non-secret configuration for the future official
  Shared Auth adapter. Authentication remains unavailable until its typed
  client artifact is publicly consumable; this module does not parse or verify
  tokens and cannot attach the server-only introspection credential.
- `src/observability.rs` owns bounded Ores/OpenTelemetry events.
- `src/doorway.rs` applies explicit local collection policy to the canonical
  managed-doorway contract. It requires a signed short-lived beacon challenge,
  separately keyed corroboration, backend nonce, desktop device
  attestation/signature verification, and exact backend-decision binding. It is
  intentionally not exposed through the C ABI.
- `src/p2p.rs` applies desktop consent, session, replay/rate, and signed-update
  and closed-JSON policy over the exact `hhm-interfaces` wire types. It owns no
  transport, cryptographic keys, decryption, artifact download, code loading,
  or installer behavior.
- `src/main.rs` and `ui/app.slint` are the first UI skin. They do not own
  identity, product authorization, or door-transition decisions.

## Planned adapters

Network, secure-storage, Supabase PKCE, native passkey, QR image, and BLE
implementations should be separate adapters behind domain-facing traits. A
platform adapter may keep a short-lived user token in platform secure storage,
but it must not copy that token into the domain snapshot, Slint properties,
logs, metrics, crash reports, or the C ABI.

The HHM backend remains authoritative for presence transitions. A managed-door
observation carries a fresh backend nonce, an enrolled-device signature, the
previous monotonic sequence, a signed doorway challenge, and proof from an
independently keyed door controller/NFC/UWB/local-network source. The UI changes
to a completed state only for an exact, next-sequence backend `accepted`
decision; ambiguous direction requires confirmation. Bluetooth events and QR
scans are inputs, never identity, exact human location, door authorization, or
the completion record.

## Relationship to hhm-flutter

Flutter may use this library on desktop through `dart:ffi`, or may implement the
same public interfaces with its own Dart clients. Sharing the C ABI is useful
for security-sensitive state-machine behavior and native integrations; sharing
visual widgets is not required. Both apps should consume the authoritative HHM
interfaces and generated clients declared through Zed.
