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
- `src/auth.rs` owns the public Shared Auth client construction boundary. It
  cannot attach the server-only introspection credential.
- `src/observability.rs` owns bounded Ores/OpenTelemetry events.
- `src/main.rs` and `ui/app.slint` are the first UI skin. They do not own
  identity, product authorization, or door-transition decisions.

## Planned adapters

Network, secure-storage, Supabase PKCE, native passkey, QR image, and BLE
implementations should be separate adapters behind domain-facing traits. A
platform adapter may keep a short-lived user token in platform secure storage,
but it must not copy that token into the domain snapshot, Slint properties,
logs, metrics, crash reports, or the C ABI.

The HHM backend remains authoritative for presence transitions. A transition
request should carry a fresh backend-issued operation identifier and be safe to
retry; the UI changes to a completed state only after the backend confirms the
record. Bluetooth events and QR scans are inputs to that request, never the
completion record.

## Relationship to hhm-flutter

Flutter may use this library on desktop through `dart:ffi`, or may implement the
same public interfaces with its own Dart clients. Sharing the C ABI is useful
for security-sensitive state-machine behavior and native integrations; sharing
visual widgets is not required. Both apps should consume the authoritative HHM
interfaces and generated clients declared through Zed.
