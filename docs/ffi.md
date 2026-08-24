# C ABI contract

ABI version `0x0001_0001` means major 1, minor 1. Consumers must reject an
unknown major version. A compatible additive change increments the minor
portion; removing or changing an exported symbol, type width, ownership rule,
or semantic invariant increments the major portion.

`hhm_desktop_p2p_protocol_version()` returns the portable schema/policy version
without exposing a way to forge peer consent or cryptographic verification.

## Ownership and threading

- `hhm_desktop_handle_new` returns a unique opaque handle or null.
- `hhm_desktop_handle_free` accepts null. A non-null handle must be freed once,
  after all concurrent calls using it have finished.
- `hhm_desktop_snapshot_json` writes an allocated UTF-8 C string on success.
- `hhm_desktop_string_free` accepts null. A returned string must be freed once
  by the same loaded library that allocated it.
- Handles synchronize state internally and may be called from multiple threads;
  disposal still requires external synchronization.

Every integer input is range-checked. The setters do not accept a Rust enum at
the ABI boundary because a foreign invalid enum discriminant would be undefined
behavior before Rust could validate it. `HhmDesktopStatus_PanicContained`
indicates a recoverable Rust panic was stopped at the boundary.

## State values

Authentication display state:

- `0`: anonymous
- `1`: unauthenticated
- `2`: degraded/unavailable authority
- `3`: authenticated

HHM product access:

- `0`: unknown
- `1`: denied
- `2`: allowed

Door proximity:

- `0`: unknown/no opt-in signal
- `1`: outside range
- `2`: nearby

QR lease:

- `active=0`: clear the safe lease metadata
- `active=1`, `purpose=0`: visitor sign-in, with 1–60 seconds remaining
- `active=1`, `purpose=1`: visitor sign-out, with 1–60 seconds remaining

The QR function does not accept the opaque QR payload. A rendering adapter must
keep that short-lived bearer value out of this state/telemetry interface.

## Header validation

`include/hhm_desktop.h` is generated from `src/ffi.rs` with cbindgen 0.29.4.
`just ffi-check` generates a second copy, compares it byte-for-byte, and parses
the committed header as strict C11 with warnings denied.
