# Repository agent instructions

Owner: `hacker-house-medellin`

Read and follow the organization policy in
[`hacker-house-medellin/.github`](https://github.com/hacker-house-medellin/.github),
including semantic conflict resolution and the `dev` integration branch.

- Preserve the separation between the UI skin, domain state, network/auth
  adapters, and `src/ffi.rs`.
- Treat the C ABI as a public compatibility contract. Keep integer inputs
  validated, contain panics, document pointer ownership, increment the ABI
  version for breaking changes, and regenerate `include/hhm_desktop.h`.
- Shared Auth establishes identity and assurance. HHM's backend owns resident,
  visitor, door, and presence authorization. Never treat BLE/proximity as
  authentication or proof that an entry/exit occurred.
- Keep authentication unavailable and fail-closed until a publicly consumable
  official Shared Auth typed-client artifact exists. Never add an ad-hoc token
  parser/verifier, introspection call, private repository credential, or
  production success stub to bypass that release gate.
- Keep P2P BLE transport separate from trust. Require explicit peer consent,
  official device-bound verification, bounded E2E envelopes, expiry/replay/rate
  defense, and pinned official release metadata. Never load peer-supplied code
  or add prohibited secret/surveillance/location payload kinds.
- Never log or place in the ABI snapshot tokens, cookies, QR payloads, beacon
  identifiers, email addresses, provider subjects, service credentials, or
  biometric material.
- Desktop builds are public clients. Never inject a Supabase service-role key,
  Shared Auth introspection credential, signing key, or provider secret.
- Edit tracked environment profiles only through SOPS. Commit ciphertext under
  `env/enc`; never commit a decrypted profile or private age key.
- Use `.zpkg.toml` for cross-repository package intent. Commit `.zpkg.lock`
  only when a real Zed resolver run produces it.
- Run `just verify` for Rust, UI, FFI/header, and encrypted-environment changes.
  Add focused tests for behavior changes and do not bypass checks.
