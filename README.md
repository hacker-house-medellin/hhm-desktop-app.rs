# hhm-desktop-app.rs

Rust-native desktop companion for Hacker House Medellín. It complements
`hhm-flutter` with a native desktop shell and a stable C ABI that Flutter/Dart
FFI or another UI skin can consume.

The first skin uses [Slint](https://slint.dev/) over its winit backend with the
software renderer. It does not use Qt. The domain and FFI library remain
independent from the skin, so a future SwiftUI, GTK, WinUI, webview, or Flutter
shell can reuse the same bounded state contract.

## Current scaffold

| Capability | Status |
|---|---|
| Linux/macOS/Windows native shell | Slint/winit shell compiles; packaging is future work |
| Rust library | `rlib`, `cdylib`, and `staticlib` outputs |
| Dart/other-skin integration | Versioned C ABI plus generated C header |
| Shared Auth | Fail-closed public configuration boundary; official typed client artifact is a release gate |
| Supabase | Documented credential-authority boundary; platform sign-in adapter is future work |
| Visitor sign-in/sign-out QR | Backend-issued 1–60 second lease metadata contract; QR rendering/network adapter is future work |
| Managed doorway | Canonical signed-challenge + separately keyed corroboration gate, exact nonce/decision binding, no FFI exposure; native verifier/signer/API adapters are release gates |
| Portable P2P | Canonical `hhm-interfaces` contract plus stricter consent/session/replay/rate/update and closed-JSON policy; crypto/transport adapters are release gates |
| Observability | Bounded Ores/OpenTelemetry structured transitions, pinned to an immutable Git revision |
| Configuration | SOPS+age ciphertext under `env/enc`, audited through Just and available in a locked Nix shell |

This repository does not yet package installers, scan BLE beacons, draw an
opaque QR payload, or call HHM's presence API. It does validate canonical
managed-doorway and P2P JSON contracts without expanding the stable C ABI.
Hardware, cryptographic, network, and durable backend behavior remain explicit
follow-on adapters, not simulated behavior.

Authentication is also intentionally unavailable in this public build: the
current upstream Shared Auth source cannot be fetched by unauthenticated public
CI. The app does not add a repository token, ad-hoc JWT parser, introspection
call, or production success stub. Shipping authentication is gated on a
publicly consumable official typed client artifact declared through Zed.

## Security model

The app preserves four independent layers:

1. Supabase may perform a provider credential ceremony.
2. Shared Auth verifies/exchanges that provider result and establishes a
   customer-realm identity and assurance outcome.
3. HHM's backend evaluates resident/visitor, door, and presence permissions.
4. Bluetooth proximity is optional context used only to decide whether the
   client may *request* a transition. The backend must still authorize and
   record it.

`anonymous`, `unauthenticated`, and `degraded` remain distinct states. The
desktop app never receives the Shared Auth introspection service credential and
never treats provider metadata, an email address, or proximity as product
authorization. Face/fingerprint ceremonies belong to platform passkeys; raw
biometric material does not enter this process.

Rotating visitor QR payloads are backend-issued bearer material. The safe
domain/FFI snapshot contains only purpose and a bounded remaining lifetime; it
does not accept, persist, serialize, or log the opaque payload.

See [`docs/architecture.md`](docs/architecture.md),
[`docs/ffi.md`](docs/ffi.md), [`docs/p2p.md`](docs/p2p.md), and
[`docs/security.md`](docs/security.md).

## Build and run

Rust 1.92 or newer is required by Slint 1.17.1.

```bash
nix develop ./.nix
cargo run
```

The Nix shell defaults `SLINT_BACKEND` to `winit-software`. Outside Nix:

```bash
SLINT_BACKEND=winit-software cargo run
```

Slint has its own licensing choices and terms. Review the current
[Slint licensing documentation](https://slint.dev/legal/licenses/) before
distributing a packaged application; this repository's own source is MIT.

## C and Dart FFI

The committed header is [`include/hhm_desktop.h`](include/hhm_desktop.h).
Consumers must compare `hhm_desktop_abi_version()` with the major/minor value
they were compiled against, release every handle/string exactly once, and
synchronize disposal with concurrent calls.

The library name is platform-specific:

- macOS: `libhhm_desktop_app.dylib`
- Linux: `libhhm_desktop_app.so`
- Windows: `hhm_desktop_app.dll`

A Dart wrapper should bind the integer-valued inputs and status return values,
copy the UTF-8 JSON snapshot immediately, then call
`hhm_desktop_string_free`. Never pass a token or QR payload through this ABI.

Regenerate and validate the header after a public Rust ABI change:

```bash
just ffi-generate
just ffi-check
```

## Dependency management

Cargo owns Rust compilation and commits `Cargo.lock`. Cross-repository package
intent lives in `.zpkg.toml`: HHM interfaces/clients/sync, Shared Auth clients,
and Ores logging are declared as Zed dependencies installed under
`.vendor/.zed`. A `.zpkg.lock` is committed only after a real successful Zed
resolver run; it is never fabricated from Git metadata.

The Cargo Git dependencies for Ores and the public `hhm-interfaces` contract
are pinned to reviewed immutable commits, so branch movement cannot silently
change a build. Shared Auth remains an official-client Zed dependency and
release gate rather than a private Cargo Git dependency that would require
leaking repository credentials into public CI.

## Encrypted configuration

`env/enc/dev.env.enc` and `env/enc/prod.env.enc` are real SOPS ciphertext with
age recipients from `.sops.yaml`. `.env.example` contains names and non-secret
examples. See [`env/README.md`](env/README.md).

Desktop bundles may contain only public-client values. Supabase service-role
keys, Shared Auth introspection credentials, provider secrets, signing keys,
tokens, cookies, and private age keys are prohibited even when encrypted in the
repository, because the final client binary cannot keep them secret.

## Validation

```bash
just verify
```

This runs formatting, all-target/all-feature compilation and tests, strict
Clippy, RustSec auditing with documented transitive maintenance exceptions,
C-header regeneration comparison, a linked C smoke test, C11 syntax
validation, and the key-independent encrypted-environment audit.
