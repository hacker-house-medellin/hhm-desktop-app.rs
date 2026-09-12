# Security and privacy boundaries

## Authentication and authorization

- Use the customer Shared Auth realm with an exact issuer, audience, authorized
  public client, asymmetric algorithm/key, expiry/not-before, scopes, session,
  and route-specific assurance policy.
- Supabase may establish a provider identity, but the verified
  `(provider, provider_tenant, provider_subject)` tuple is resolved by Shared
  Auth. Never link or authorize by matching an email address.
- Keep `anonymous`, definitely invalid (`unauthenticated`), and authority outage
  (`degraded`) distinct. Privileged work fails closed in all three states.
- HHM's backend owns household membership, roles, visitor grants, doors,
  presence records, and resource authorization.
- This public client must not call protected introspection because it cannot
  safely hold the independent service credential. Use the official public
  exchange/verify flow and backend guards.
- Authentication remains fail-closed and unavailable until the official typed
  Shared Auth client is published in a form public CI can consume. Do not add an
  ad-hoc JWT/JWKS parser, token-verification implementation, private repository
  credential, introspection call, or production success stub to bypass that
  release gate.

## QR and proximity

- Visitor sign-in and sign-out QR values are generated and signed by the
  backend, expire within one minute, bind to a purpose/door/nonce, and are
  consumed once through an idempotent backend operation.
- Clients do not generate trust-bearing QR values. Screenshots/replays must be
  rejected by expiry, signature, purpose, and one-time consumption checks.
- BLE is opt-in, revocable, and permission-gated. It is a noisy proximity
  signal, not identity, assurance, authorization, or proof that a person
  crossed a doorway.
- A presence change is shown as completed only after the backend confirms its
  authoritative record.
- P2P requires explicit peer selection, short-lived consent/session state,
  device-bound cryptographic verification, allowlisted E2E-encrypted envelopes,
  and expiry/replay/rate limits. Invalid or unavailable crypto fails closed.
- Peer update discovery carries signed digests/sequence metadata only. A pinned
  official release key and anti-rollback check are mandatory; peer-provided
  artifact bytes, URLs, scripts, libraries, or install instructions are never
  accepted or executed.

## Sensitive data

Never place access/refresh tokens, cookies, provider credentials, service
credentials, QR payloads, raw beacon identifiers, names, email addresses,
provider subjects, conversations, camera/audio content, or biometric material
in domain snapshots, FFI values, logs, traces, metrics, crash reports, URLs, or
fixtures.

Camera and conversation recording are outside this desktop scaffold. Any future
integration requires an explicit lawful basis, visible consent/notice,
room-specific minimization, retention/deletion controls, access audit, encrypted
transport/storage, and a reviewed backend contract. Raw biometric templates are
prohibited; platform passkeys carry opaque signed WebAuthn assertions instead.

## Observability

Ores events use fixed event names and low-cardinality enum outcomes. The local
Ores transport is bridged into Rust tracing so a deployment-controlled collector
can export it. Collector credentials must be injected outside the app bundle;
the desktop binary must never contain OTLP authorization headers.

## Dependency audit

`just audit` denies every RustSec vulnerability and warning except four
explicitly reviewed *unmaintained* notices currently inherited through Slint's
UI/compiler graph: RUSTSEC-2025-0141 (`bincode`), RUSTSEC-2024-0436 (`paste`),
RUSTSEC-2026-0206 (`rustybuzz`), and RUSTSEC-2026-0192 (`ttf-parser`). They are
not vulnerability advisories, but each exception must be re-evaluated whenever
Slint or the renderer/compiler dependencies change. New advisories fail CI.

Report vulnerabilities privately through GitHub's Security tab. Do not place
credential material or exploit details in a public issue.
