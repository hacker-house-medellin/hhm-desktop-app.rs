# Encrypted configuration

Tracked environment profiles live only in `env/enc/*.env.enc`. They are SOPS
dotenv documents encrypted to the public age recipients in `.sops.yaml`; age
private keys and decrypted files are never committed.

Use the pinned development shell and task runner:

```bash
nix develop ./.nix
just env-check
just env-edit dev
just env-rekey
```

`just env-edit` decrypts in the editor process and writes ciphertext back.
`just env-rekey` updates recipient metadata after a reviewed change to
`.sops.yaml`. CI runs `just env-check` without a private key: it verifies that
the tracked profiles are encrypted, have a SOPS MAC, and have at least two
recovery recipients.

## Desktop secret boundary

This repository may name public endpoints, audience/client identifiers, and a
Supabase publishable key. It must never contain or receive a Supabase service
role key, Shared Auth introspection credential, signing key, provider secret,
refresh token, access token, cookie, raw QR payload, or private age key.

Production values should normally be injected by the release system after SOPS
decryption or by the platform's secret/configuration service. Encryption in Git
protects review and transport; it does not make a value safe to embed in a
desktop binary. Only public-client configuration belongs in an app bundle.
