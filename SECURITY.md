# Security policy

Report vulnerabilities privately through this repository's **Security** tab.
Do not open a public issue containing exploit details, credentials, tokens, QR
payloads, beacon identifiers, resident/visitor data, or camera/audio content.

Supported security fixes target the latest release and the current `dev`
integration branch. A report should include the affected commit/version,
platform, minimal reproduction without real user data, impact, and any known
mitigation.

If a credential appears in a report, log, commit, or screenshot, treat it as
compromised and ask an authorized human operator to rotate or revoke it through
the owning system. Automated contributors must not rotate production
credentials or rewrite repository history.
