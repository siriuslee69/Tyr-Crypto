# Security

## Status

Tyr-Crypto is experimental software.

- It may **not** be production ready.
- It comes with **no warranties or guarantees**.
- Some modules implement custom or workspace-specific constructions that should not be treated as externally audited.

## Reporting a Vulnerability

- Do not post full exploit details in a public issue if the problem could expose users or secrets.
- Use the maintainer's private or internal channel when one exists.
- If no private channel is available, open a minimal public issue that states a security concern exists and request a private follow-up.

Include:

- affected module or file
- exact compile flags and platform
- reproduction steps
- whether optional native backends are involved
- expected impact

## Current Security Posture

- Wrapper `chacha20` authentication uses keyed BLAKE3.
- Wrapper AES-256-GCM uses authenticated decryption.
- New PIN wrapping defaults to Argon2id-based derivation.
- Legacy wrapped keys without stored PIN KDF parameters still rely on a compatibility fallback during unwrap.
- The `otp` helpers are custom and are not meant as RFC HOTP/TOTP compatibility code.

## Out of Scope

- insecure host environments
- misconfigured native toolchains
- vulnerabilities in third-party dependencies outside the wrapper/builder surface here
- protocol misuse by downstream applications
