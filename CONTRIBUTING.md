# Contributing to Tyr-Crypto

## Purpose

This repo exists to provide reusable crypto primitives, wrappers, and build helpers for the other Nim repos in this workspace. Keep changes focused on that boundary.

## What Belongs Here

- Nim wrappers over optional crypto backends
- pure-Nim helper implementations used inside the workspace
- key derivation, wrapping, signature, and KEX helpers
- chunked file encryption and hashing helpers
- backend metadata, build helpers, and regression tests
- documentation for safe use and repo structure

## What Does Not Belong Here

- application protocol logic
- user/session orchestration
- account/database storage
- transport/client/server state machines
- unaudited crypto redesigns without tests and rationale

## Read These Files First

- `README.md`
- `src/tyr_crypto/wrapper/crypto.nim`
- `src/tyr_crypto/wrapper/pin_key.nim`
- `src/tyr_crypto/chunkyCrypto/level2/file_ops.nim`
- `src/tyr_crypto/registry.nim`
- `tests/test_all.nim`

## High-Risk Areas

- `src/tyr_crypto/wrapper/crypto.nim`
  - public symmetric API surface
- `src/tyr_crypto/wrapper/pin_key.nim`
  - password/PIN derivation and key wrapping
- `src/tyr_crypto/chunkyCrypto/level2/file_ops.nim`
  - file format, disk I/O, threading behavior
- `src/tyr_crypto/custom_crypto/`
  - custom primitives and SIMD paths
- `src/tyr_crypto/bindings/`
  - native ABI assumptions and failure handling

## Rules for Changes

- Prefer existing audited upstream primitives over inventing new constructions.
- If you change authentication, key derivation, or ciphertext layout, add a regression test.
- Keep optional backends optional. A missing library should fail clearly, not break unrelated builds.
- Preserve Windows and Linux friendliness where practical.
- If a change affects how callers should use the repo, update `README.md`.
- If a change affects maintainers or reviewers, update this file too.

## Review Checklist

- Does the change stay inside Tyr-Crypto's repo boundary?
- Are error cases explicit and descriptive?
- Did you avoid weakening an existing security property?
- Did you avoid changing serialized/file output formats accidentally?
- Are new code paths covered by tests?
- If a threaded path changes, is ownership/memory behavior still safe under ORC/ARC?
- Are docs aligned with the actual behavior?

## Commands to Run

```bash
nimble test
nim check src/tyr_crypto/registry.nim
```

Run additional commands when relevant:

```bash
nimble test_all
nimble test_all_threads_on
nimble test_all_threads_off
nimble test_gimli
nimble test_blake3_simd
nimble perf_sigma
```

## Optional Backend Validation

When touching a backend-specific path, validate with the corresponding build flags and installed libraries where possible:

```bash
nimble build -d:hasLibsodium -d:hasLibOqs -d:hasOpenSSL3 -d:hasNimcrypto
```

## Documentation Expectations

- `README.md` should explain repo boundary, major state types, orchestrators, and examples.
- `SECURITY.md` should stay honest about production readiness and reporting.
- Keep the issue playbook in the README current when new recurring failure modes appear.

## Contribution License

- Unless explicitly stated otherwise, contributions intended for Tyr-Crypto are accepted under the same license as the repo's original code: `Unlicense`.
- Do not copy third-party code into the repo without preserving its original notices and updating `THIRD_PARTY_LICENSES.md` when needed.
- Submodules, vendored upstream code, and generated native artifacts keep their upstream licenses.
