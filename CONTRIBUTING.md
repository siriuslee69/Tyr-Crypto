# Contributing to Tyr-Crypto

## Purpose
Tyr-Crypto is the workspace crypto primitive repo.

Keep changes inside that boundary:

- typed crypto wrappers
- pure-Nim crypto implementations
- optional backend bindings
- wasm/JS bridge code
- regression/vector tests
- build helpers for native dependencies

Do not put application protocol logic here.

## Read First
Before changing anything substantial, read:

- [README.md](f:/CodingMain/Tyr-Crypto/README.md)
- [src/tyr_crypto.nim](f:/CodingMain/Tyr-Crypto/src/tyr_crypto.nim)
- [basic_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/basic_api.nim)
- [src/protocols/custom_crypto/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto)
- [.iron/meta/registry.nim](f:/CodingMain/Tyr-Crypto/.iron/meta/registry.nim)
- [tests/test_all.nim](f:/CodingMain/Tyr-Crypto/tests/test_all.nim)

If the change touches wasm/JS:

- [json_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm/level2/json_api.nim)
- [exports.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm/exports.nim)
- [tyr_crypto.mjs](f:/CodingMain/Tyr-Crypto/bindings/js/tyr_crypto.mjs)
- [tyr_crypto.d.ts](f:/CodingMain/Tyr-Crypto/bindings/js/tyr_crypto.d.ts)

## Current Architecture
- [basic_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/basic_api.nim) is the canonical public wrapper surface.
- `modern_api` is gone.
- `Tyr`-suffixed material aliases identify local custom implementations.
- Unsuffixed backend-backed materials may still coexist where Tyr also exposes a pure-Nim alternative.
- `custom_crypto/` is organized by algorithm family with small compatibility facades at the top level.

## Rules
- Preserve explicit endianness in crypto code. Do not rely on host-endian memory casts for protocol-critical state.
- Treat side-channel exposure as a first-class constraint.
  Use branchless comparisons or mask-based selection where secrets are involved.
- Prefer small, parameterized shared modules over copy-pasted per-tier variants.
- If you add a custom algorithm:
  add the scalar implementation first.
  add vector/known-answer tests.
  add SIMD parity tests if you add a SIMD backend.
  wire it into `basic_api` only after the lower layer is stable.
- If you add a new local custom material object or alias, give it a `Tyr`-suffixed name.
- Keep optional backend paths optional. Missing libraries should fail clearly.
- Do not silently replace a backend path with a custom one unless the public API name makes that explicit.

## High-Risk Areas
- [basic_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/basic_api.nim)
  typed public wrapper surface
- [src/protocols/custom_crypto/mceliece/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto/mceliece)
  large pure-Nim KEM implementation
- [src/protocols/custom_crypto/sha3/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto/sha3)
  Keccak/SHA3/SHAKE code
- [src/protocols/custom_crypto/poly1305/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto/poly1305)
  one-time authenticator and SIMD batch path
- [src/protocols/custom_crypto/hmac.nim](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto/hmac.nim)
  generic HMAC orchestration over custom backends
- [src/protocols/bindings/](f:/CodingMain/Tyr-Crypto/src/protocols/bindings)
  dynamic loading and native ABI assumptions
- [src/protocols/wrapper/wasm/](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm)
  public wasm ABI

## Testing Expectations
At minimum, run the smallest relevant checks.

Common commands:

```bash
nim check src/protocols/wrapper/basic_api.nim
nimble test
```

For broader validation:

```bash
nimble test_all
nimble test_wasm
nimble test_gimli
nimble test_blake3_simd
```

For custom algorithm work:

- run the dedicated algorithm test file
- run the SIMD parity file if one exists
- run [test_primitives_api.nim](f:/CodingMain/Tyr-Crypto/tests/test_primitives_api.nim) if dispatch behavior changed
- run [test_quick_api.nim](f:/CodingMain/Tyr-Crypto/tests/test_quick_api.nim) if typed material/layout behavior changed
- run [test_all.nim](f:/CodingMain/Tyr-Crypto/tests/test_all.nim) before closing out a larger refactor

## Review Checklist
- Does the change stay inside Tyr-Crypto’s repo boundary?
- Is the custom-vs-backend distinction still obvious in names and docs?
- Are secret-dependent branches avoided where practical?
- Are endianness-sensitive loads/stores explicit?
- Are output lengths and material sizes validated?
- Are new vectors or parity tests added where needed?
- If wasm/JS changed, were both the Nim and JS/TS sides updated together?
- Are README and CONTRIBUTING still accurate after the change?

## Documentation Rules
- Update [README.md](f:/CodingMain/Tyr-Crypto/README.md) when the public surface changes.
- Update this file when contributor workflow or architecture expectations change.
- Keep examples aligned with the actual exported API.
- Remove stale references instead of leaving “temporary” legacy docs around.

## Native Builders
Builder tasks live in [tyr_crypto.nimble](f:/CodingMain/Tyr-Crypto/tyr_crypto.nimble) and [tools/](f:/CodingMain/Tyr-Crypto/tools).

When touching backend loaders/builders, validate the corresponding paths:

```bash
nimble build_libsodium
nimble build_liboqs
nimble build_openssl
```

## License
Contributions are expected to follow the repo’s existing `Unlicense` model unless stated otherwise.
