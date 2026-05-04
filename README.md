# Tyr-Crypto
Experimental Nim crypto toolkit for the sibling repos in this workspace.

## Warning
This repository is not production-ready.

- It contains custom cryptographic implementations and repo-specific constructions.
- APIs and internal layouts may still change.
- If you need hardened production crypto, use audited upstream libraries and standardized protocols directly.

## Current Shape
`src/tyr_crypto.nim` exports the current public surface:

- `algorithms`
- `basic_api`
- custom pure-Nim modules:
  `random`, `blake3`, `gimli_sponge`, `sha3`, `poly1305`, `mceliece`, `otp`, `hmac`
- `signature_support`

The canonical wrapper layer is [basic_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/basic_api.nim).
There is no generic material/inference layer anymore.

`custom_crypto/` now splits implementation code by primitive class:

- `symmetric/` for hashes, MACs, RNG, stream/block helpers, and OTP utilities
- `asymmetric/pq/` for post-quantum KEM/signature implementations
- `asymmetric/none_pq/` reserved for non-PQ asymmetric implementations

The old top-level module names under `custom_crypto/` remain as compatibility facades.

## Repo Boundary
This repo owns:

- typed single-algorithm crypto wrappers
- pure-Nim crypto helpers and experiments
- optional native bindings and builders
- wasm/JS bridge for the currently exported basic surfaces
- regression/vector tests for the crypto primitives

This repo does not own:

- application protocols
- certificate policy
- transport/session orchestration
- account or database state
- key management infrastructure outside these local wrappers

## Canonical API
Use typed materials from [basic_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/basic_api.nim).

Main operation families:

- `hash`
- `hmac`
- `authenticate`
- `sign`
- `verify`
- `encrypt`
- `decrypt`
- `seal`
- `open`
- `asymKeypair`
- `symEnc` / `symDec`
- `hmacCreate` / `hmacAuth`
- `asymEnc` / `asymDec`
- `asymSign` / `asymVerify`
- `cryptoRand`

## `Tyr` Suffixes
Local custom implementations now expose `Tyr`-suffixed names so they are easy to distinguish from backend-backed paths.

Examples in [basic_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/basic_api.nim):

- `blake3TyrHashM`
- `gimliTyrHashM`
- `sha3TyrHashM`
- `blake3TyrHmacM`
- `gimliTyrHmacM`
- `poly1305TyrHmacM`
- `sha3TyrHmacM`
- `xchacha20TyrCipherM`
- `chacha20TyrCipherM`
- `aesCtrTyrCipherM`
- `gimliStreamTyrCipherM`
- `mceliece0TyrSendM` / `mceliece0TyrOpenM`
- `mceliece1TyrSendM` / `mceliece1TyrOpenM`
- `mceliece2TyrSendM` / `mceliece2TyrOpenM`

The old unsuffixed McEliece materials still exist and remain the `liboqs`-backed path.
The `Tyr`-suffixed McEliece materials are the pure-Nim path.

The custom module facades also expose `Tyr`-suffixed proc aliases such as:

- `blake3TyrHash`
- `gimliTyrXof`
- `sha3TyrHash`
- `shake256Tyr`
- `poly1305TyrTag`
- `chacha20TyrXor`
- `xchacha20TyrXor`
- `aesCtrTyrXor`

## Current Pure-Nim Algorithms
Current local/custom implementations include:

- BLAKE3
- Gimli sponge, tag, and stream helpers
- SHA3-224 / 256 / 384 / 512
- SHAKE256
- Poly1305
- AES-CTR
- ChaCha20 / HChaCha20 / XChaCha20
- Classic McEliece `6688128f`, `6960119f`, `8192128f`
- NTRU HPS/HRSS KEMs: `ntruhps2048509`, `ntruhps2048677`, `ntruhps4096821`, `ntruhrss701`
- SABER KEMs: `lightsaber`, `saber`, `firesaber`
- OTP helpers

## Optional Backend Paths
Some surfaces still depend on optional native libraries:

- `libsodium`
  - X25519
  - Ed25519
  - some compatibility/authentication helpers
- `liboqs`
  - Kyber
  - Frodo
  - NTRU Prime
  - BIKE
  - Falcon
  - Dilithium
  - SPHINCS+
- `OpenSSL`
  - Ed448
- `nimcrypto`
  - AES-GCM binding/tests

Missing optional libraries should raise explicit `LibraryUnavailableError`, not silently fall back.

PQClean reference bindings for NTRU/SABER live under `src/protocols/bindings` and point at the pinned `submodules/pqclean` submodule; the normal custom NTRU/SABER APIs use the pure-Nim implementations under `custom_crypto/asymmetric/pq/`.

NTRU now defaults to a KAT-compatible pure-Nim Toom-4 plus two-level Karatsuba multiplier ported from the PQClean performance shape. The exact-int64 Toom-4 path remains available with `-d:ntruMulToom4`, the previous coefficient path with `-d:ntruMulCoeff`, the original temp/reduce path with `-d:ntruMulTmp`, and the row-style trials with `-d:ntruMulRows` / `-d:ntruMulRowsUnroll4`. SABER kept its original temp/reduce multiplier because the tested split-loop and Toom variants regressed; those experiments remain opt-in via `-d:saberMulToom4`, `-d:saberMulToom4Mod`, and `-d:saberMulToom4Cached`.

## Workspace Dependencies
The repo uses local workspace helper repos in addition to the native-library submodules:

- `SIMD-Nexus`
  - SIMD helpers used by the local accelerated paths
- `Sigma-BenchAndEval`
  - benchmarking helpers for the Sigma perf tasks
- `Otter-RepoEvaluation`
  - timing instrumentation for `otterBench`, `otterSpan`, and the Otter perf tasks

The `submodules/` folder is expected to mirror the shared workspace with local junctions during development.
The corresponding manifest entries live in [.gitmodules](f:/CodingMain/Tyr-Crypto/.gitmodules).

## Quick Start
### Typed hash
```nim
import tyr_crypto

let digest = hash(@[byte 1, 2, 3], blake3TyrHashM())
doAssert digest.len == 32
```

### Typed cipher
```nim
import tyr_crypto

var
  m: xchacha20TyrCipherM
  msg = @[byte 1, 2, 3, 4]

for i in 0 ..< m.key.len:
  m.key[i] = 0x11'u8
for i in 0 ..< m.nonce.len:
  m.nonce[i] = 0x22'u8

let cipher = encrypt(msg, m)
doAssert decrypt(cipher, m) == msg
```

### Pure-Nim McEliece
```nim
import tyr_crypto

let kp = asymKeypair(mceliece0TyrSendM)

var
  sendM: mceliece0TyrSendM
  openM: mceliece0TyrOpenM

for i in 0 ..< sendM.receiverPublicKey.len:
  sendM.receiverPublicKey[i] = kp.publicKey[i]
for i in 0 ..< openM.receiverSecretKey.len:
  openM.receiverSecretKey[i] = kp.secretKey[i]

let env = seal(sendM)
let shared = open(env, openM)
doAssert shared == env.sharedSecret
```

## Wasm / JS
The wasm bridge is basic-only.

Current exported wasm/JS operations:

- `basic.encrypt`
- `basic.decrypt`
- `blake3Hash`
- `blake3KeyedHash`
- `gimliHash`
- `sha3Hash`
- `capabilities`

Relevant files:

- [types.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm/level0/types.nim)
- [json_codec.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm/level1/json_codec.nim)
- [json_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm/level2/json_api.nim)
- [exports.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm/exports.nim)
- [tyr_crypto.mjs](f:/CodingMain/Tyr-Crypto/bindings/js/tyr_crypto.mjs)
- [tyr_crypto.d.ts](f:/CodingMain/Tyr-Crypto/bindings/js/tyr_crypto.d.ts)

## Layout
- [src/tyr_crypto.nim](f:/CodingMain/Tyr-Crypto/src/tyr_crypto.nim)
  public export surface
- [basic_api.nim](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/basic_api.nim)
  canonical typed wrapper API
- [src/protocols/custom_crypto/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto)
  compatibility facades plus the implementation roots below
- [src/protocols/custom_crypto/symmetric/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto/symmetric)
  symmetric/hash/MAC/random/OTP implementations
- [src/protocols/custom_crypto/asymmetric/pq/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto/asymmetric/pq)
  post-quantum KEM/signature implementations
- [src/protocols/custom_crypto/asymmetric/none_pq/](f:/CodingMain/Tyr-Crypto/src/protocols/custom_crypto/asymmetric/none_pq)
  reserved slot for future non-PQ asymmetric implementations
- [src/protocols/bindings/](f:/CodingMain/Tyr-Crypto/src/protocols/bindings)
  optional native bindings
- [src/protocols/wrapper/wasm/](f:/CodingMain/Tyr-Crypto/src/protocols/wrapper/wasm)
  wasm bridge
- [.iron/meta/registry.nim](f:/CodingMain/Tyr-Crypto/.iron/meta/registry.nim)
  primitive backend metadata
- [tests/](f:/CodingMain/Tyr-Crypto/tests)
  vectors and regression tests

## Commands
Common repo commands from [tyr_crypto.nimble](f:/CodingMain/Tyr-Crypto/tyr_crypto.nimble):

```bash
nimble test
nimble test_all
nimble test_wasm
nimble test_gimli
nimble test_blake3_simd
nimble test_neon_checks
nimble test_simd_matrix
nimble build_android_harness
nimble build_android_harness_asymmetric_fast
nimble build_android_harness_asymmetric_full
nimble build_wasm
nimble build_libsodium
nimble build_liboqs
nimble bench_pq_profiles
nimble build_openssl
```

Direct focused checks that are often useful:

```bash
nim check src/tyr_crypto.nim
nim check src/protocols/wrapper/basic_api.nim
nim c --nimcache:build/nimcache_test_all -r tests/test_all.nim
```

## Current Validation Highlights
The suite currently includes:

- known-answer tests for BLAKE3, SHA3, and Poly1305
- scalar/SIMD parity tests for BLAKE3, Gimli, SHA3, and Poly1305
- ARM64/NEON compile-check coverage for the SIMD/custom-crypto matrix plus
  X25519, Kyber, Dilithium, SPHINCS, and McEliece asymmetric paths
- wrapper-layer dispatch tests
- wasm bridge tests
- pure-Nim `mceliece0Tyr` roundtrip coverage
- pure-Nim NTRU and SABER roundtrip/KAT coverage, including AVX2 parity where supported

## Android Harness
- `tests/android_harness`
  - minimal Android app that executes the packaged native Tyr test binary and
    writes the captured output to `files/last_test_output.txt`
- `tests/test_android_custom_crypto.nim`
  - Android-targeted subset covering custom crypto plus SIMD/NEON checks
- `tests/test_android_asymmetric_fast.nim`
  - Android-targeted reduced asymmetric/PQ subset for quicker phone validation,
    including a Falcon-512 smoke subset instead of the full Falcon suite
- `tests/test_android_asymmetric_crypto.nim`
  - Android-targeted full asymmetric/PQ bundle including Frodo, SPHINCS+, and McEliece
- `tools/build_android_harness.ps1`
  - cross-compiles the selected ARM64 and x86_64 native harness binaries and builds the APK
- `tools/run_android_harness.ps1`
  - installs, launches, polls for completion, and prints the captured app output for one connected device

Typical flow:
```bash
nimble build_android_harness
powershell -NoProfile -ExecutionPolicy Bypass -File tools/run_android_harness.ps1 -Serial ZY22K9DZG9
```

Asymmetric/PQ harness flows:
```bash
nimble build_android_harness_asymmetric_fast
powershell -NoProfile -ExecutionPolicy Bypass -File tools/run_android_harness.ps1 -Serial ZY22K9DZG9 -TimeoutSeconds 900

nimble build_android_harness_asymmetric_full
powershell -NoProfile -ExecutionPolicy Bypass -File tools/run_android_harness.ps1 -Serial ZY22K9DZG9 -TimeoutSeconds 1200
```

Tracing support:
- add `{.otterTrace.}` to top-level routines you want enter/leave markers for
- compile with `-d:otterTrace`
- on Android harness runs, `MainActivity` passes `TYR_OTTER_TRACE_PATH` to the native process

Current result from this workspace:
- Motorola `motorola_edge_50_fusion` ARM64 run passed the custom/SIMD harness,
  including the NEON checks.
- Motorola `motorola_edge_50_fusion` ARM64 direct native runs also passed both
  the reduced asymmetric/PQ bundle and the full asymmetric/PQ bundle.
- Motorola direct ARM64 focused runs also passed the new X25519 `NEON2x` batch
  test and the McEliece roundtrip test after the latest phone-oriented NEON pass.
- Host and Motorola revalidation also passed after the SPHINCS 2-lane batching
  and Kyber SSE2 cached-basemul expansion pass.
- The x86_64 emulator app launches, but the packaged x86_64 native harness exits
  with code `139`, so the emulator path still needs follow-up.

## Notes
- Endianness is handled explicitly in the local implementations.
- Constant-time comparisons are used where detached tags/signatures are checked in local code.
- The custom algorithms are still experimental even when tests pass.

Read [CONTRIBUTING.md](f:/CodingMain/Tyr-Crypto/CONTRIBUTING.md) before changing behavior.
