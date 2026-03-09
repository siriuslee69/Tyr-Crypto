# Tyr-Crypto

Experimental Nim crypto toolkit for the sibling repos in this workspace.

## Warning

This repository is **not guaranteed to be production ready**.

- It includes custom cryptographic constructions and pure-Nim implementations that should be treated as experimental until they receive deeper review and external validation.
- This repository is explicitly **vibecoded** experimental crypto code. Expect rough edges, changing APIs, and places that still need deeper review.
- It is provided **without warranties or guarantees of any kind**.
- If you need hardened production crypto, prefer well-reviewed upstream libraries and audited protocol designs.

## What This Repo Owns

- reusable Nim wrappers around optional crypto backends
- pure-Nim helper primitives used by the workspace
- password/PIN-based key derivation and wrapping helpers
- chunked file encryption and hashing helpers
- backend metadata and algorithm registry helpers
- build helpers for optional native dependencies

## What This Repo Does Not Own

- protocol definitions for an application
- certificate lifecycle or trust policy
- network transport/session orchestration
- user/account storage
- key management infrastructure outside the local wrappers in this repo

## Main State Types

- `EncryptionState`
  - wrapper-level symmetric encryption state in `src/tyr_crypto/wrapper/crypto.nim`
- `CipherText`
  - wrapper ciphertext plus authentication material
- `Key`
  - password/PIN-derived wrapping state in `src/tyr_crypto/wrapper/pin_key.nim`
- `DerivedEncryptionKeys`
  - derived symmetric state plus KDF metadata
- `ChunkyOptions` and `ChunkyManifest`
  - chunked file processing config and output manifest
- `SignatureKeypair`
  - wrapper-level signing keypair for classical, PQ, and hybrid signature modes

## Main Orchestrators

- `encrypt` / `decrypt`
  - high-level wrapper entrypoints for symmetric message encryption
- `deriveSymmetricKeysFromBytesWithSalt` / `deriveSymmetricKeysFromString`
  - password-to-wrapper-state derivation
- `deriveMasterKey`, `wrapMasterKeyWithPin`, `unwrapMasterKeyWithPin`
  - password/PIN key lifecycle
- `encryptFileChunks`, `decryptFileChunks`, `hashFileChunks`
  - large-file chunk processing
- `createHybridKexOffer`, `respondHybridKexOffer`, `finalizeHybridKex`
  - hybrid PQ/classical KEX helpers
- `createKyberX25519KexOffer`, `createMcElieceX25519KexOffer`
  - duo hybrid KEX helpers with enum-selected PQ variants
- `signatureKeypair`, `signMessage`, `verifyMessage`
  - unified signature API for Ed25519, PQ signatures, and hybrid signatures

## Loop Entrypoints

- `updateBlake3` / `finalBlake3`
  - streaming hash updates
- `runEncryptTasks` / `runDecryptTasks`
  - chunk worker loops
- `encryptChunkTask`, `decryptChunkTask`, `hashChunkTask`
  - per-chunk file processing loops

## Layout

- `src/tyr_crypto/common.nim`
  - shared error types and helper templates
- `src/tyr_crypto/random.nim`
  - OS randomness with optional extra entropy mixing
- `src/tyr_crypto/registry.nim`
  - metadata for supported algorithms and providers
- `src/tyr_crypto/wrapper/`
  - high-level encryption, PIN/KDF, signatures, and hybrid KEX APIs
- `src/tyr_crypto/custom_crypto/`
  - pure-Nim and SIMD-oriented crypto helpers
- `src/tyr_crypto/chunkyCrypto/`
  - chunked file encryption and hashing
- `src/tyr_crypto/bindings/`
  - optional native bindings
- `tools/`
  - native dependency build helpers
- `tests/`
  - vectors, regressions, and wrapper tests
- `iron/`
  - repo coordination metadata

## Quick Start

### Base build and test

```bash
nimble test
nim check src/tyr_crypto/registry.nim
```

### Enable optional backends

```bash
nimble build -d:hasLibsodium -d:hasLibOqs -d:hasOpenSSL3 -d:hasNimcrypto -d:hasBlake3
```

If a backend is compiled out or missing at runtime, the wrappers raise `LibraryUnavailableError` instead of failing silently.

### Native builder tasks

```bash
nimble build_libsodium
nimble build_liboqs
nimble build_openssl
```

These tasks expect the relevant submodules and a working native build toolchain. On Windows that usually means an MSYS2-style environment plus standard C/C++ build tools.

### Full native-backed test run

```bash
nimble build_libsodium
nimble build_liboqs
nimble build_openssl
nimble test_all
```

`nimble test_all` is the native-backed suite path and is expected to run with `libsodium`, `liboqs`, and OpenSSL enabled.

If you are using submodule-local native builds instead of system-installed libraries, you may need to point the loaders at them with environment variables such as `LIBSODIUM_SOURCE`, `LIBSODIUM_LIB_DIRS`, `LIBOQS_SOURCE`, `LIBOQS_LIB_DIRS`, `OPENSSL_SOURCE`, and `OPENSSL_LIB_DIRS`.

## Examples

### 1. Symmetric wrapper API

```nim
import tyr_crypto/wrapper/crypto

let state = EncryptionState(
  algoType: chacha20,
  keys: @[Key(key: newSeqWith(32, 0x11'u8), keyType: isSym)],
  nonce: newSeqWith(24, 0x22'u8)
)

let msg = @[byte 1, 2, 3, 4]
let cipher = encrypt(msg, state)
let plain = decrypt(cipher, state)
doAssert plain == msg
```

### 2. Password-derived state

```nim
import tyr_crypto/wrapper/pin_key
import tyr_crypto/wrapper/crypto

when defined(hasLibsodium):
  let derived = deriveSymmetricKeysFromString(xchacha20Gimli, "correct horse", @[], 0'u16)
  let cipher = encrypt(@[byte 7, 8, 9], derived.state)
  doAssert decrypt(cipher, derived.state) == @[byte 7, 8, 9]
```

### 3. Chunked file encryption

```nim
import tyr_crypto/chunkyCrypto
import tyr_crypto/wrapper/pin_key
import tyr_crypto/wrapper/crypto

when defined(hasLibsodium):
  let derived = deriveSymmetricKeysFromString(xchacha20AesGimli, "file-passphrase", @[], 64'u16)
  var opt = initChunkyOptions()
  opt.chunkBytes = 64 * 1024
  opt.bufferBytes = 4096

  let manifest = encryptFileChunks("input.bin", "chunks", derived.state, opt)
  decryptFileChunks(manifest, "chunks", "output.bin", derived.state, opt)
```

### 4. Enum-driven hybrid KEX

```nim
import tyr_crypto

when defined(hasLibsodium) and defined(hasLibOqs):
  let duo = createMcElieceX25519KexOffer(mvClassicMcEliece6960119)
  let (duoResp, duoSharedB) = respondMcElieceX25519KexOffer(duo.offer)
  let duoSharedA = finalizeMcElieceX25519Kex(duo, duoResp)
  doAssert duoSharedA == duoSharedB

  let triple = createHybridKexOffer(kvKyber1024, mvClassicMcEliece8192128)
  let (tripleResp, tripleSharedB) = respondHybridKexOffer(triple.offer)
  let tripleSharedA = finalizeHybridKex(triple, tripleResp)
  doAssert tripleSharedA == tripleSharedB
```

### 5. Hybrid KEX with caller-provided entropy

```nim
import tyr_crypto

when defined(hasLibsodium) and defined(hasLibOqs):
  let userEntropy = "mouse-jitter|keypress-latency|request=42"

  let state = createKyberX25519KexOfferWithEntropy(
    kvKyber768,
    userEntropy
  )
  let (resp, sharedB) = respondKyberX25519KexOfferWithEntropy(
    state.offer,
    "server-timing|request=42"
  )
  let sharedA = finalizeKyberX25519Kex(state, resp)
  doAssert sharedA == sharedB
```

These helpers feed liboqs KEM operations from a scoped hybrid RNG path that mixes:

- the normal OS-backed secure random source
- caller-supplied bytes such as user interaction or local event timing
- local process/timing context used as extra diversification

### 6. Hybrid signatures

```nim
import tyr_crypto

when defined(hasLibsodium) and defined(hasLibOqs):
  let kp = signatureKeypair(saEd25519Falcon512Hybrid)
  let msg = @[byte 1, 2, 3, 4]
  let sig = signMessage(saEd25519Falcon512Hybrid, msg, kp.secretKey)
  doAssert verifyMessage(saEd25519Falcon512Hybrid, msg, sig, kp.publicKey)
```

## Custom Wrapper Compositions

- `chacha20`
  - wrapper stream mode currently implemented as `xchacha20Xor(...)` plus a keyed BLAKE3 tag
- `xchacha20Gimli`
  - `XChaCha20 -> Gimli stream -> Gimli tag`
- `aesGimli`
  - `AES-CTR -> Gimli stream -> Gimli tag`
- `xchacha20AesGimli`
  - `XChaCha20 -> AES-CTR -> Gimli stream -> Gimli tag`
- `xchacha20AesGimliPoly1305`
  - `XChaCha20 -> AES-CTR -> Gimli stream -> (Gimli tag || Poly1305 tag)`
- `aes256`
  - AES-256-GCM via the Nimcrypto backend

These wrapper names are repo-specific constructions, not standardized AEAD names. Treat the ciphertext and tag layout as implementation-specific and version-sensitive.

## Hybrid Wrapper Surfaces

- `createKyberX25519KexOffer*` / `respondKyberX25519KexOffer*`
  - `Kyber + X25519`
- `createMcElieceX25519KexOffer*` / `respondMcElieceX25519KexOffer*`
  - `Classic McEliece + X25519`
- `createHybridKexOffer*` / `respondHybridKexOffer*`
  - `Kyber + Classic McEliece + X25519`
- `*WithEntropy` KEX helpers
  - mix OS randomness, caller-provided entropy bytes, and local timing/process context through a scoped liboqs RNG callback
- `saEd25519Falcon512Hybrid` / `saEd25519Falcon1024Hybrid`
  - generate and verify both the Ed25519 and Falcon halves

## Current Crypto Surfaces

- Symmetric wrapper modes
  - `chacha20`
  - `xchacha20Gimli`
  - `aesGimli`
  - `xchacha20AesGimli`
  - `xchacha20AesGimliPoly1305`
  - `aes256`
- Hybrid KEX modes
  - `Kyber + X25519` with `kvKyber768` or `kvKyber1024`
  - `Classic McEliece + X25519` with `mvClassicMcEliece6688128`, `mvClassicMcEliece6960119`, or `mvClassicMcEliece8192128`
  - `Kyber + Classic McEliece + X25519` with enum-selected Kyber and McEliece variants
- Hybrid signature modes
  - `saEd25519Falcon512Hybrid`
  - `saEd25519Falcon1024Hybrid`
  - Hybrid signatures require both the classical and PQ halves to verify

## Native and Disk Boundaries

- Native runtime boundaries
  - `libsodium`, `liboqs`, and OpenSSL are optional dynamic/native dependencies
- Disk boundaries
  - `blake3HashFile`
  - `encryptFileChunks`
  - `decryptFileChunks`
  - `hashFileChunks`
- Repo-local build boundaries
  - `tools/build_libsodium.nim`
  - `tools/build_liboqs.nim`
  - `tools/build_openssl.nim`

## Security Notes

- The wrapper `chacha20` mode now uses a keyed BLAKE3 tag instead of hashing `key || nonce || ciphertext` directly.
- The AES-256-GCM wrapper now uses authenticated decryption instead of decrypt-then-compare.
- PIN wrapping now defaults to Argon2id-based derivation for new keys.
- Older wrapped keys that predate stored PIN KDF parameters still have a legacy unwrap fallback path.
- Hybrid liboqs KEM calls no longer rely only on the liboqs default RNG path; the wrapper now installs a scoped mixed-entropy callback and also exposes `*WithEntropy` helpers for caller-provided material.
- The liboqs RNG hook is process-global, so those hybrid-entropy KEM sections are serialized with a lock while keygen/encapsulation runs.
- `otp.nim` exposes custom deterministic OTP-style helpers. It is **not** an RFC HOTP/TOTP interoperability layer and should not be assumed compatible with authenticator apps.
- Several modules in `custom_crypto/` are implementation experiments first and compatibility surfaces second.

## Licensing

- Original Tyr-Crypto code in this repository is released under the `Unlicense`.
- See `LICENSE` for the full text and `THIRD_PARTY_LICENSES.md` for the dependency summary.
- Checked-out submodules keep their upstream licenses and are **not** relicensed by Tyr-Crypto.
- Top-level submodule licenses currently observed:
  - `libsodium`: ISC
  - `liboqs`: MIT, with per-folder third-party exceptions inside the source tree
  - `OpenSSL`: Apache-2.0
- The checked-out `submodules/openssl/` tree also contains nested helper and test repositories with additional licenses, including GPL/LGPL components such as `tlsfuzzer` and `tlslite-ng`.
- This summary is for repo maintenance and attribution only. It is not legal advice.

## Common Commands

```bash
nimble test
nimble test_all
nimble test_all_threads_on
nimble test_all_threads_off
nimble test_gimli
nimble test_blake3_simd
nimble perf_sigma
```

## Issue Playbook

- `LibraryUnavailableError`
  - You compiled without the matching `-d:has*` flag or the native library is not available at runtime.
- `nimble test` passes but native backends are still unverified
  - The default suite exercises the fallback paths too. Compile with the relevant flags and installed libraries when you need backend-specific validation.
- Chunk hashing is currently serial even when encryption/decryption use worker threads
  - This is intentional for now. The previous ORC/ARC threaded hash path hit ownership corruption with seq payloads, so correctness won over parallelism.
- Builder tasks fail on Windows
  - Check that the submodule exists and that the native toolchain expected by the upstream project is installed.
- OTP output does not match external TOTP apps
  - Expected. The `otp` module is custom and not a drop-in RFC 4226/6238 implementation.

## Development Notes

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before changing behavior. Security reporting guidance lives in [SECURITY.md](./SECURITY.md). Licensing notes for dependencies live in [THIRD_PARTY_LICENSES.md](./THIRD_PARTY_LICENSES.md).

## Conventions Summary

- Keep functions short and compose helpers instead of nesting deeply.
- Declare `var`/`let` blocks near the top of the proc.
- Preserve the level-based module layout under `src/tyr_crypto/`.
- Prefer explicit runtime errors over silent fallback behavior.
- Add or update tests whenever crypto behavior, file formats, or backend wiring changes.
- Update docs when public behavior or repo structure changes.
