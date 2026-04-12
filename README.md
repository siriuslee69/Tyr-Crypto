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
- backend metadata helpers stored under `.iron/meta/`
- build helpers for optional native dependencies

## What This Repo Does Not Own

- protocol definitions for an application
- certificate lifecycle or trust policy
- network transport/session orchestration
- user/account storage
- key management infrastructure outside the local wrappers in this repo

## Main State Types

- `SymAuthState`
  - enum-driven authenticated symmetric state in `src/protocols/wrapper/suite_api.nim`
- `SymAuthCipher`
  - ciphertext plus detached authentication material from `suite_api`
- `Key`
  - password/PIN-derived wrapping state implemented in `src/protocols/wrapper/password_support.nim` and exposed through the base/top-level API
- `DerivedEncryptionKeys`
  - derived symmetric state plus KDF metadata
- `ChunkyOptions` and `ChunkyManifest`
  - chunked file processing config and output manifest
- `SignatureKeypair`
  - signing keypair for classical, PQ, and composed signature modes
## Main Orchestrators

- `hash` / `verify` / `sign` / `seal` / `open` / `encrypt` / `decrypt`
  - typed single-algorithm entrypoints exposed by `basic_api`
- `symEnc` / `symDec`
  - clean enum-driven pure symmetric dispatch surface
- `hmacCreate` / `hmacAuth`
  - clean enum-driven custom HMAC dispatch surface
- `symAuthEnc` / `symAuthDec`
  - clean enum-driven authenticated symmetric dispatch surface
- `asymEnc` / `asymDec`
  - clean enum-driven asymmetric/KEM dispatch surface
- `asymSign` / `asymVerify`
  - clean enum-driven signature dispatch surface
- `crypoRand`
  - clean enum-driven random-byte dispatch surface
- `deriveSymmetricKeysFromBytesWithSalt` / `deriveSymmetricKeysFromString`
  - password-to-auth-state derivation
- `deriveMasterKey`, `wrapMasterKeyWithPin`, `unwrapMasterKeyWithPin`
  - password/PIN key lifecycle
- `encryptFileChunks`, `decryptFileChunks`, `hashFileChunks`
  - large-file chunk processing
- `signatureKeypair`, `signMessage`, `verifyMessage`
  - internal single-signature support used by the base API

## Loop Entrypoints

- `updateBlake3` / `finalBlake3`
  - streaming hash updates
- `runEncryptTasks` / `runDecryptTasks`
  - chunk worker loops
- `encryptChunkTask`, `decryptChunkTask`, `hashChunkTask`
  - per-chunk file processing loops

## Layout

- `src/protocols/common.nim`
  - shared error types and helper templates
- `src/protocols/custom_crypto/random.nim`
  - OS randomness with optional extra entropy mixing
- `src/protocols/wrapper/basic_api.nim`
  - primitive enum-driven API for symmetric, HMAC, asymmetric, signature, random, and typed single-material dispatch
- `.iron/meta/registry.nim`
  - metadata for supported algorithms and providers
- `src/protocols/wrapper/`
  - basic API, password/PIN support, signature support, wasm support
- `src/protocols/custom_crypto/`
  - pure-Nim and SIMD-oriented crypto helpers
- `src/protocols/chunky_crypto/`
  - chunked file encryption and hashing
- `src/protocols/bindings/`
  - optional native bindings
- `src/protocols/wrapper/wasm/`
  - JSON-based wasm bridge exported through a small C ABI
- `bindings/js/`
  - JS loader and TS declarations for the wasm build output
- `tools/`
  - native dependency and wasm build helpers
- `tests/`
  - vectors, regressions, and wrapper tests
- `iron/`
  - repo coordination metadata

## Quick Start

### Base build and test

```bash
nimble test
nim check .iron/meta/registry.nim
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

### JS/TS + WebAssembly bindings

```bash
nimble test_wasm
nimble build_wasm
```

The wasm path is `Nim -> C -> Emscripten -> .wasm`. The Nim implementation stays in this repo; the JS/TS side only loads the generated module and marshals typed arrays across a small JSON + base64 ABI.

`nimble build_wasm` compiles `src/protocols/wrapper/wasm/exports.nim` to C and then links it with `emcc`, producing browser/Node-friendly assets under `bindings/js/dist/` plus the checked-in loader files in `bindings/js/`.

The current wasm surface exposes:

- `capabilities`
- `basic.encrypt` / `basic.decrypt`
- `blake3Hash`
- `blake3KeyedHash`
- `gimliHash`
- `sha3Hash`

The default wasm build is aimed at the pure-Nim surfaces. Algorithms that depend on `libsodium` or `nimcrypto` remain listed in `capabilities()`, but they only become callable when you pass the matching Nim flags and provide wasm-compatible native libraries to Emscripten.

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

### 0. Typed Symmetric API

```nim
import tyr_crypto

var
  m: xchacha20cipherM
  msg = @[byte 1, 2, 3, 4]
for i in 0 ..< 32:
  m.key[i] = 0x11'u8
for i in 0 ..< 24:
  m.nonce[i] = 0x22'u8
let cipher = encrypt(msg, m)
doAssert decrypt(cipher, m) == msg
```

### 1. Typed Hash API

```nim
import tyr_crypto

let digest = hash(@[byte 7, 8, 9], blake3HashM())
doAssert digest.len == 32
```

### 3. Chunked file encryption

```nim
import tyr_crypto

when defined(hasLibsodium):
  let derived = deriveSymmetricKeysFromString(csXChaCha20AesGimli, "file-passphrase", @[], 64'u16)
  var opt = initChunkyOptions()
  opt.chunkBytes = 64 * 1024
  opt.bufferBytes = 4096

  let manifest = encryptFileChunks("input.bin", "chunks", derived.state, opt)
  decryptFileChunks(manifest, "chunks", "output.bin", derived.state, opt)
```

### 4. Multi KEM API

```nim
import tyr_crypto

when defined(hasLibsodium) and defined(hasLibOqs):
  let rx = asymKeypair(kaX25519)
  let rk = asymKeypair(kaKyber1)
  let rm = asymKeypair(kaMcEliece2)
  let combo = multiAsymEnc(
    mksX25519Kyber1McEliece2,
    @[rx.publicKey, rk.publicKey, rm.publicKey]
  )
  let shared = multiAsymDec(
    mksX25519Kyber1McEliece2,
    @[rx.secretKey, rk.secretKey, rm.secretKey],
    combo
  )
  doAssert shared == combo.sharedSecret
```

### 5. Multi KEM with caller-provided entropy

```nim
import tyr_crypto

when defined(hasLibsodium) and defined(hasLibOqs):
  let rx = asymKeypair(kaX25519)
  let rk = asymKeypair(kaKyber0)
  let combo = multiAsymEnc(
    mksX25519Kyber0,
    @[rx.publicKey, rk.publicKey],
    @[toBytes("mouse-jitter|request=42"), toBytes("server-timing|request=42")]
  )
  let shared = multiAsymDec(
    mksX25519Kyber0,
    @[rx.secretKey, rk.secretKey],
    combo
  )
  doAssert shared == combo.sharedSecret
```

These helpers feed liboqs KEM operations from a scoped hybrid RNG path that mixes:

- the normal OS-backed secure random source
- caller-supplied bytes such as user interaction or local event timing
- local process/timing context used as extra diversification

### 6. Multi Signatures

```nim
import tyr_crypto

when defined(hasLibsodium) and defined(hasLibOqs):
  let kp = multiAsymKeypair(mssEd25519Falcon0)
  let msg = @[byte 1, 2, 3, 4]
  let sig = multiAsymSign(mssEd25519Falcon0, msg, kp.secretKeys)
  doAssert multiAsymVerify(mssEd25519Falcon0, msg, sig, kp.publicKeys)
```

### 7. JS/TS wasm binding

```js
import { loadTyrCrypto } from "./bindings/js/tyr_crypto.mjs";

const tyr = await loadTyrCrypto();

const key = new Uint8Array(32);
key[0] = 7;

const nonce = new Uint8Array(24);
nonce[0] = 9;

const cipher = tyr.encrypt({
  algo: "chacha20",
  keys: [key],
  nonce,
  message: new Uint8Array([1, 2, 3, 4]),
});

const plain = tyr.decrypt({
  algo: "chacha20",
  keys: [key],
  nonce,
  ciphertext: cipher.ciphertext,
  hmac: cipher.hmac,
});
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

## Multi API Surfaces

- `multiAsymEnc*` / `multiAsymDec*`
  - composed KEM flows such as `X25519 + Kyber` or `X25519 + Kyber + McEliece`
- `multiAsymSign*` / `multiAsymVerify*`
  - composed signature flows such as `Ed25519 + Falcon`
- `multiSymAuthEnc*` / `multiSymAuthDec*`
  - composed authenticated symmetric flows built from the basic API

## Current Crypto Surfaces

- Symmetric wrapper modes
  - `chacha20`
  - `xchacha20Gimli`
  - `aesGimli`
  - `xchacha20AesGimli`
  - `xchacha20AesGimliPoly1305`
  - `aes256`
- Basic KEM modes
  - `kaX25519`
  - `kaKyber0`, `kaKyber1`
  - `kaMcEliece0`, `kaMcEliece1`, `kaMcEliece2`
  - `kaFrodo0`, `kaNtruPrime0`, `kaBike0`
- Multi KEM modes
  - `mksX25519Kyber0`
  - `mksX25519Kyber1`
  - `mksX25519McEliece0`
  - `mksX25519McEliece1`
  - `mksX25519Kyber1McEliece2`
- Multi signature modes
  - `mssEd25519Falcon0`
  - `mssEd25519Falcon1`
- `mssEd25519Dilithium0`
- `mssFalcon0Dilithium0`
- `mssFalcon1Dilithium1`

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
nimble test_wasm
nimble build_wasm
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
- `emcc` is missing or `nimble build_wasm` fails immediately
  - Install and activate an Emscripten SDK environment first. The wasm build is not using Nim's JS backend; it expects `emcc` on `PATH`.
- A wasm algorithm shows `compiledIn: false` in `capabilities()`
  - Expected unless the wasm build was compiled with the matching `-d:has*` flag and a wasm-compatible backend library.
- OTP output does not match external TOTP apps
  - Expected. The `otp` module is custom and not a drop-in RFC 4226/6238 implementation.

## Development Notes

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before changing behavior. Security reporting guidance lives in [SECURITY.md](./SECURITY.md). Licensing notes for dependencies live in [THIRD_PARTY_LICENSES.md](./THIRD_PARTY_LICENSES.md).

## Conventions Summary

- Keep functions short and compose helpers instead of nesting deeply.
- Declare `var`/`let` blocks near the top of the proc.
- Preserve the level-based module layout under `src/protocols/`.
- Prefer explicit runtime errors over silent fallback behavior.
- Add or update tests whenever crypto behavior, file formats, or backend wiring changes.
- Update docs when public behavior or repo structure changes.
