# Tyr-Crypto

Experimental Nim crypto toolkit for the sibling repos in this workspace.

## Production Scope
This repo is production-ready in the project-hygiene sense defined by [.iron/conventions/PROJECTS.md](.iron/conventions/PROJECTS.md): dependencies are declared, native source dependencies live under `submodules/`, generated artifacts are ignored, and docs/tests/build tasks are present.

This is still custom cryptographic code. Treat the local `Tyr` implementations as experimental unless the exact primitive, mode, and deployment environment have been independently reviewed for your use case.

## Current Shape
`src/tyr_crypto.nim` exports the current public surface:

- `algorithms`
- [basic_api.nim](src/protocols/wrapper/basic_api.nim)
- custom pure-Nim modules: `random`, `blake3`, `gimli_sponge`, `sha3`, `poly1305`, `mceliece`, `otp`, `hmac`, `kdf`
- `signature_support`
- [public_key_verify.nim](src/protocols/wrapper/public_key_verify.nim) for
  OpenSSL-backed RSA/ECDSA detached verification and X.509 public-key
  certificate checks

The canonical wrapper layer is [basic_api.nim](src/protocols/wrapper/basic_api.nim). There is no generic material/inference layer anymore.

`custom_crypto/` splits implementation code by primitive class:

- `symmetric/` for hashes, MACs, RNG, stream/block helpers, KDFs, and OTP utilities
- `asymmetric/pq/` for post-quantum KEM/signature implementations
- `asymmetric/none_pq/` for non-PQ asymmetric implementations

The old top-level module names under `custom_crypto/` remain as compatibility facades.

## Repo Boundary
```text
+----------------------------+--------------------------------------------+
| Tyr-Crypto owns            | Tyr-Crypto does not own                    |
+----------------------------+--------------------------------------------+
| typed crypto wrappers      | application protocols                      |
| pure-Nim crypto helpers    | certificate policy                         |
| optional native bindings   | transport/session orchestration            |
| wasm/JS bridge             | account or database state                  |
| regression/vector tests    | external key-management infrastructure     |
| native dependency builders | app-specific authorization decisions       |
+----------------------------+--------------------------------------------+
```

## Canonical API
Use Tyr-Crypto as an imported library. It does not expose a runtime `config.toml` or `userconfig.toml` loader; calling projects should configure behavior through typed materials, explicit function parameters, and their own application config where needed.

## NixOS

Import `inputs.tyr.nixosModules.default` from the flake when a NixOS host wants
to install Tyr source material or generate declarative profiles for services
that consume Tyr:

```nix
{
  imports = [ inputs.tyr.nixosModules.default ];

  programs.tyr-crypto = {
    enable = true;

    settings = {
      pqProfile = "portable";
      simd = "auto";
      kdfMemoryKiB = 65536;
    };

    profiles.geist.settings.consumer = "geist";

    profiles.torii = {
      mode = "replace";
      settings.consumer = "torii";
    };
  };
}
```

Conflict rule:
- `configFile` and declarative `settings` are mutually exclusive at the same scope.
- Named profiles merge over global settings by default.
- Set `profiles.<name>.mode = "replace"` when a consumer must not inherit global defaults.

These generated TOML files are for downstream consumers. Tyr itself does not
read them at runtime.

Use typed materials from [basic_api.nim](src/protocols/wrapper/basic_api.nim).

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
Local custom implementations expose `Tyr`-suffixed names so they are easy to distinguish from backend-backed paths.

Examples in [basic_api.nim](src/protocols/wrapper/basic_api.nim):

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

The old unsuffixed McEliece materials still exist and remain the `liboqs`-backed path. The `Tyr`-suffixed McEliece materials are the pure-Nim path.

## Current Pure-Nim Algorithms
Current local/custom implementations include:

- BLAKE3
- Gimli sponge, tag, and stream helpers
- SHA3-224 / 256 / 384 / 512
- SHAKE256
- Poly1305
- AES-CTR
- ChaCha20 / HChaCha20 / XChaCha20
- Custom memory-hard KDF with tail-indexed xor rounds and full-memory refill
- Classic McEliece `6688128f`, `6960119f`, `8192128f`
- NTRU HPS/HRSS KEMs: `ntruhps2048509`, `ntruhps2048677`, `ntruhps4096821`, `ntruhrss701`
- SABER KEMs: `lightsaber`, `saber`, `firesaber`
- OTP helpers

## Optional Backend Paths
Some surfaces still depend on optional native libraries:

- `libsodium`: X25519, Ed25519, compatibility/authentication helpers
- `liboqs`: Kyber, Frodo, NTRU Prime, BIKE, Falcon, Dilithium, SPHINCS+
- `OpenSSL`: Ed448, RSA/ECDSA detached verification, X.509 chain/public-key
  checks
- `nimcrypto`: AES-GCM binding/tests

Missing optional libraries should raise explicit `LibraryUnavailableError`, not silently fall back.

PQClean reference bindings for NTRU/SABER live under `src/protocols/bindings` and point at the pinned `submodules/pqclean` submodule. The normal custom NTRU/SABER APIs use the pure-Nim implementations under `custom_crypto/asymmetric/pq/`.

## Workspace Dependencies
```text
+------------------------+---------------------------------------------+
| Dependency             | Location                                    |
+------------------------+---------------------------------------------+
| libsodium              | submodules/libsodium                        |
| liboqs                 | submodules/liboqs                           |
| OpenSSL                | submodules/openssl                          |
| PQClean                | submodules/pqclean                          |
| PQClean Falcon refs    | submodules/pqclean_falcon_ref_sources       |
| NTRU sampling refs     | submodules/ntru_sampling_ref_sources        |
| SIMD-Nexus             | submodules/simd_nexus or ../SIMD-Nexus      |
| Sigma-BenchAndEval     | submodules/sigma_bench_and_eval             |
| Otter-RepoEvaluation   | submodules/otter_repo_evaluation            |
+------------------------+---------------------------------------------+
```

The corresponding manifest entries live in [.gitmodules](.gitmodules). Local path overrides belong in `.iron/.local.gitmodules.toml`, which is ignored.

## Quick Start
### Typed hash
```nim
import tyr_crypto

var digest = hash(@[byte 1, 2, 3], blake3TyrHashM())
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

var cipher = encrypt(msg, m)
doAssert decrypt(cipher, m) == msg
```

### Pure-Nim McEliece
```nim
import tyr_crypto

var kp = asymKeypair(mceliece0TyrSendM)

var
  sendM: mceliece0TyrSendM
  openM: mceliece0TyrOpenM

for i in 0 ..< sendM.receiverPublicKey.len:
  sendM.receiverPublicKey[i] = kp.publicKey[i]
for i in 0 ..< openM.receiverSecretKey.len:
  openM.receiverSecretKey[i] = kp.secretKey[i]

var env = seal(sendM)
var shared = open(env, openM)
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

- [types.nim](src/protocols/wrapper/wasm/level0/types.nim)
- [json_codec.nim](src/protocols/wrapper/wasm/level1/json_codec.nim)
- [json_api.nim](src/protocols/wrapper/wasm/level2/json_api.nim)
- [exports.nim](src/protocols/wrapper/wasm/exports.nim)
- [tyr_crypto.mjs](bindings/js/tyr_crypto.mjs)
- [tyr_crypto.d.ts](bindings/js/tyr_crypto.d.ts)

## Layout And Docs
- [CODE_LAYOUT.md](docs/CODE_LAYOUT.md): source layout, dependency flow, naming table
- [TESTS.md](docs/TESTS.md): test groups, defines, Android harness flow
- [BENCHMARKS.md](docs/BENCHMARKS.md): Sigma/Otter entry points and artifact policy
- [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md): local third-party license notes
- [CONTRIBUTING.md](CONTRIBUTING.md): contributor workflow and review checklist
- [.iron/conventions/](.iron/conventions): copied Proto-RepoTemplate conventions

## Commands
Common repo commands from [tyr_crypto.nimble](tyr_crypto.nimble):

```bash
nimble check_core
nimble check
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
nimble build_openssl
nimble bench_pq_profiles
```

Direct focused checks:

```bash
nimble check_core
nim check src/tyr_crypto.nim
nim check src/protocols/wrapper/basic_api.nim
```

## Current Validation Highlights
The suite currently includes:

- known-answer tests for BLAKE3, SHA3, Poly1305, and PQ algorithms with local vectors
- scalar/SIMD parity tests for BLAKE3, Gimli, SHA3, Poly1305, X25519, and PQ hot paths
- ARM64/NEON compile-check coverage through `nimble test_neon_checks`
- wrapper-layer dispatch tests
- custom KDF tail-indexing, full-memory parameter validation, and generator wiring
- wasm bridge tests
- Android native harness tests for custom/SIMD and asymmetric/PQ bundles

## Android Harness
```text
nimble build_android_harness_asymmetric_fast
   |
   v
ignored Gradle/app/native build outputs
   |
   v
nim r tools/run_android_harness.nim -- --serial:<device> --timeoutSeconds:900
   |
   v
captured native output under app files
```

Current workspace notes:

- Physical ARM64 phone harnesses have passed in prior validation runs.
- The x86_64 emulator app launches, but the packaged x86_64 native harness has previously exited with code `139`; use physical ARM64 devices as the trusted Android signal until that emulator path is fixed.

## Maintainer Conventions
This repo follows the copied Proto conventions in [.iron/conventions](.iron/conventions). The condensed local rules are:

```text
+------------------+--------------------------------------------------+
| Area             | Rule                                             |
+------------------+--------------------------------------------------+
| Language         | Nim unless a file is generated binding or asset  |
| Flow             | perceive raw data -> build truth -> act          |
| Inputs           | sanitize before public/user-facing API use       |
| Layout           | src/protocols, tests, tools, docs, submodules    |
| Native deps      | declare in nimble and keep source in submodules  |
| Tests            | expose focused nimble tasks for common runs      |
| Docs             | update README/docs/progress for larger changes   |
| Artifacts        | keep build/runtime/cache output ignored          |
+------------------+--------------------------------------------------+
```

## Issue Playbook
```text
+--------------------------------------+---------------------------------------------+
| Issue                                | Workaround / status                         |
+--------------------------------------+---------------------------------------------+
| Missing native backend               | Run the matching nimble build_* task or      |
|                                      | compile without the -d:has* flag.           |
| x86_64 Android emulator exit 139     | Validate Android on physical ARM64 devices. |
| emcc missing for wasm build          | Install/activate Emscripten before           |
|                                      | nimble build_wasm.                          |
| Nimble user-cache permission errors  | Use repo-local caches through the provided   |
|                                      | nimble tasks or explicit --nimcache:build/* |
| Falcon tests dominate runtime        | Use --only:falcon512 or --only:falcon1024   |
|                                      | in the Nim desktop test runner.             |
| Ambiguous research PDF redistribution| Keep as ignored local cache; regenerate with |
|                                      | docs/research/*/download_papers.nim.        |
+--------------------------------------+---------------------------------------------+
```
