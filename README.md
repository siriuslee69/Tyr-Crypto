# Tyr-Crypto

Experimental Nim crypto toolkit. Pure-Nim implementations for post-quantum KEMs, signatures, symmetric primitives, and key agreement — plus optional native backend paths (libsodium, liboqs, OpenSSL).

```
IMPORTANT: This is custom cryptographic code. Treat local Tyr implementations as
experimental unless the exact primitive, mode, and deployment environment have been
independently reviewed for your use case.
```

---

## Quick Start

```nim
import tyr_crypto

# ---- Hash ----
var d = blake3Hash(@[byte 1, 2, 3])
doAssert d.len == 32

# ---- KEM (Kyber768) ----
let kp = kyberTyrKeypair(kyber768)
let ct = kyberTyrEncaps(kyber768, kp.publicKey)
let shared = kyberTyrDecaps(kyber768, kp.secretKey, ct.ciphertext)
doAssert shared == ct.sharedSecret

# ---- Sign (Dilithium65) ----
let msg = @[byte 'M', 'e', 's', 's', 'a', 'g', 'e']
let kp2 = dilithiumTyrKeypair(dilithium65)
let sig = dilithiumTyrSign(dilithium65, msg, kp2.secretKey)
doAssert dilithiumTyrVerify(dilithium65, msg, sig, kp2.publicKey)

# ---- AEAD (XChaCha20-Poly1305 via typed material) ----
import tyr_crypto
var m: xchacha20TyrCipherM
for i in 0 ..< m.key.len:    m.key[i] = 0x11'u8
for i in 0 ..< m.nonce.len:  m.nonce[i] = 0x22'u8
let cipher = encrypt(@[byte 1,2,3,4], m)
doAssert decrypt(cipher, m) == @[byte 1,2,3,4]
```

More examples: [examples/](examples/readme.md)

---

## Algorithm Overview

### Symmetric (all pure Nim)

| Primitive | Use |
|-----------|-----|
| BLAKE3 | Hash, keyed hash, derive-key KDF, XOF |
| SHA3-224/256/384/512, SHAKE128/256 | FIPS 202 hash/XOF |
| Gimli | Lightweight sponge (hash, tag, stream) |
| ChaCha20 / XChaCha20 | Stream cipher (IETF RFC 8439, 192-bit nonce) |
| Poly1305 | One-time MAC |
| AES-CTR | AES in CTR mode |
| Argon2id/i | Memory-hard password hashing |
| Custom KDF | Memory-hard key derivation (tail-indexed xor rounds) |

### Asymmetric (pure Nim unless noted)

| Category | Algorithms | Implementation |
|----------|-----------|----------------|
| **KEM** | Kyber (ML-KEM-512/768/1024) | Pure Nim + optional SIMD |
| | FrodoKEM (640/976/1344, AES+SHAKE) | Pure Nim (streamed matrix) |
| | BIKE-L1 | Pure Nim (constant-time decoder) |
| | NTRU (HPS-509/677/821, HRSS-701) | Pure Nim (Toom-4+K2) |
| | SABER (LightSaber/Saber/FireSaber) | Pure Nim |
| | Classic McEliece (6688128f/6960119f/8192128f) | Pure Nim |
| **Sign** | Dilithium (ML-DSA-44/65/87) | Pure Nim + optional SIMD |
| | Falcon (512/1024, scalar+SIMD backends) | Pure Nim |
| | SPHINCS+-SHAKE-128f-simple | Pure Nim |
| **KA** | X25519 | Pure Nim (5 passes, SIMD batching) |

Detailed parameter tables, key sizes, and speed ranking: [docs/ALGORITHMS.md](docs/ALGORITHMS.md)

---

## Repo Boundary

```
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

---

## API Surface

The canonical wrapper layer is [basic_api.nim](src/protocols/wrapper/basic_api.nim) in [src/tyr_crypto.nim](src/tyr_crypto.nim):

- `hash` / `hmac` / `authenticate`
- `sign` / `verify`
- `encrypt` / `decrypt` / `seal` / `open`
- `asymKeypair` / `asymEnc` / `asymDec` / `asymSign` / `asymVerify`
- `cryptoRand`

Local pure-Nim implementations use `Tyr` suffixed names (e.g. `kyberTyrKeypair`, `blake3TyrHashM`). Unsuffixed names may resolve to native backend paths when available.

---

## Documentation Map

| Document | Contents |
|----------|----------|
| [docs/ALGORITHMS.md](docs/ALGORITHMS.md) | All algorithms: parameters, key sizes, security level, speed ranking, CT audit |
| [docs/CODE_LAYOUT.md](docs/CODE_LAYOUT.md) | Source tree, dependency flow, naming rules |
| [docs/TESTS.md](docs/TESTS.md) | Test groups, commands, Android harness, build defines |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Benchmark entry points, measurement flow, interpretation |
| [docs/research/pq_non_ntru_saber/README.md](docs/research/pq_non_ntru_saber/README.md) | Papers: Kyber, Dilithium, Falcon, Frodo, BIKE, McEliece, SPHINCS+ |
| [docs/research/ntru_saber/README.md](docs/research/ntru_saber/README.md) | Papers: NTRU, SABER — includes full optimization history with benchmark tables |
| [.iron/PROGRESS.md](.iron/PROGRESS.md) | Full implementation history: bugs found/fixed, performance changes, decisions |
| [docs/benchmarks/](docs/benchmarks/) | Curated benchmark JSON snapshots (desktop + 3 phones) |
| [.examples/](examples/readme.md) | Runnable usage examples |
| [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) | Third-party license notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor workflow and review checklist |
| [.iron/conventions/](.iron/conventions) | Proto-RepoTemplate conventions |

---

## Optional Native Backend Paths

| Backend | Algorithms | Define |
|---------|-----------|--------|
| **libsodium** | X25519, Ed25519, AEAD helpers | `-d:hasLibsodium` |
| **liboqs** | Kyber, Frodo, NTRU, BIKE, Dilithium, Falcon, SPHINCS+, McEliece | `-d:hasLibOqs` |
| **OpenSSL** | Ed448, RSA/ECDSA verify, X.509 checks | `-d:hasOpenSSL3` |
| **nimcrypto** | AES-GCM | (import-time) |

Missing optional libraries raise `LibraryUnavailableError`.

---

## Commands

```bash
nimble check_core     # core imports and types
nimble check          # full module check
nimble test           # default test suite
nimble test_all       # full test matrix (slow)
nimble test_wasm      # wasm target tests
nimble test_neon_checks     # ARM64 NEON compile check
nimble test_simd_matrix     # scalar/SIMD parity matrix
nimble bench_custom_crypto  # Tyr-only primitive report
nimble bench_pq_profiles    # PQ benchmark profiles
nimble build_android_harness               # Android native test (custom/SIMD)
nimble build_android_harness_asymmetric_fast  # Android: Kyber + Dilithium
nimble build_android_harness_asymmetric_full  # Android: all PQ
nimble build_wasm          # Emscripten wasm build
nimble build_libsodium     # build native libsodium
nimble build_liboqs        # build native liboqs
nimble build_openssl       # build native OpenSSL
```

---

## Issue Playbook

```
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

---

## Workspace Dependencies

```
Dependency             Location
libsodium              submodules/libsodium
liboqs                 submodules/liboqs
OpenSSL                submodules/openssl
PQClean                submodules/pqclean
PQClean Falcon refs    submodules/pqclean_falcon_ref_sources
NTRU sampling refs     submodules/ntru_sampling_ref_sources
SIMD-Nexus             submodules/simd_nexus or ../SIMD-Nexus
Sigma-BenchAndEval     submodules/sigma_bench_and_eval
Otter-RepoEvaluation   submodules/otter_repo_evaluation
```

Local path overrides go in `.iron/.local.gitmodules.toml` (gitignored).

## NixOS

Import `inputs.tyr.nixosModules.default` from the flake:

```nix
{
  imports = [ inputs.tyr.nixosModules.default ];
  programs.tyr-crypto = {
    enable = true;
    settings = { pqProfile = "portable"; simd = "auto"; kdfMemoryKiB = 65536; };
  };
}
```

Generated TOML files are for downstream consumers. Tyr itself does not read them at runtime.

## Wasm / JS Bridge

Basic encryption/hash operations exported for wasm/JS targets. Files:
- `src/protocols/wrapper/wasm/`
- `bindings/js/tyr_crypto.mjs`
- `bindings/js/tyr_crypto.d.ts`

Exported operations: `basic.encrypt`, `basic.decrypt`, `blake3Hash`, `blake3KeyedHash`, `gimliHash`, `sha3Hash`, `capabilities`.

---

## Maintainer Conventions

This repo follows the [Proto conventions](.iron/conventions). Key rules:

```
Language        Nim
Flow            raw data → sanitize → typed material → operate → output
Layout          src/protocols, tests, tools, docs, submodules
Native deps     declare in nimble + submodules
Artifacts       all build/cache/runtime outputs ignored
```
