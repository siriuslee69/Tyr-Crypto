# Tyr-Crypto

Experimental Nim crypto toolkit. Pure-Nim implementations for post-quantum KEMs, signatures, symmetric primitives, and key agreement — plus optional native backend paths (libsodium, liboqs, OpenSSL).

```
IMPORTANT: This is custom cryptographic code. Treat local Tyr implementations as
experimental unless the exact primitive, mode, and deployment environment have been
independently reviewed for your use case.

The current code does **not** make a blanket constant-time claim: Dilithium
signing, Falcon signing/key generation, and Argon2id retain algorithm-level
timing or memory-access caveats. See the audited status table in
[docs/ALGORITHMS.md](docs/ALGORITHMS.md#constant-time--side-channel-notes).
```

---

## Quick Start

```nim
import tyr_crypto

# ---- Hash ----
var d = blake3Hash(@[byte 1, 2, 3])
doAssert d.len == 32

# ---- KEM (Kyber768) ----
var kp = kyberTyrKeypair(kyber768)
var ct = kyberTyrEncaps(kyber768, kp.publicKey)
var shared = kyberTyrDecaps(kyber768, kp.secretKey, ct.ciphertext)
doAssert shared == ct.sharedSecret

# ---- Sign (Dilithium65) ----
var msg = @[byte 'M', 'e', 's', 's', 'a', 'g', 'e']
var kp2 = dilithiumTyrKeypair(dilithium65)
var sig = dilithiumTyrSign(dilithium65, msg, kp2.secretKey)
doAssert dilithiumTyrVerify(dilithium65, msg, sig, kp2.publicKey)

# ---- AEAD (XChaCha20-Poly1305 via typed material) ----
import tyr_crypto
var m: xchacha20TyrCipherM
for i in 0 ..< m.key.len:    m.key[i] = 0x11'u8
for i in 0 ..< m.nonce.len:  m.nonce[i] = 0x22'u8
var cipher = encrypt(@[byte 1,2,3,4], m)
doAssert decrypt(cipher, m) == @[byte 1,2,3,4]
```

More examples: [examples/](examples/readme.md)

---

## Algorithm Overview

The SIMD columns say whether that implementation is available for the primitive;
individual calls may still select the scalar path or require a batched API. For
the custom KDF, `yes` means its selected BLAKE3, Gimli, SHA3, XChaCha20, or
AES-CTR generator has that implementation—not that the KDF's memory-mixing loop
itself is vectorized. Performance wording is based on the curated snapshots in
[docs/benchmarks/](docs/benchmarks/) and the benchmark notes in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

### Symmetric (all pure Nim)

| Primitive | SSE | AVX | NEON | Use |
|-----------|-----|-----|------|-----|
| BLAKE3 | yes | yes | yes | Hash, keyed hash, derive-key KDF, XOF |
| SHA3-224/256/384/512, SHAKE128/256 | yes | yes | yes | FIPS 202 hash/XOF |
| Gimli | yes | yes | yes | Lightweight sponge (hash, tag, stream) |
| ChaCha20 / XChaCha20 | yes | yes | yes | Stream cipher (IETF RFC 8439, 192-bit nonce for XChaCha20) |
| Poly1305 | yes | yes | yes | One-time MAC |
| AES-CTR | yes | yes | yes | AES in CTR mode |
| Argon2id/i | yes | yes | yes | Memory-hard password hashing |
| Custom KDF | yes | yes | yes | Memory-hard key derivation (tail-indexed xor rounds) |

Curated benchmark snapshots currently focus on the asymmetric and key-agreement paths. For symmetric tuning runs, use `nimble bench_custom_crypto` and `nimble bench_custom_kdf`.

### Asymmetric (pure Nim unless noted)

| Category | Algorithms | Implementation | SSE | AVX | NEON | Benchmark-guided profile |
|----------|------------|----------------|-----|-----|------|--------------------------|
| **KEM** | Kyber (ML-KEM-512/768/1024) | Pure Nim | yes | yes | no | Fastest PQ KEM family in the current curated snapshots; sub-ms on desktop and still sub-ms on the measured phones |
| **KEM** | FrodoKEM (640/976/1344, AES + SHAKE) | Pure Nim (streamed matrix) | yes | yes | no | Conservative, high-bandwidth path; much slower than Kyber/SABER/NTRU, with AES variants clearly faster than SHAKE on desktop |
| **KEM** | BIKE-L1 | Pure Nim (constant-time decoder) | no | no | no | Tens-of-ms KEM in the current snapshots |
| **KEM** | NTRU (HPS-509/677/821, HRSS-701) | Pure Nim (Toom-4 + K2 default) | no | yes | no | Mid-latency KEM; clearly slower than Kyber/SABER, but far below Frodo/BIKE/McEliece |
| **KEM** | SABER (LightSaber/Saber/FireSaber) | Pure Nim | no | no | no | Same low-latency class as Kyber in the current snapshots; sub-ms on desktop and on the measured phones |
| **KEM** | Classic McEliece (6688128f/6960119f/8192128f) | Pure Nim | no | no | no | Slowest measured KEM here; key generation dominates, but ciphertexts stay very small |
| **Sign** | Dilithium (ML-DSA-44/65/87) | Pure Nim | yes | yes | no | Fastest measured PQ signature family in the current curated snapshots |
| **Sign** | Falcon (512/1024, scalar + SIMD backends) | Pure Nim | yes | no | yes | Smallest PQ signatures here, but current curated pure-Nim snapshots are strongly keygen-dominated and much slower than Dilithium |
| **Sign** | SPHINCS+-SHAKE-128f-simple | Pure Nim | no | no | no | Slower than Dilithium, but still far below the current Falcon totals |
| **KA** | X25519 | Pure Nim (5 passes, SIMD batching) | yes | yes | yes | Best current results come from the SIMD batch paths; still a sub-ms path on desktop and phones |

Detailed parameter tables, key sizes, CT notes, and speed ranking: [docs/ALGORITHMS.md](docs/ALGORITHMS.md)

---

## Benchmark-Guided Performance

These numbers are not protocol guarantees. They are README-level guidance taken from the curated benchmark snapshots under [docs/benchmarks/](docs/benchmarks/), meant to help with rough algorithm selection and expectation-setting.

### KEMs

| Family | Desktop guidance | ARM64 phone guidance | Notes |
|--------|------------------|----------------------|-------|
| Kyber | about `0.06-0.13 ms` | about `0.33-0.91 ms` | Lowest-latency PQ KEM family in the current curated set |
| SABER | about `0.14-0.27 ms` | about `0.29-0.75 ms` | Same low-latency class as Kyber in practice |
| NTRU | about `2.34-4.57 ms` | about `6.54-20.85 ms` | Current default uses the promoted Toom-4 + K2 path |
| FrodoKEM | about `1.24-45.27 ms` | about `21-133 ms` | AES variants are much faster than SHAKE on desktop; the gap narrows on phones |
| BIKE-L1 | about `65 ms` | about `50-74 ms` | Decoder-heavy, sits in the tens-of-ms range in current snapshots |
| Classic McEliece | about `186-214 ms` | about `495-892 ms` | Key generation dominates total runtime |

### Signatures

| Family | Desktop keygen | Desktop sign | Desktop verify | ARM64 phone keygen | ARM64 phone sign | ARM64 phone verify | Notes |
|--------|----------------|--------------|----------------|--------------------|------------------|--------------------|-------|
| Dilithium | about `0.08-0.20 ms` | about `0.19-0.29 ms` | about `0.09-0.20 ms` | about `0.11-0.31 ms` | about `0.23-0.60 ms` | about `0.09-0.34 ms` | Fastest measured PQ signature family in the current curated snapshots |
| Falcon-512 | about `12.09 s` | about `1.37 ms` | about `0.03 ms` | about `10.15-14.39 s` | about `0.85-1.20 ms` | about `0.04-0.06 ms` | Current pure-Nim Falcon cost is overwhelmingly keygen; sign and verify are already in the ms/us range |
| Falcon-1024 | about `86.85 s` | about `2.87 ms` | about `0.07 ms` | about `69.77-98.73 s` | about `1.77-2.51 ms` | about `0.08-0.12 ms` | Falcon-1024 is even more strongly keygen-dominated in the curated snapshots |
| SPHINCS+ | n/a in current curated split table | n/a in current curated split table | n/a in current curated split table | n/a in current curated split table | n/a in current curated split table | n/a in current curated split table | Current curated README snapshot only records combined `sign_verify`: about `20.9 ms` desktop and about `89-128 ms` on the measured phones |

### Key Agreement

| Family | Desktop guidance | ARM64 phone guidance | Notes |
|--------|------------------|----------------------|-------|
| X25519 | about `357-391 us` | about `508-697 us` | Best current desktop and phone results come from the AVX2 / NEON batch pass |

---

## Repo Boundary

| Tyr-Crypto owns | Tyr-Crypto does not own |
|-----------------|-------------------------|
| typed crypto wrappers | application protocols |
| pure-Nim crypto helpers | certificate policy |
| optional native bindings | transport/session orchestration |
| wasm/JS bridge | account or database state |
| regression/vector tests | external key-management infrastructure |
| native dependency builders | app-specific authorization decisions |

---

## API Surface

The canonical wrapper layer is [basic_api.nim](src/protocols/wrapper/basic_api.nim) in [src/tyr_crypto.nim](src/tyr_crypto.nim):

- `hash` / `hmac` / `authenticate`
- `sign` / `verify`
- `encrypt` / `decrypt` / `seal` / `open`
- `genKeypair` / `encaps` / `decaps`
- `cryptoRand`

Compatibility aliases still exist in `basic_api.nim` for older callers:

- `asymKeypair` / `asymEnc` / `asymDec` / `asymSign` / `asymVerify`

Local pure-Nim implementations use `Tyr` suffixed names (e.g. `kyberTyrKeypair`, `blake3TyrHashM`). Unsuffixed names may resolve to native backend paths when available.

`import tyr_crypto` is the supported all-in-one import and now exports the AES,
Gimli, XChaCha20, NTRU, and SABER facades as well. The small
`protocols/custom_crypto/*.nim` facades remain as compatibility imports for
existing callers; they are intentionally not removed, because removing them
would break direct imports without improving the canonical API.

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
| [examples/](examples/readme.md) | Runnable usage examples |
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

| Command | Purpose |
|---------|---------|
| `nimble check_core` | Core imports and types |
| `nimble check` | Full module check |
| `nimble test` | Default test suite |
| `nimble test_all` | Full test matrix (slow) |
| `nimble test_wasm` | Wasm bridge regression tests |
| `nimble test_neon_checks` | ARM64 / NEON compile-check matrix |
| `nimble test_simd_matrix` | Scalar / SIMD parity matrix |
| `nimble bench_custom_crypto` | Tyr-only primitive report |
| `nimble bench_pq_profiles` | PQ benchmark profiles |
| `nimble build_android_harness` | Android native test harness |
| `nimble build_android_harness_asymmetric_fast` | Android harness with Kyber + Dilithium |
| `nimble build_android_harness_asymmetric_full` | Android harness with the full PQ bundle |
| `nimble build_wasm` | Release Emscripten wasm/JS build |
| `nimble build_wasm_debug` | Debug Emscripten wasm/JS build |
| `nimble build_libsodium` | Build native libsodium |
| `nimble build_liboqs` | Build native liboqs |
| `nimble build_openssl` | Build native OpenSSL |

---

## Issue Playbook

| Issue | Workaround / status |
|-------|---------------------|
| Missing native backend | Run the matching `nimble build_*` task or compile without the matching `-d:has*` flag |
| x86_64 Android emulator exit 139 | Validate Android on physical ARM64 devices |
| `emcc` missing for wasm build | Install and activate Emscripten before running `nimble build_wasm` |
| Nimble user-cache permission errors | Use the repo-local cache tasks or an explicit `--nimcache:build/*` path |
| Falcon tests dominate runtime | Use `--only:falcon512` or `--only:falcon1024` in the Nim desktop test runner |
| Ambiguous research PDF redistribution | Keep as ignored local cache and regenerate with `docs/research/*/download_papers.nim` |

---

## Workspace Dependencies

| Dependency | Location |
|------------|----------|
| libsodium | `submodules/libsodium` |
| liboqs | `submodules/liboqs` |
| OpenSSL | `submodules/openssl` |
| PQClean | `submodules/pqclean` |
| PQClean Falcon refs | `submodules/pqclean_falcon_ref_sources` |
| NTRU sampling refs | `submodules/ntru_sampling_ref_sources` |
| SIMD-Nexus | `submodules/simd_nexus` or `../SIMD-Nexus` |
| Sigma-BenchAndEval | `submodules/sigma_bench_and_eval` |
| Otter-RepoEvaluation | `submodules/otter_repo_evaluation` |

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

Basic encryption/hash operations are exported for wasm/JS targets.

### Build It Yourself

1. Install Nim and make sure `nim` is on `PATH`.
2. Install and activate Emscripten so `emcc` is on `PATH`.
3. Build the release bridge with `nimble build_wasm`.
4. Build a debug bridge with `nimble build_wasm_debug`.
5. Re-run the JSON bridge regression tests with `nimble test_wasm`.

If Nim's library path is not auto-detected on your machine, set `NIM_LIB_DIR` before running the wasm build task.

### Files

| Path | Purpose |
|------|---------|
| `src/protocols/wrapper/wasm/` | Nim wasm bridge sources |
| `tools/build_wasm.nim` | Nim + Emscripten build driver |
| `bindings/js/dist/tyr_crypto_wasm.mjs` | Generated Emscripten module |
| `bindings/js/tyr_crypto.mjs` | JS loader / wrapper |
| `bindings/js/tyr_crypto.d.ts` | TypeScript declarations |

### Exported JS Surface

| Export | Purpose |
|--------|---------|
| `loadTyrCrypto` | Load the generated wasm module |
| `abiVersion` | Return wasm ABI version |
| `capabilities` | Return supported wasm bridge features |
| `basic.encrypt` / `basic.decrypt` | JSON bridge for basic cipher operations |
| `basic.blake3Hash` / `basic.blake3KeyedHash` | BLAKE3 hashing helpers |
| `basic.gimliHash` | Gimli hashing helper |
| `basic.sha3Hash` | SHA3 hashing helper |

### Minimal JS Usage

```js
import { loadTyrCrypto } from "./bindings/js/tyr_crypto.mjs";

const tyr = await loadTyrCrypto();
console.log(tyr.abiVersion());
console.log(tyr.capabilities());
```

---

## Maintainer Conventions

This repo follows the [Proto conventions](.iron/conventions). Key rules:

| Area | Rule |
|------|------|
| Language | Nim |
| Flow | raw data -> sanitize -> typed material -> operate -> output |
| Layout | `src/protocols`, `tests`, `tools`, `docs`, `submodules` |
| Native deps | declare in nimble + submodules |
| Artifacts | all build/cache/runtime outputs ignored |
