# Tyr-Crypto

Experimental Nim crypto toolkit. Pure-Nim implementations for post-quantum KEMs, signatures, symmetric primitives, and key agreement, plus optional native backend paths through libsodium, liboqs, and OpenSSL.

```
IMPORTANT: This is custom cryptographic code. Treat local Tyr implementations as
experimental unless the exact primitive, mode, and deployment environment have been
independently reviewed for your use case.

The current code does **not** make a blanket constant-time claim: Dilithium
signing, Falcon signing/key generation, and Argon2id retain algorithm-level
timing or memory-access caveats. See the reviewed status table in
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
var m: xchacha20TyrCipherM
for i in 0 ..< m.key.len:    m.key[i] = 0x11'u8
for i in 0 ..< m.nonce.len:  m.nonce[i] = 0x22'u8
var cipher = encrypt(@[byte 1,2,3,4], m)
doAssert decrypt(cipher, m) == @[byte 1,2,3,4]
```

More examples: [examples/](examples/readme.md)

---

## Algorithm Overview

The SIMD column names the code that actually uses vector lanes. It does not imply
that the complete algorithm is vectorized. Some paths require a batched API or a
compile define such as `-d:avx2`; there is no general runtime CPU-feature dispatcher.
For the custom KDF, SIMD belongs to the selected generator, not to the KDF's
memory-mixing loop. Performance wording is based on the curated snapshots in
[docs/benchmarks/](docs/benchmarks/) and the benchmark notes in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

### Symmetric (all pure Nim)

| Primitive | SIMD coverage | Use |
|-----------|---------------|-----|
| BLAKE3 | SSE2, AVX2, NEON compression paths | Hash, keyed hash, derive-key KDF, XOF |
| SHA3-224/256/384/512, SHAKE128/256 | SSE2/NEON two-lane and AVX2 four-lane batching | FIPS 202 hash/XOF |
| Gimli | SSE2, AVX2, NEON state operations | Lightweight sponge (hash, tag, stream) |
| ChaCha20 | SSE2/NEON four-block and AVX2 eight-block canonical stream/XOR APIs; scalar single-block and tails | IETF RFC 8439 stream cipher |
| XChaCha20 | Uses the same SSE2/NEON four-block and AVX2 eight-block canonical core after HChaCha20 | Stream cipher with a 192-bit nonce |
| Poly1305 | SSE2/NEON two-message and AVX2 four-message batch APIs | One-time MAC |
| AES-CTR | SSE2, AVX2, NEON counter/XOR paths; AES-NI is separately selected | AES in CTR mode |
| Argon2id/i | SSE2, AVX2, NEON block operations | Memory-hard password hashing |
| Custom KDF | Depends on the selected generator; mixing remains scalar | Memory-hard key derivation (tail-indexed xor rounds) |

Curated benchmark snapshots currently focus on the asymmetric and key-agreement paths. For symmetric tuning runs, use `nimble bench_custom_crypto` and `nimble bench_custom_kdf`.

### Asymmetric (pure Nim unless noted)

| Category | Algorithms | SIMD coverage | Benchmark-guided profile |
|----------|------------|---------------|--------------------------|
| **KEM** | Kyber (ML-KEM-512/768/1024) | SSE2/NEON four-pair and AVX2 eight-pair polynomial accumulation; coefficient helpers | Fastest PQ KEM family in the current curated snapshots; sub-ms on desktop and the measured phones |
| **KEM** | FrodoKEM (640/976/1344, AES + SHAKE) | Streamed matrix generation; SSE2/NEON 128-bit and AVX2 256-bit matrix products; optional Tyr-native AES-NI | Conservative, high-bandwidth path; AES-NI makes AES variants substantially faster, while streamed SHAKE avoids the full matrix allocation |
| **KEM** | BIKE-L1 | SSE2/NEON 128-bit decoder word helpers; multiplication remains scalar/Karatsuba | Tens-of-ms KEM in the current snapshots |
| **KEM** | NTRU (HPS-509/677/821, HRSS-701) | AVX2 16-lane and SSE2/NEON 8-lane cyclic multiplication selected automatically; scalar builds retain Toom-4 + K2 | Mid-latency KEM; current local AVX2 A/B is about 8-13% faster than K2 and needs refreshed cross-device snapshots |
| **KEM** | SABER (LightSaber/Saber/FireSaber) | AVX2 16-lane and NEON 8-lane schoolbook multiplication; SSE2 reduction-only path | Same low-latency class as Kyber in the curated snapshots; current SIMD core needs refreshed cross-device snapshots |
| **KEM** | Classic McEliece (6688128f/6960119f/8192128f) | AVX2 matrix fill, AVX2/SSE2/NEON masked keygen row XOR, and 8-lane AVX2 or 4-lane SSE2/NEON decoder root evaluation | Slowest measured KEM here; key generation dominates, but ciphertexts stay very small |
| **Sign** | Dilithium (ML-DSA-44/65/87) | AVX2 polynomial products and SSE2/NEON coefficient/hash batching | Fastest measured PQ signature family in the current curated snapshots |
| **Sign** | Falcon (512/1024) | SSE2/NEON two-lane FFT and norm helpers; most key generation remains scalar | Smallest PQ signatures here, but current pure-Nim snapshots are strongly keygen-dominated |
| **Sign** | SPHINCS+-SHAKE-128f-simple | AVX2 four-way and SSE2/NEON two-way SHAKE/WOTS batching | Slower than Dilithium, but far below current Falcon key-generation-dominated totals |
| **KA** | X25519 | SSE2/NEON two-way and AVX2 four-way batch APIs | Best current results come from SIMD batch paths; still sub-ms on desktop and phones |

`native_avx2`, `native_sse2`, and `native_neon` in benchmark JSON describe how
the executable was compiled. They do not assert that every listed algorithm is
fully vectorized. The SABER `saberClean`/`saberAvx2` value is compatibility and
reporting metadata: arithmetic is selected at compile time, so even an explicit
`saberClean` argument in an AVX2 build uses the pure-Nim AVX2 core. It does not
dispatch to the vendored PQClean C code.

Detailed parameter tables, key sizes, CT notes, and speed ranking: [docs/ALGORITHMS.md](docs/ALGORITHMS.md)

---

## Benchmark-Guided Performance

These numbers are not protocol guarantees. They are README-level guidance taken from the curated benchmark snapshots under [docs/benchmarks/](docs/benchmarks/), meant to help with rough algorithm selection and expectation-setting.

### KEMs

| Family | Desktop guidance | ARM64 phone guidance | Notes |
|--------|------------------|----------------------|-------|
| Kyber | about `0.06-0.13 ms` | about `0.33-0.91 ms` | Lowest-latency PQ KEM family in the current curated set |
| SABER | historical snapshot: about `0.14-0.27 ms` | historical snapshot: about `0.29-0.75 ms` | Predates the new AVX2/NEON multiplication core; use a fresh local benchmark for current numbers |
| NTRU | historical snapshot: about `2.34-4.57 ms` | historical snapshot: about `6.54-20.85 ms` | Predates automatic AVX2/SSE2/NEON cyclic multiplication; local AVX2 A/B improved 8-13% over K2 |
| FrodoKEM | current local native-fast: about `0.98-3.16 ms` AES and `5.01-19.50 ms` SHAKE | historical snapshots: about `21-133 ms` | AES requires explicit `-d:aesni -maes`; same-source A/B shows SHAKE row streaming about 18-23% faster; cross-device snapshots need refresh |
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
| **OpenSSL** | Ed448, RSA/ECDSA verify, X.509 checks, optional Frodo public AES matrix generation | `-d:hasOpenSSL3` |
| **nimcrypto** | AES-GCM | (import-time) |

Missing optional libraries raise `LibraryUnavailableError`.

`nimsimd` and SIMD-Nexus are intrinsic wrappers: they generate CPU instructions
inside Tyr's Nim implementation and do not call an external crypto library.
External C-library paths are opt-in through the defines above. In particular,
Frodo does not probe or load `libcrypto` unless `-d:hasOpenSSL3` is present.

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
| Otter-RepoEvaluation | `submodules/otter_repo_evaluation` (timing, benchmarks, and statistical evaluation) |

Local path overrides go in `.iron/.local.gitmodules.toml` (gitignored).

PQClean is a vendored collection of standalone C implementations of
post-quantum algorithms. Tyr uses it for reference vectors, interoperability,
and selected bindings. It is not the same as Tyr's pure-Nim `custom_crypto`
implementation, and merely having a PQClean AVX2 directory does not make that
code part of a Tyr call path. Upstream PQClean is no longer actively maintained,
so its code should be treated as pinned reference/vendor code rather than an
automatically updated security dependency.

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

Basic cipher, hash, and pure-Nim X25519/Kyber KEM operations are exported for
wasm/JS targets. The KEM names `kyber768` and `kyber1024` identify the pinned
CRYSTALS-Kyber round-3 implementation, not FIPS 203 ML-KEM.

### Build It Yourself

1. Install Nim and make sure `nim` is on `PATH`.
2. Install and activate Emscripten so `emcc` is on `PATH`.
3. Build the release bridge with `nimble build_wasm`.
4. Build a debug bridge with `nimble build_wasm_debug`.
5. Re-run the JSON bridge regression tests with `nimble test_wasm`.
6. Build the bridge and open the interactive browser/native dashboard with `nimble testUi`.
7. Run the complete headless WebUI browser matrix with `nimble test_webui_interop`.

The dashboard's top test rail can run the full suite, the WebUI transport probe,
functional tests, vectors/KATs, edge cases, benchmarks/profilers, or the live
browser-WASM matrix. Family buttons narrow the visible catalog to symmetric,
hash, MAC, password, entropy, classical, PQ KEM, PQ signature, composite, API,
interop, or benchmark entries. Every card can also be run by itself.
`nimble webui_interop` remains an alias-style launcher for the same interactive
dashboard.

The catalog contains more than 50 allowlisted groups, including the unified
benchmark tables and every specialized Sigma/Otter benchmark entrypoint that
imports `custom_crypto`.

Every catalog card is a paired test:

```text
card worker
  native compile -> native run
  WASM compile   -> Node/WASM run
```

The card has separate `Native` and `WASM` tabs with independent state, timing,
and log files. Both phases run in sequence even if one fails. Different cards
run concurrently in separate worker processes. The card play button becomes a
stop button while that card runs, and `Stop all` cancels every active worker.
Filters, family tabs, output controls, and other cards remain usable while
tests are running.

The launcher isolates failures using four process roles:

```text
testUi supervisor
  |-- WebUI host       <- relaunched after an abnormal exit
  `-- test spawner    <- owns the job registry
        `-- workers   <- one isolated process per active card
```

The WebUI host never compiles or executes catalog tests. A compiler crash,
native test crash, WASM runtime failure, or stopped worker is recorded in its
atomic job state without taking down the UI or test spawner.

The editable output field at the top defaults to `testResults/`. Pressing its
folder button opens the built-in directory picker; direct paths and `~/...`
paths are accepted as well. Every native test or benchmark writes:

- `<timestamp>-<job>-<test-id>-native.log`: native compile and run output.
- `<timestamp>-<job>-<test-id>-wasm.log`: Emscripten and Node/WASM output.
- `<timestamp>-<job>-<test-id>.json`: both phase states, durations, exit codes,
  stop state, and result paths.

The browser-WASM matrix writes the same `.log` and `.json` pair. `testResults/`
is ignored by Git so repeated local runs do not dirty the repository.

New cards use the `pairedTest` template in
`tests/webui_interop/test_catalog.nim`. The declaration supplies only metadata,
sources, fixed arguments, and optional WASM threading; shared worker code owns
compilation, native/WASM sequencing, logs, polling, crash isolation, and stop
handling.

Run `nimble test_testui_wasm_catalog` to compile-check every catalog source as
executable WASM. This is the completeness gate for future card additions.

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
| `basic.kemKeypair` | Create deterministic or random X25519/Kyber keypairs |
| `basic.kemEncaps` / `basic.kemDecaps` | Create and open X25519/Kyber KEM exchanges |
| `basic.blake3Hash` / `basic.blake3KeyedHash` | BLAKE3 hashing helpers |
| `basic.gimliHash` | Gimli hashing helper |
| `basic.sha3Hash` | SHA3 hashing helper |

### Minimal JS Usage

```js
import { loadTyrCrypto } from "./bindings/js/tyr_crypto.mjs";

const tyr = await loadTyrCrypto();
const key = crypto.getRandomValues(new Uint8Array(32));
const nonce = crypto.getRandomValues(new Uint8Array(24));
const message = new TextEncoder().encode("browser message");

const cipher = tyr.basic.encrypt({ algo: "xchacha20", key, nonce, message });
const plain = tyr.basic.decrypt({ algo: "xchacha20", key, nonce, payload: cipher.payload });

// `cipher.ciphertext` is sent to the remote X25519/Kyber key owner.
const receiver = tyr.basic.kemKeypair({ algo: "kyber768" });
const kem = tyr.basic.kemEncaps({ algo: "kyber768", receiverPublicKey: receiver.publicKey });
const shared = tyr.basic.kemDecaps({
  algo: "kyber768", receiverSecretKey: receiver.secretKey, ciphertext: kem.ciphertext,
});
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
