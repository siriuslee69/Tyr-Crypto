Commit Message: restructure custom crypto into symmetric and asymmetric folders

Features to implement:
- Stable high-level crypto wrapper API with predictable inputs/outputs.
- Pure Nim implementations for common primitives (XChaCha20, BLAKE3, etc.).
- Native bindings for libsodium, OpenSSL, and liboqs.
- Test vectors and regression tests for all supported primitives.
- Build and test nimble tasks for daily use and CI.
- Chunked file encryption + hashing wrapper for large files.

Implemented:
- libsodium bindings for AEAD, XChaCha20 stream, and Argon2 APIs.
- nimcrypto binding for AES-256-GCM.
- Pure Nim BLAKE3 and XChaCha20 (with HChaCha20) implementations.
- Wrapper-level encrypt/decrypt with tag verification.
- Unit tests for bindings, custom crypto, and wrapper API.
- Kyber+X25519 hybrid KEX variant and tests.
- Signature wrapper for Ed25519 and liboqs PQ signatures.
- SIMD-Nexus integration and Gimli SSE permutation.
- Gimli SSE regression test against reference.
- Gimli sponge helpers and XChaCha20+Gimli wrapper with tests.
- XChaCha20+AES+Gimli wrapper with configurable tag length.
- AES-CTR helper using nimcrypto core with optional SSE/AVX XOR.
- XChaCha20 SIMD keystream implementation with SSE/AVX lanes.
- Gimli reference vector test (c-ref).
- AES-CTR vs nimcrypto CTR + AES-GCM vs libsodium comparison tests.
- AES-CTR streaming state with in-place transforms.
- XChaCha20+AES+Gimli wrapper available without nimcrypto.
- ChunkyCrypto module with threaded chunk encrypt/decrypt + hash tree.
- Hybrid KEX modules renamed to duo/triple with ASCII headers.
- Bindings/builders moved into dedicated src folders.
- Pure Nim Kyber768/Kyber1024 backend with Tyr typed KEM materials and tests.
- Pure Nim Kyber validated against local liboqs byte-for-byte outputs and local KAT corpus hashes.
- Pure Nim FrodoKEM-976-AES backend with Tyr typed KEM materials and release-mode interop/KAT checks.
- Pure Nim ML-DSA-44/65/87 backend with Tyr typed signature materials and local liboqs/KAT validation.
- Pure Nim SPHINCS+-SHAKE-128f-simple backend with Tyr typed signature materials and local liboqs/KAT validation.
- Pure Nim BIKE-L1 backend with Tyr typed KEM materials and local liboqs/KAT validation.
- Frodo hot matrix-dot loops now use optional SSE2/AVX2 SIMD via SIMD-Nexus-backed 16-bit multiply-low helpers.
- Kyber polynomial add/sub now use optional SSE2/AVX2 SIMD coefficient lanes with scalar tails.
- Dilithium polynomial add/sub/shift-left now use optional SSE2/AVX2 SIMD coefficient lanes with scalar tails.
- SIMD-Nexus now exports missing generic `int32` helpers plus 16-bit multiply-low helpers for reusable PQ arithmetic paths.
- Sigma benchmark support now works again in this workspace, and Tyr has a dedicated `perf_sigma_pq` benchmark comparing the pure-Nim PQ backends against liboqs for the currently available algorithms.
- Otter wrapper-based PQ profiling now works through `perf_otter_pq` and prints the hottest timed Tyr PQ wrapper functions per algorithm family.
- Otter now captures real inner-function spans for Kyber (`genMatrix`, `indcpaKeypair`, `indcpaEnc`, `indcpaDec`), Frodo (`generateMatrixA`, `mulAddAsPlusE`, `mulAddSaPlusE`, `mulAddSbPlusE`, `mulBs`), and BIKE (`gf2xModMul`, `gf2xModInv`, `decodeBike`).
- Frodo no longer materializes the full AES matrix for keypair/encaps/decaps; the hot `A*s+e` and `s*A+e` paths now stream matrix stripes directly from AES.
- Frodo now has an optional AES-NI fast path (`-d:aesni` + `-maes`) for AES-128 block encryption, and the 4-row `A*s+e` generator uses a 4-way AES-NI block helper.
- `custom_crypto` implementations now live under `symmetric/` and `asymmetric/pq/`, while top-level module names remain compatibility facades and `asymmetric/none_pq/` is reserved for future non-PQ asymmetric code.

Working on:
- Argon2 pure Nim implementation or dedicated binding wrapper.
- Optional Poly1305 AEAD path for the wrapper-level XChaCha20 flow.
- Hybrid public-key crypto plan: 3-layer scheme using McEliece + Curve25519 + Kyber.

Last big change or problem:
- The `custom_crypto` tree had grown by algorithm name only, which made the symmetric vs asymmetric split implicit and left no reserved slot for non-PQ asymmetric code.

Fix attempt and result:
- Moved implementation folders under `src/protocols/custom_crypto/symmetric/` and `src/protocols/custom_crypto/asymmetric/pq/`, added top-level facades for moved single-file modules (`random`, `hmac`, `otp`), reserved `asymmetric/none_pq/`, then revalidated the public surface with `nim check` plus focused symmetric/PQ tests.

## 2026-04-04 First-pass Audit
Readiness: Not production ready yet—the repo still ships tracked binaries, the autopush automation never reads the audit log, and environment tooling keeps claiming missing headers even when the submodules are present.

Findings:
- [High] Several binaries such as `tests/test_all.exe`, `tests/test_chunky_crypto.exe`, etc. are tracked under `tests/`; these artifacts bloat the repo, force every clone to pull platform-specific output, and diverge from what contributors actually rebuild, so the repo cannot be treated as a clean, production-grade library until they are removed or moved to a release artifact store.
- [Medium] `task autopush` in `tyr_crypto.nimble` reads `iron/progress.md` but the tracked audit log lives at `.iron/PROGRESS.md`, so autopush never picks up the human-written commit message and instead falls back to the default string—it currently ignores the very metadata meant to describe what changed.
- [Medium] `tools/ensure_env.nim` checks for libsodium/liboqs/OpenSSL headers at paths such as `submodules/openssl/include/submodules/openssl/sha.h`, yet the real headers sit at `submodules/openssl/include/openssl/sha.h`; the mismatch makes `needSubmodules()` always return `true`, so every builder run claims the submodules (and their headers) are missing even when they are already checked out.

Next steps:
- [ ] Stop tracking the generated `tests/*.exe` artifacts (e.g., delete them, add the pattern to `.gitignore`, and rely on `nimble test` runs to produce them locally).
- [ ] Point `task autopush` at `.iron/PROGRESS.md` (and make sure it handles the upgrade from uppercase to lowercase paths) so the commit message reflects the audit log.
- [ ] Fix `opensslHeader` (and any other header paths in `tools/ensure_env.nim`) to match the actual layout under `submodules/*/include/`, allowing `needSubmodules()` to detect the headers correctly.

## 2026-04-04 First-pass Audit
Readiness: Not production ready yet—the repo still ships tracked binaries, the autopush automation never reads the audit log, and environment tooling keeps claiming missing headers even when the submodules are present.

Findings:
- [High] Numerous binaries such as `tests/test_all.exe`, `tests/test_chunky_crypto.exe`, etc. are tracked under `tests/`; these artifacts bloat the repo, force every clone to fetch 50+ MB of platform-specific output, and will diverge from what contributors actually rebuild, so the repo cannot be treated as a clean, production-grade library until they are removed or moved to a release artifact store.
- [Medium] `task autopush` in `tyr_crypto.nimble` reads `iron/progress.md` but the tracked audit log lives at `.iron/PROGRESS.md`, so autopush never picks up the human-written commit message and instead falls back to the default string—it currently ignores the very metadata meant to describe what changed.
- [Medium] `tools/ensure_env.nim` verifies the libsodium/liboqs/OpenSSL headers by looking for `submodules/openssl/include/submodules/openssl/sha.h`, yet the real header path is `submodules/openssl/include/openssl/sha.h`, so the check always fails, `nimble build_*` reruns `git submodule update` every time, and the environment setup reports missing dependencies even though the submodules are already checked out.

Next steps:
- [ ] Stop tracking the generated `tests/*.exe` artifacts (e.g. delete them, add the pattern to `.gitignore`, and rely on `nimble test` runs to produce them locally).
- [ ] Point `task autopush` at `.iron/PROGRESS.md` (and make sure it handles the upgrade from uppercase to lowercase paths) so the commit message reflects the audit log.
- [ ] Fix `opensslHeader` (and any other header paths in `tools/ensure_env.nim`) to match the real layout under `submodules/*/include/`, so `needSubmodules()` can detect the headers and stop insisting that the submodules are missing.

## 2026-04-04 Implementation Pass
Summary: Completed the feasible fixes from the first-pass findings without touching frontend code.

Implemented:
- Updated `task autopush` in `tyr_crypto.nimble` to read `.iron/PROGRESS.md` first, then fallback to `.iron/progress.md` and legacy `iron/progress.md`.
- Fixed `tools/ensure_env.nim` header probes to real include paths:
  - `submodules/openssl/include/openssl/sha.h`
  - `submodules/libsodium/src/libsodium/include/sodium/crypto_hash_sha256.h`
- Cleaned local test binaries with `git clean -fX tests` and verified no tracked `.exe` files remain via `git ls-files "*.exe"` (empty output).

Verification:
- `nim check tools\\ensure_env.nim` (pass)
- `nim check src\\tyr_crypto\\registry.nim` (pass)
- `nim r tools\\ensure_env.nim -- --submodules` (fails in this sandbox due default nimcache path write error at `C:\\Users\\n1ght\\nimcache\\...`)
- `nim c -r --nimcache:._tmp_nimcache_ensure tools\\ensure_env.nim -- --submodules` (pass)

Remaining blockers:
- Environment-level Nim default nimcache write path is not writable in this sandbox unless `--nimcache` is overridden.

## 2026-04-06 Wasm Binding Pass
Summary: Added a Nim-first JS/TS wasm bridge instead of rewriting Tyr logic in JavaScript.

Implemented:
- Added `src/tyr_crypto/wasm/` with a JSON + base64 bridge for `capabilities`, `encrypt`, `decrypt`, `blake3Hash`, and `blake3KeyedHash`.
- Added `src/tyr_crypto/wasm/exports.nim` so the bridge can be compiled as a C ABI surface for Emscripten.
- Added `bindings/js/tyr_crypto.mjs` and `bindings/js/tyr_crypto.d.ts` as the checked-in JS/TS loader layer.
- Added `tools/build_wasm.nim` plus `nimble build_wasm`, `nimble build_wasm_debug`, and `nimble test_wasm`.
- Added `tests/test_wasm_bridge.nim` and included it in `tests/test_all.nim`.

Verification:
- `nim check --nimcache:build\\nimcache_wasm_check src\\tyr_crypto\\wasm\\exports.nim` (pass)
- `nim check --nimcache:build\\nimcache_wasm_tool tools\\build_wasm.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_wasm_test tests\\test_wasm_bridge.nim` (pass)

Remaining blockers:
- `emcc` is not installed in this environment, so `nimble build_wasm` could not be executed here.

