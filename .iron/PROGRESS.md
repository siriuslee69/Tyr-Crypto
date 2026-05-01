Commit Message: add non-NTRU/SABER paper cache lock and license policy

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
- Pure Nim NTRU KEM support for HPS-2048-509, HPS-2048-677, HPS-4096-821, and HRSS-701 with NIST KAT DRBG replay and liboqs/PQClean KAT hash validation.
- Pure Nim SABER KEM support for LightSaber, Saber, and FireSaber with official SABER `.rsp` vector validation.
- PQClean reference NTRU/SABER bindings moved into `src/protocols/bindings`, with the used reference sources moved under `submodules/pqclean_*_ref`.
- NTRU/SABER polynomial reduction now has pure Nim SIMD hooks for AVX2/SSE2 and ARM64/NEON compile paths, while the KEM APIs dispatch through the Nim core by default.
- ARM64/NEON compile checks now include NTRU/SABER mobile-target coverage through the pure Nim backends.
- NTRU/SABER now have OtterBench instrumentation on the public KEM wrappers and main core hot paths, and focused desktop plus three-phone benchmark JSONs are included in `docs/benchmarks`.
- NTRU/SABER security and optimization papers are stored and indexed under `docs/research/ntru_saber`, with implementation findings and next-step guidance.
- NTRU/SABER research PDFs now have a checksum lock, downloader, ignore policy, and license notes so ambiguous documents stay local-cache only.
- NTRU mod-3 reduction now uses the lower-leakage branchless form from the NTRU side-channel literature, and the shared PQ wipe helper uses volatile stores for transient secret byte buffers.
- NTRU's KAT-compatible Toom-4 plus two-level Karatsuba pure-Nim multiplier is now the default, with exact Toom, coefficient, temp/reduce, and row-style trial variants kept behind benchmark flags.
- SABER's tested split-loop and Toom multiplier variants are retained only as opt-in benchmark flags because they were KAT-correct but slower than the existing temp/reduce path.
- NTRU/SABER desktop and three-phone OtterBench JSON/HTML reports have been refreshed under `docs/benchmarks`, with experimental optimization trial JSONs archived under `docs/research/ntru_saber/benchmarks`.
- Non-NTRU/SABER PQ research papers are stored and indexed under `docs/research/pq_non_ntru_saber`, with source comments tying paper-backed optimization and hardening notes to exact code hotspots.
- Non-NTRU/SABER PQ research PDFs now have a checksum lock, downloader, ignore policy, and license notes so ambiguous specification PDFs stay local-cache only.
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
- Added `tools/bench_pq_profiles.nim` plus a `nimble bench_pq_profiles` task to build matched `liboqs_min_pq_scalar` / `liboqs_min_pq_avx2` profiles and run the Sigma PQ comparison suites with the intended Tyr scalar and AVX2 flags.
- Added `Otter-RepoEvaluation` to the visible submodule manifest and local submodule path resolution used by Tyr's Otter profiling tasks.
- Added `nimble test_neon_checks` and `nimble test_simd_matrix` so NEON coverage is a first-class runnable path instead of living only in manual notes.
- Added `tests/test_android_custom_crypto.nim` as an Android-targeted custom/SIMD subset.
- Added `tests/android_harness` plus build/run scripts to package and execute the native test harness inside a minimal Android app.

Working on:
- Argon2 pure Nim implementation or dedicated binding wrapper.
- Optional Poly1305 AEAD path for the wrapper-level XChaCha20 flow.
- Hybrid public-key crypto plan: 3-layer scheme using McEliece + Curve25519 + Kyber.

Last big change or problem:
- Non-NTRU/SABER PQ research PDFs needed the same redistribution-safe repo policy as the NTRU/SABER papers: keep clearly licensed documents, avoid committing ambiguous PDFs, and keep local copies intact.

Fix attempt and result:
- Added `docs/research/pq_non_ntru_saber/papers.lock.json`, `download_papers.ps1`, and `LICENSES.md`. `.gitignore` now ignores unclassified non-NTRU/SABER research PDFs by default while whitelisting CC-BY/CC0 ePrint documents. Five ambiguous specification PDFs were removed from the git index with `git rm --cached` and remain present locally.

Verification:
- `git diff --check` passed; it only reported existing LF-to-CRLF warnings from Git on this Windows checkout.
- `powershell -ExecutionPolicy Bypass -File docs\research\ntru_saber\download_papers.ps1 -IncludeTracked` verified all paper/supporting-document hashes.
- `powershell -ExecutionPolicy Bypass -File docs\research\pq_non_ntru_saber\download_papers.ps1 -IncludeTracked` verified all non-NTRU/SABER paper/spec hashes.
- `nim check --nimcache:build\nimcache_pq_research_kyber tests\test_kyber_tyr.nim` passed.
- `nim check --nimcache:build\nimcache_pq_research_dilithium tests\test_dilithium_tyr.nim` passed.
- `nim check --nimcache:build\nimcache_pq_research_frodo tests\test_frodo_tyr.nim` passed.
- `nim check --nimcache:build\nimcache_pq_research_bike tests\test_bike_tyr.nim` passed.
- `nim check --nimcache:build\nimcache_pq_research_falcon tests\test_falcon_tyr.nim` passed.
- `nim check --nimcache:build\nimcache_pq_research_mceliece tests\test_mceliece_tyr.nim` passed.
- `nim check --nimcache:build\nimcache_pq_research_sphincs tests\test_sphincs_tyr.nim` passed.
- `nim c --nimcache:build/nimcache_test_ntru_tyr -r tests/test_ntru_tyr.nim` passed after fixing the volatile wipe pointer path.
- `nimble test_ntru_saber` passed.
- `nimble test_ntru_saber_avx2` passed.
- NTRU rollback/trial builds `-d:ntruMulToom4K2`, `-d:ntruMulToom4`, and `-d:ntruMulCoeff` passed focused KAT/roundtrip test runs after the K2 default promotion.
- SABER `-d:saberMulToom4Cached` passed focused official-vector tests after the cached-Toom path was added.
- `nim check` passed for default NTRU, `-d:ntruMulTmp`, `-d:ntruIsoSample`, and `tools/collect_asymmetric_benchmarks.nim`.
- NTRU rollback/trial builds `-d:ntruMulTmp`, `-d:ntruMulRows`, `-d:ntruMulRowsUnroll4`, and `-d:ntruIsoSample` passed their focused test runs; the two row variants had to be rerun sequentially because parallel runs shared the same temp KAT filename.
- SABER trial builds `-d:saberMulRows`, `-d:saberMulRowsUnroll4`, and `-d:saberMulCoeff` passed focused SABER KAT/vector tests.
- Final OtterBench runs completed for the Windows AVX2 workstation plus connected Infinix X6871, motorola edge 50 fusion, and moto g56 5G Android/NEON devices.

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

## 2026-04-21 Frodo Variant Expansion
Summary: Expanded the pure-Nim Frodo backend and wrapper API from the old single `frodo976aes` shape to the full `640/976/1344 x AES/SHAKE` matrix, exposed through tiered basic API names.

Implemented:
- Added custom Frodo parameter sets for `frodo640aes`, `frodo640shake`, `frodo976aes`, `frodo976shake`, `frodo1344aes`, and `frodo1344shake`.
- Generalized the custom Frodo XOF and matrix-generation flow so AES and SHAKE variants share the same core operations while still selecting the correct Frodo-specific SHAKE width and matrix generator.
- Extended the wrapper KEM enums, algorithm kinds, typed materials, and `liboqs` algorithm IDs so Frodo is now exposed as tier `0/1/2` plus explicit `Aes` and `Shake` suffixes, matching the McEliece-style tiering.
- Updated the focused Frodo tests and quick API metadata checks to cover the six wrapper surfaces and all six pure-Nim custom variants.
- Fixed the remaining `frodo640*` arithmetic assumptions by reducing generic Frodo math modulo `q` and reducing generated matrix entries to the active parameter set's modulus instead of relying on implicit `uint16` wraparound.

Verification:
- `nim check --nimcache:build\\nimcache_frodo_params src\\protocols\\custom_crypto\\asymmetric\\pq\\frodo\\params.nim` (pass)
- `nim check --nimcache:build\\nimcache_frodo_ops_fix src\\protocols\\custom_crypto\\asymmetric\\pq\\frodo\\operations.nim` (pass)
- `nim check --nimcache:build\\nimcache_basic_api src\\protocols\\wrapper\\basic_api.nim` (pass)
- `nim check -d:release --nimcache:build\\nimcache_test_quick_check tests\\test_quick_api.nim` (pass)
- `nim check -d:release --nimcache:build\\nimcache_test_frodo_check2 tests\\test_frodo_tyr.nim` (pass)
- `nim c -r -d:release --nimcache:build\\nimcache_test_quick_run2 tests\\test_quick_api.nim` (pass)
- `nim c -r -d:release --nimcache:build\\nimcache_test_frodo_run2 tests\\test_frodo_tyr.nim` (pass)

Remaining blockers:
- The exact-match and interop branches in `tests/test_frodo_tyr.nim` only compile and run when `-d:hasLibOqs` is enabled; that path was not active in this verification environment, so the new custom/liboqs Frodo byte-for-byte comparisons were not executed here.

## 2026-04-24 Endian + NEON Pass
Summary: Removed the remaining host-endian shortcuts I found in the custom crypto stack and added a first NEON-backed SIMD path through `SIMD-Nexus` for the portable 128-bit lane consumers.

Implemented:
- Replaced host-endian word stores/loads in the XChaCha20 SIMD keystream writer, SHA3 OpenSSL word extraction, Frodo AES block decoding, and McEliece byte-word copies with explicit little-endian handling.
- Extended `SIMD-Nexus` with missing NEON-capable high-level helpers for `uint16x8`, `uint32x4`, and `uint64x2`, plus byte-lane XOR helpers and the missing `simd_nexus/simd/generic_u32` / `generic_u64` wrapper exports.
- Wired NEON-aware SIMD paths into Tyr's BLAKE3, SHA3, Poly1305, Gimli, XChaCha20, and AES-CTR code, keeping the existing SSE2/AVX2 behavior intact on x86.
- Added lighter-weight NEON coefficient-lane hooks for Kyber polynomial add/sub and Dilithium polynomial add/sub/shift-left via the `SIMD-Nexus` wrapper layer.
- Added NEON-gated SIMD parity tests alongside the existing SSE/AVX coverage for XChaCha20, BLAKE3, SHA3, Poly1305, Gimli, and AES-CTR.

Verification:
- `nim check --nimcache:build\\nimcache_check_simd_nexus src\\simd_nexus.nim` in `SIMD-Nexus` (pass)
- `nim check --cpu:arm64 -d:neon` for `tests\\test_xchacha20_simd.nim`, `tests\\test_blake3_simd.nim`, `tests\\test_sha3_simd.nim`, `tests\\test_poly1305_simd.nim`, `tests\\test_gimli_sse.nim`, `tests\\test_aes_ctr.nim`, `tests\\test_custom_crypto.nim`, `tests\\test_kyber_tyr.nim`, and `tests\\test_dilithium_tyr.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_custom_crypto tests\\test_custom_crypto.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_aes_ctr tests\\test_aes_ctr.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_xchacha tests\\test_xchacha20_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_blake3 tests\\test_blake3_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_sha3 tests\\test_sha3_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_poly1305 tests\\test_poly1305_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_gimli tests\\test_gimli_sse.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_frodo tests\\test_frodo_tyr.nim` (pass)
- `nim c -r -d:release --out:build\\test_mceliece_release_run.exe --nimcache:build\\nimcache_run_mceliece_release2 tests\\test_mceliece_tyr.nim` (pass)

Remaining blockers:
- Some deeper PQ hot paths are still AVX2-specific and therefore fall back to scalar on ARM64/NEON today, especially the heavier Frodo stream-accumulation kernels and the larger AVX2-only Kyber/Dilithium arithmetic helpers outside the new coefficient-lane hooks.

## 2026-04-26 Revalidation + Android Harness Pass
Summary: reran the host custom/SIMD suite, integrated the NEON matrix into nimble tasks, fixed a real ARM64-native NEON codegen bug in `SIMD-Nexus`, and validated the native test harness on an Android phone and inside a minimal Android app.

Implemented:
- Re-ran the host-side custom crypto tests for:
  - `test_custom_crypto`
  - `test_aes_ctr`
  - `test_xchacha20_simd`
  - `test_blake3_simd`
  - `test_sha3_simd`
  - `test_poly1305_simd`
  - `test_gimli_sse`
  - `test_x25519_simd`
- Added `test_neon_checks` and `test_simd_matrix` tasks to `tyr_crypto.nimble`.
- Added `tools/zigcc_linux_aarch64.cmd` / `tools/zigcc_linux_x86_64.cmd` for Zig-based Linux cross-compiles used by the Android harness flow.
- Added `tests/test_android_custom_crypto.nim` to package only the relevant custom/SIMD suites into the Android-native harness binary.
- Fixed `SIMD-Nexus/src/protocols/simd/base_operations.nim` so the NEON dynamic shift paths no longer force compile-time-only intrinsics during real ARM64 C compilation.
- Added an Android harness app under `tests/android_harness` that runs the packaged native binary from `nativeLibraryDir` and writes output to `files/last_test_output.txt`.

Verification:
- `nim c -r --nimcache:build\\nimcache_run_custom_crypto_again tests\\test_custom_crypto.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_aes_ctr_again tests\\test_aes_ctr.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_xchacha_again tests\\test_xchacha20_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_blake3_again tests\\test_blake3_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_sha3_again tests\\test_sha3_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_poly1305_again tests\\test_poly1305_simd.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_gimli_again tests\\test_gimli_sse.nim` (pass)
- `nim c -r --nimcache:build\\nimcache_run_x25519_again tests\\test_x25519_simd.nim` (pass)
- `nimble test_neon_checks` (pass)
- `nimble test_simd_matrix` (pass)
- ARM64 native harness cross-compile:
  - `nim c --os:linux --cpu:arm64 -d:neon ... tests\\test_android_custom_crypto.nim` (pass)
- x86_64 native harness cross-compile:
  - `nim c --os:linux --cpu:amd64 ... tests\\test_android_custom_crypto.nim` (pass)
- Android harness APK build:
  - `tests/android_harness/gradlew.bat assembleDebug` (pass)
- Motorola app run:
  - installed APK, launched `org.tyrcrypto.harness.MainActivity`, and read back `files/last_test_output.txt` via `run-as` (pass)
- Motorola direct native run:
  - `adb shell /data/local/tmp/test_android_custom_crypto_arm64` (pass)

Remaining note:
- The x86_64 emulator installs and launches the harness app, but the packaged x86_64 native binary currently exits with code `139`, so only the ARM64 phone path is fully validated today.

## 2026-04-26 Motorola Asymmetric/PQ Pass
Summary: extended the Android-native validation from the custom/SIMD subset into the pure asymmetric/PQ stack on the Motorola and found a real ARM64-specific Kyber issue.

Implemented:
- Added `tests/test_android_asymmetric_crypto.nim` and `tests/test_android_asymmetric_fast.nim` as Android-targeted asymmetric/PQ harness entrypoints.
- Added a lightweight `{.otterTrace.}` pragma in `src/protocols/helpers/otter_support.nim` for function entry/leave tracing without manual `echo` instrumentation.
- Applied `otterTrace` to the top-level pure-Nim asym/PQ entrypoints:
  - X25519 facade
  - Kyber operations
  - Frodo operations
  - BIKE operations
  - Dilithium operations
  - Falcon operations
  - SPHINCS operations
  - McEliece operations

Verification:
- Full ARM64 release asym/PQ harness cross-compiled successfully:
  - `tests/test_android_asymmetric_crypto.nim`
- Reduced ARM64 release asym/PQ harness cross-compiled successfully:
  - `tests/test_android_asymmetric_fast.nim`
- Motorola direct run of the reduced asym/PQ harness completed and surfaced a failing Kyber test:
  - `cached polyvec basemul matches scalar reference` in `tests/test_kyber_tyr.nim`
  - failing coefficients differ by exactly `3329`, which points to an ARM64/NEON normalization/reduction mismatch rather than random corruption.

Current result:
- Pure ARM64 phone coverage is no longer just "slow"; there is an actionable Kyber bug on the Motorola in the cached polyvec multiply path.
- The full asym/PQ app-hosted harness still runs too long to treat as healthy without more targeted tracing or per-family splitting.

## 2026-04-26 Kyber Cached Multiply Fix
Summary: fixed the Motorola ARM64 Kyber cached-polyvec mismatch and reran the reduced asymmetric/PQ harness sequentially on device.

Root cause:
- `polyvecBaseMulAccMontgomeryCached` in `src/protocols/custom_crypto/asymmetric/pq/kyber/polyvec.nim` skipped the final `polyReduce(r)` step that the reference `polyvecBaseMulAccMontgomery` path performs.
- The earlier phone-only mismatch by exactly `3329` was a representation-normalization bug, not random arithmetic corruption.

Implemented:
- Added the missing `polyReduce(r)` at the end of `polyvecBaseMulAccMontgomeryCached`.
- Kept the new Android ARM64/phone validation flow and the new `otterTrace` pragma support in place for future long-running PQ investigation.

Verification:
- `nim c -r -d:release --nimcache:build\\nimcache_run_kyber_host_fix tests\\test_kyber_tyr.nim` (pass)
- Rebuilt `tests/test_android_asymmetric_fast.nim` for Linux ARM64 + NEON and reran it sequentially on the Motorola (pass)

Current result:
- The reduced Motorola asymmetric/PQ harness now passes for:
  - X25519
  - Kyber
  - BIKE
  - Dilithium
  - Falcon
- The heavier Android-hosted full asymmetric/PQ harness is still not treated as complete validation yet because it remains much slower and still needs staged/per-family execution before it is practical to rely on for quick regression checks.

## 2026-04-26 Android Asymmetric Harness Runtime Pass
Summary: turned the Android harness scripts into target-aware tooling, fixed the app-run polling path, and made the "fast" asymmetric phone bundle actually fast by replacing the full Falcon suite there with a smaller Falcon-512 smoke subset.

Implemented:
- Parameterized `tools/build_android_harness.ps1` with `custom_crypto`, `asymmetric_fast`, and `asymmetric_full` targets plus optional release builds.
- Added `nimble build_android_harness_asymmetric_fast` and `nimble build_android_harness_asymmetric_full`.
- Reworked `tools/run_android_harness.ps1` so it polls `files/last_test_output.txt` until completion instead of assuming every run finishes in 8 seconds.
- Added `tests/test_falcon_tyr_android_smoke.nim` and switched `tests/test_android_asymmetric_fast.nim` to use that smoke subset instead of the full Falcon suite.

Verification:
- Motorola direct native run of the original reduced asymmetric bundle: about 423 seconds, with `test_falcon_tyr.nim` alone accounting for about 421 seconds.
- Motorola direct native run of the full asymmetric bundle: about 433 seconds, all suites passed.
- Motorola direct native run of the updated reduced asymmetric bundle: about 27 seconds, all suites passed.
- Motorola Android app-hosted run of the updated reduced asymmetric bundle via `tools/run_android_harness.ps1 -TimeoutSeconds 300`: pass with `exit=0`.

Remaining note:
- The full asymmetric/PQ Android bundle is correct on the Motorola, but it is still an exhaustive run rather than a quick phone smoke test because the full Falcon suite remains expensive on ARM64.

## 2026-04-26 ARM64 Asymmetric NEON Expansion Pass
Summary: added the next realistic phone-side ARM64/NEON expansion points in the asymmetric stack instead of claiming blanket coverage where the code was still scalar.

Implemented:
- Extended the X25519 shared implementation template so ARM64 can use the existing generic 2-lane SIMD batch flow through `uint64x2`.
- Added exported `x25519ScalarmultBatchNeon2x` / `x25519TyrSharedNeon2x` support through the pass modules and top-level X25519 facade.
- Added a NEON byte-lane row-XOR fast path in Classic McEliece `pkGen`, targeting the elimination loops that previously stayed scalar on ARM64.
- Extended the ARM64/NEON compile-check matrix to include `tests/test_x25519_simd.nim` and `tests/test_mceliece_tyr.nim`.
- Added ARM64-aware X25519 perf and Otter perf test branches so the new NEON path has normal benchmark entrypoints.

Verification:
- Host regression:
  - `nim c -r --nimcache:build\\nimcache_run_x25519_simd_host tests\\test_x25519_simd.nim` (pass)
  - `nim c -r -d:release --nimcache:build\\nimcache_run_mceliece_host tests\\test_mceliece_tyr.nim` (pass)
- ARM64/NEON compile-check:
  - `nim check --cpu:arm64 -d:neon --nimcache:build\\nimcache_check_x25519_neon tests\\test_x25519_simd.nim` (pass)
  - `nim check --cpu:arm64 -d:neon --nimcache:build\\nimcache_check_mceliece_neon tests\\test_mceliece_tyr.nim` (pass)
- Motorola direct runs:
  - `tests/test_x25519_simd.nim` (pass, exercises `NEON2x batch matches scalar across all passes`)
  - `tests/test_mceliece_tyr.nim` (pass)

Remaining note:
- This pass does not mean "all asymmetric algorithms are now NEON-accelerated". Falcon is still effectively scalar on ARM64 in this repo, Frodo's explicit wide arithmetic is still x86-SIMD-only, and SPHINCS batch hashing is still x86-gated at the call-site level even though the shared SHA3 layer has ARM64 SIMD underneath.

## 2026-04-26 Asymmetric 128-bit SIMD Consolidation Pass
Summary: pushed the next realistic asymmetric SIMD layer across both older x86 and ARM64 instead of only adding isolated phone fixes.

Implemented:
- SPHINCS:
  - widened the 2-lane SHAKE batch wrappers in `sphincs/hash.nim` so they are no longer x86-only.
  - added real 2-lane batch use in the WOTS verification and signing leaf paths in `sphincs/wots.nim` and `sphincs/merkle.nim`.
  - fixed the first regression in that new path by restoring the per-step `hashAddr` update before each batched `thash1Batch2` call.
- McEliece:
  - kept the earlier ARM64 NEON row-XOR fast path.
  - validated that the default x86 build still exercises the SSE2-side row-XOR path cleanly, and that the AVX2 build still passes.
- X25519:
  - kept the new `NEON2x` batch path and revalidated both the x86 SSE2/AVX batch paths and the ARM64 phone path after the rest of the asymmetric edits.
- Kyber:
  - added a 128-bit SSE2 cached-polyvec basemul path in `kyber/polyvec.nim` so older x86 no longer falls straight from AVX2 to scalar for that hot path.
  - deliberately did not fake a NEON version of that kernel because the available NEON bindings in this environment do not expose the signed 16-bit widening multiplies that the cached Kyber arithmetic needs for a correct 1:1 port.
- Repo wiring:
  - extended `nimble test_neon_checks` / `test_simd_matrix` compile coverage to include `tests/test_sphincs_tyr.nim` alongside the earlier X25519/McEliece additions.

Verification:
- SPHINCS:
  - `nim c -r tests\\test_sphincs_tyr.nim` (pass)
  - `nim c -r -d:release tests\\test_sphincs_tyr.nim` (pass)
  - `nim c -r -d:release -d:avx2 --passC:"-mavx2" --passL:"-mavx2" tests\\test_sphincs_tyr.nim` (pass)
  - ARM64 release cross-compile + Motorola direct run of `tests\\test_sphincs_tyr.nim` (pass)
- Kyber:
  - `nim c -r tests\\test_kyber_tyr.nim` (pass, exercises the new SSE2 cached path on host)
  - `nim c -r -d:avx2 --passC:"-mavx2" --passL:"-mavx2" tests\\test_kyber_tyr.nim` (pass)
  - ARM64 release cross-compile + Motorola direct run of `tests\\test_kyber_tyr.nim` (pass)
- X25519:
  - `nim c -r tests\\test_x25519_simd.nim` (pass)
  - `nim c -r -d:avx2 --passC:"-mavx2" --passL:"-mavx2" tests\\test_x25519_simd.nim` (pass)
  - ARM64 release cross-compile + Motorola direct run of `tests\\test_x25519_simd.nim` (pass, including `NEON2x batch matches scalar across all passes`)
- McEliece:
  - `nim c -r -d:release tests\\test_mceliece_tyr.nim` (pass)
  - `nim c -r -d:avx2 --passC:"-mavx2" --passL:"-mavx2" tests\\test_mceliece_tyr.nim` (pass)
  - ARM64 release cross-compile + Motorola direct run of `tests\\test_mceliece_tyr.nim` (pass)
- Repo-level matrix:
  - `nimble test_neon_checks` (pass)

Remaining note:
- A correct NEON port of Kyber's cached polyvec basemul likely needs either extra signed 16-bit widening multiply bindings in `nimsimd/neon` or a more manual signed-lane expansion strategy. I did not ship an unsigned approximation there.

## 2026-04-26 Cross-device Asymmetric Benchmark Report Pass
Summary: built a reusable structured benchmark collector + HTML renderer, gathered desktop and Motorola datasets, and isolated a Motorola-specific x25519 benchmark stability caveat instead of hiding it.

Implemented:
- Added `tools/collect_asymmetric_benchmarks.nim`:
  - emits structured JSON rows for whole-algorithm summary timings and per-function Otter aggregates.
  - supports `--profile`, `--only=<family>`, `--phase=<summary|function|both>`, `--scale`, and `--verbose`.
  - records metadata such as local/UTC timestamp, compiled backend, device label, phase, and loop scale.
- Added `tools/render_asymmetric_benchmark_report.nim`:
  - merges multiple benchmark JSON files into one self-contained sortable HTML report.
  - uses an Avalon-style glass topbar, search, filter chips, and sort buttons.
  - shows per-run cards including phase and loop scale so reduced-scale runs are visible.
- Fixed the `otterTiming` compile ambiguity in `src/protocols/helpers/otter_support.nim` by stopping the helper from re-exporting the raw Otter package.
- Produced benchmark datasets under `build/benchmarks/` for:
  - desktop AVX2
  - Motorola phone families: `x25519` (reduced scale), `kyber`, `bike`, `mceliece`, `dilithium`, `sphincs`, `frodo`, `falcon`
- Produced the merged HTML report:
  - `build/benchmarks/asymmetric_bench_report_full.html`

Verification:
- Desktop collector build:
  - `tools/collect_asymmetric_benchmarks.nim` compiled and ran, producing `asymmetric_desktop.json`
- Phone family runs:
  - `kyber` full phone scale: pass
  - `bike` full phone scale: pass
  - `mceliece` full phone scale: pass
  - `dilithium` full phone scale: pass
  - `sphincs` full phone scale: pass
  - `frodo` full phone scale: pass
  - `falcon` full phone scale: pass
  - `x25519` reduced phone scale (`--scale=0.001`): pass for both scalar and `neon2x` rows
- HTML renderer build + final merge:
  - `build/benchmarks/asymmetric_bench_report_full.html` generated successfully

Important caveat:
- The Motorola `x25519` summary benchmark causes a device `kernel_panic` at normal mobile scale even before other families start when the family filter is set correctly. The safe data included in the report for Motorola `x25519` is therefore from the explicit reduced-scale run (`loop_scale = 0.001`), and that reduced scale is visible in the report metadata.
- The Android x86_64 emulator was not useful as a secondary native x25519 benchmark/debug target here: the collector run and a direct `test_x25519_simd_x86_64_linux` run both failed immediately under the emulator, so the final report does not include emulator timing rows.

## 2026-04-30 X25519 Benchmark Failure Isolation Pass
Summary: revisited the phone-side `x25519` benchmark instability with the corrected family filter and showed that the crypto implementation itself is not the thing crashing.

Implemented:
- Fixed the benchmark collector so `--only=<family>` is actually reliable when used in-value form and added extra isolation flags:
  - `--implementation=<pass>`
  - `--backend=<scalar|sse2x|neon2x|avx4x>`
- Added `tools/probe_x25519_stability.nim` as a minimal direct stress runner that removes the JSON/report aggregation layer and can target one pass/backend at a time.
- Re-ran `x25519` summary collection on:
  - Motorola Edge 50 Fusion
  - Infinix X6871
  - Moto G56 5G
- Captured full-scale `x25519` summary JSON for all three phones by saving stdout before the post-run crash:
  - `build/benchmarks/x25519_phone_summary_scale_0_5.json`
  - `build/benchmarks/x25519_infinix_summary_scale_0_5.json`
  - `build/benchmarks/x25519_moto_g56_summary_scale_0_5.json`
- Regenerated `build/benchmarks/asymmetric_bench_report_full.html` with the extra phone-side `x25519` summary runs included.

Findings:
- The earlier assumption that the Motorola reboot was definitely a pure `x25519` algorithm failure was too strong.
- With the corrected family filter:
  - Motorola `x25519` summary is stable at `loop_scale = 0.001`, `0.05`, `0.1`, and `0.25`.
  - At `loop_scale = 0.5`, the collector completes all scalar and `neon2x` rows and emits valid JSON, then the process dies with user-space `SIGSEGV`.
- The exact same post-run `SIGSEGV` after full `x25519` summary completion reproduces on:
  - Edge 50 Fusion
  - Infinix X6871
  - Moto G56 5G
- The dedicated direct `x25519` probe:
  - passes `pass3/neon2x` and `pass4/neon2x` on the Motorola at the same loop counts used by the collector
  - passes the full eight-row `x25519` sequence (all four scalar passes plus all four `neon2x` passes) on the Motorola
  - also passes when compiled with `-d:otterTiming`

Current conclusion:
- The evidence now points away from:
  - a pure `x25519` scalar math bug
  - a pure `x25519` NEON math bug
  - an Edge-50-specific kernel issue
- The most likely culprit is the ARM64 benchmark collector/report aggregation path around the `x25519` summary run itself, not the crypto implementation being benchmarked.

## 2026-04-30 X25519 Benchmark Runtime Fix
Summary: found and fixed the actual runtime cause of the weird post-run `x25519` benchmark crashes on Android shell binaries.

Root cause:
- `submodules/otter_repo_evaluation/src/protocols/state.nim` defaulted Otter timing flushes to `build/otter_timings.log`.
- On Android shell binaries, that default path resolved to an unwritable/read-only location instead of a repo-local build directory.
- When `-d:otterTiming` was enabled, the process completed the benchmark rows, then the registered exit hook attempted to flush timings during shutdown and crashed or faulted in that bad-path exit sequence.
- This is why:
  - the direct `x25519` probe passed without the collector/report layer,
  - the minimal `x25519 + JsonNode + otterTiming` probe still crashed,
  - and the same failure reproduced across multiple ARM64 phones.

Implemented:
- Updated `submodules/otter_repo_evaluation/src/protocols/state.nim` so Otter now chooses a writable Android default:
  - honors `TYR_OTTER_TIMING_LOG_PATH` / `OTTER_TIMING_LOG_PATH` first
  - otherwise uses `/data/local/tmp/otter_timings.log` when that directory exists
  - falls back to the previous `build/otter_timings.log` behavior elsewhere
- Revalidated the full `x25519` collector path on:
  - Motorola Edge 50 Fusion
  - Infinix X6871
  - Moto G56 5G
- Replaced the temporary recovered `x25519` summary rows in the HTML report with the normal full collector outputs:
  - `build/benchmarks/x25519_phone_full_fixed.json`
  - `build/benchmarks/x25519_infinix_full_fixed.json`
  - `build/benchmarks/x25519_moto_g56_full_fixed.json`

Verification:
- Before fix:
  - ARM64 collector with `-d:otterTiming` completed `x25519` summary work, then crashed during shutdown
  - ARM64 `--mm:refc` collector surfaced the same underlying problem as a writable-path `OSError`
- After fix:
  - full `x25519` collector run with `phase=both`, `scale=1.0` passed on all three phones
  - no post-run `SIGSEGV`
  - no kernel panic
  - `build/benchmarks/asymmetric_bench_report_full.html` regenerated using the fixed full `x25519` phone datasets

Current conclusion:
- The weird `x25519` benchmark crash was an Otter timing log-path/runtime teardown bug on Android shell binaries.
- It was not an `x25519` algorithm bug and not a NEON implementation bug.

## 2026-04-30 Additional Phone Benchmark Coverage
Summary: finished the asymmetric phone matrix beyond the first Motorola so the report now covers three physical phones instead of one.

Implemented:
- Collected non-`x25519` asymmetric benchmark datasets at normal phone scale for:
  - Infinix X6871
  - Moto G56 5G
- Kept the recovered full-scale `x25519` summary runs for:
  - Edge 50 Fusion
  - Infinix X6871
  - Moto G56 5G
- Regenerated `build/benchmarks/asymmetric_bench_report_full.html` with the full cross-device asymmetric set.

Verification:
- Infinix X6871:
  - `kyber`, `bike`, `mceliece`, `dilithium`, `sphincs`, `frodo`, `falcon` (pass)
- Moto G56 5G:
  - `kyber`, `bike`, `mceliece`, `dilithium`, `sphincs`, `frodo`, `falcon` (pass)

Current dataset status:
- Desktop AVX2: full asymmetric summary + function timing dataset
- Edge 50 Fusion: full non-`x25519` asymmetric dataset, low-scale `x25519` full dataset, recovered full-scale `x25519` summary dataset
- Infinix X6871: full non-`x25519` asymmetric dataset, recovered full-scale `x25519` summary dataset
- Moto G56 5G: full non-`x25519` asymmetric dataset, recovered full-scale `x25519` summary dataset

## 2026-04-30 Falcon Portable SIMD Pass
Summary: turned Falcon's placeholder SIMD selector into a real shared 2-lane SIMD path for SSE2-class x86 and ARM64/NEON, then validated it across desktop and all three phones.

Implemented:
- Added a real `f64x2` bridge in `submodules/simd_nexus/src/protocols/simd/generic_f64.nim`:
  - ARM64/NEON now has the missing `float64x2` load/store/arithmetic imports wired locally
  - added a comment there explaining that `nimsimd 1.3.2` exposes `float64x2` but not the common helpers we need for a shared SSE2/NEON path
- Added the matching public shim `submodules/simd_nexus/src/simd_nexus/simd/generic_f64.nim`
- Added Falcon SIMD state and backend scoping in `src/protocols/custom_crypto/asymmetric/pq/falcon/params.nim`:
  - `falconCompileHasSimd`
  - thread-local backend scoping with `withFalconBackend`
  - `falconAuto` now prefers the SIMD backend when the build can support it
  - renamed the benchmark/backend label from the misleading `simd_avx2` to `simd128`
- Added `src/protocols/custom_crypto/asymmetric/pq/falcon/fpr_simd.nim` as the shared SSE2/NEON helper layer for Falcon's `FalconFpr` arrays
- Vectorized the contiguous Falcon polynomial hot paths in `src/protocols/custom_crypto/asymmetric/pq/falcon/fft.nim`:
  - `polyAdd`
  - `polySub`
  - `polyMulFft`
  - `polyMuladjFft`
  - `polyMulselfadjFft`
  - `polyMulconst`
  - `polyDivFft`
  - `polyInvnorm2Fft`
  - `polyAddMuladjFft`
  - `polyMulAutoadjFft`
  - `polyDivAutoadjFft`
  - `polyLDLFft`
  - `polyLDLmvFft`
- Vectorized the Falcon keygen norm accumulation in `src/protocols/custom_crypto/asymmetric/pq/falcon/keygen.nim`
- Updated Falcon runtime entrypoints in `src/protocols/custom_crypto/asymmetric/pq/falcon/operations.nim` so explicit `falconScalar` vs `falconSimd` calls now really select different execution paths inside the same build
- Widened test/benchmark metadata:
  - `tests/test_falcon_tyr.nim` now enables the scalar-vs-SIMD comparisons whenever the shared SIMD path is available, not only under `-d:avx2`
  - added `tests/test_falcon_tyr_simd_smoke.nim` as a fast Falcon-512 scalar-vs-SIMD validator
  - upgraded `tests/test_falcon_tyr_android_smoke.nim` so the fast Android asymmetric bundle also exercises Falcon scalar-vs-SIMD matching
  - `tests/test_sigma_perf_falcon.nim` now labels the active backend through the public Falcon backend metadata
  - `tools/bench_custom_crypto_table.nim` now reports Falcon SIMD rows as `simd128`
  - `tyr_crypto.nimble` `test_neon_checks` now includes `tests/test_falcon_tyr.nim`

Verification:
- Host compile-check:
  - `nim check tests/test_falcon_tyr.nim` (pass)
- ARM64/NEON compile-check:
  - `nim check --cpu:arm64 -d:neon tests/test_falcon_tyr.nim` (pass)
- Host runtime:
  - `tests/test_falcon_tyr_simd_smoke.nim` (pass)
  - scalar roundtrip: pass
  - scalar vs simd deterministic keypair/sign: pass
  - scalar vs simd prepared signing: pass
- Android x86_64 emulator:
  - direct native `tests/test_falcon_tyr_simd_smoke.nim` binary still exits with `SIGSEGV` / `exit=139`
  - no useful crash signal beyond the same emulator instability already observed earlier
- Physical ARM64 phones with the release ARM64 smoke binary:
  - Motorola Edge 50 Fusion: pass
  - Infinix X6871: pass
  - Moto G56 5G: pass
- Repo matrix:
  - `nimble test_neon_checks` (pass)
- Fast Android asymmetric harness entrypoint:
  - `nim check tests/test_android_asymmetric_fast.nim` (pass)
  - `nim check --cpu:arm64 -d:neon tests/test_android_asymmetric_fast.nim` (pass)

Current conclusion:
- Falcon now has a real portable SIMD path for shared 128-bit SSE2/NEON execution instead of only an AVX2-shaped label.
- The emulator remains an unreliable Android native validation target; the physical ARM64 phones are clean.
- This is still not a full Falcon FFT/backend rewrite, but the contiguous polynomial and LDL/keygen hot paths are now genuinely vectorized on both x86 and ARM64.

## 2026-04-30 Remaining Asymmetric SIMD Completion Pass
Summary: completed the remaining practical SSE2/NEON expansion points in the custom asymmetric modules and validated the full phone harness on all three connected ARM64 devices.

Implemented:
- Dilithium:
  - added a shared 2-lane SHAKE sampling path for SSE2-class x86 and ARM64/NEON.
  - wired the 2-lane path into matrix expansion plus eta/gamma sampling for all current `l`/`k` shapes when AVX2 4-lane batching is unavailable.
- BIKE:
  - added a 128-bit qword helper layer for SSE2 and NEON.
  - used it for padded GF(2) word XOR and the bit-sliced decoder add/subtract loops.
- Frodo:
  - widened the optimized AES streaming path from the old fixed Frodo-976 shape to all AES variants by using dynamic row/stripe buffers sized by `p.n`.
  - passed the active stride into SSE2/AVX2/NEON accumulation kernels instead of hard-coding `976`.
  - reduced generated AES words and accumulated outputs to the active Frodo modulus so Frodo-640 AES stays correct on the optimized path.
- Repo coverage:
  - added Frodo and BIKE to `nimble test_neon_checks` and `nimble test_simd_matrix`.
  - fixed stale `.iron/meta/registry.nim` Frodo metadata so the current six Frodo KEM enum values compile in the regular desktop suite.

Verification:
- Compile checks:
  - `nim check --cpu:arm64 -d:neon tests\test_frodo_tyr.nim` (pass)
  - `nim check -d:sse2 tests\test_frodo_tyr.nim` (pass)
  - `nim check tests\test_frodo_tyr.nim` (pass)
  - `nim check --cpu:arm64 -d:neon tests\test_bike_tyr.nim` (pass)
  - `nim check -d:sse2 tests\test_bike_tyr.nim` (pass)
  - `nim check --cpu:arm64 -d:neon tests\test_dilithium_tyr.nim` (pass)
  - `nim check -d:sse2 tests\test_dilithium_tyr.nim` (pass)
- Focused desktop runtime:
  - `nim c -r -d:release tests\test_frodo_tyr.nim` (pass)
  - `nim c -r -d:release tests\test_bike_tyr.nim` (pass)
  - `nim c -r -d:release tests\test_dilithium_tyr.nim` (pass)
- Repo matrix:
  - `nimble test_neon_checks` (pass)
  - `nimble build_android_harness_asymmetric_full` (pass)
  - `nimble test` (pass; debug `test_all` took about 23.5 minutes)
- Physical Android full asymmetric harness:
  - Infinix X6871 / `124312552Q103525`: pass
  - Motorola Edge 50 Fusion / `ZY22K9DZG9`: pass
  - Moto G56 5G / `ZY32M27XLK`: pass

Current conclusion:
- The remaining feasible asymmetric SSE2/NEON paths are now implemented for Dilithium, BIKE, and Frodo without regressing the prior X25519/Kyber/McEliece/SPHINCS/Falcon work.
- The x86_64 emulator remains excluded from validation because previous direct native harness runs still hit emulator-only instability; the three physical ARM64 phones are clean.

## 2026-04-30 Frodo/McEliece Benchmark Follow-up
Summary: answered the McEliece/Frodo follow-up by re-checking McEliece SIMD coverage, applying one more Frodo AES-stream memory-traffic reduction, and refreshing focused desktop plus three-phone benchmarks.

Implemented:
- McEliece:
  - confirmed the current SIMD work is the masked public-key-generation row-XOR helper in `mceliece/pk_gen.nim`, with AVX2, SSE2, and NEON branches.
  - left the deeper GF/controlbits/Benes/syndrome code scalar for now because the current Otter spans only show whole-operation McEliece timing, not a reliable internal hotspot split.
- Frodo:
  - added direct transposed/reduced AES column-stripe decode for the `mulAddSaPlusEStream` path.
  - removed the extra temporary column buffer plus separate reduce/transpose pass from that AES column-stripe loop.
  - removed the now-dead dynamic non-transposed column-stripe helpers after wiring the direct-transposed path.
  - kept SHAKE variants functionally on the same path; their remaining hotspot is mostly SHAKE matrix generation/generic matrix multiply rather than the AES streaming transpose.

Verification:
- Focused Frodo checks after the direct-transpose/helper-cleanup change:
  - `nim check --cpu:arm64 -d:neon tests\test_frodo_tyr.nim` (pass)
  - `nim check -d:sse2 tests\test_frodo_tyr.nim` (pass)
  - `nim check -d:sse2 -d:avx2 -d:aesni tests\test_frodo_tyr.nim` (pass)
  - `nim c -r -d:release tests\test_frodo_tyr.nim` (pass)
- Regular desktop suite:
  - `nimble test` (pass; debug `test_all` took about 23.5 minutes)
- Focused benchmark collectors:
  - `build/benchmarks/frodo_mceliece_desktop_direct_t.json`
  - `build/benchmarks/frodo_mceliece_infinix_direct_t.json`
  - `build/benchmarks/frodo_mceliece_edge50_direct_t.json`
  - `build/benchmarks/frodo_mceliece_motog56_direct_t.json`

Benchmark notes:
- Desktop AVX2 Frodo AES improved by about 11-16% versus the immediately preceding dynamic-buffer run:
  - Frodo640AES: 1.416 ms -> 1.226 ms
  - Frodo976AES: 2.807 ms -> 2.367 ms
  - Frodo1344AES: 4.752 ms -> 4.247 ms
- Phone Frodo AES improved by about 2% across the three devices:
  - Infinix X6871 Frodo1344AES: 88.186 ms -> 86.091 ms
  - Edge 50 Fusion Frodo1344AES: 114.465 ms -> 111.827 ms
  - Moto G56 Frodo1344AES: 125.666 ms -> 122.950 ms
- Frodo SHAKE movement was mostly noise-level because the dominant costs remain `generateMatrixA` and non-streaming SHAKE-side multiplication.
- McEliece final focused timings stayed in the expected range with the existing row-XOR SIMD:
  - Desktop AVX2: about 206-251 ms across the three enabled `f` variants.
  - Infinix X6871: about 495-580 ms.
  - Edge 50 Fusion: about 644-757 ms.
  - Moto G56: about 733-899 ms.

Current conclusion:
- McEliece already had the practical row-XOR SIMD hook from the earlier pass; further work should start with better internal timing spans before touching controlbits/Benes/GF code.
- Frodo AES has one fewer memory pass in the slow `mulAddSaPlusEStream` path and was rebenchmarked on desktop plus all three connected phones.
- The next meaningful Frodo target is a streaming/SIMD SHAKE-matrix path, not more cleanup around the AES stripe transpose.

## 2026-04-30 Deeper Frodo/McEliece Optimization Follow-up
Summary: went deeper on the two slowest KEMs, kept the measured McEliece wins, rejected slower Frodo/McEliece experiments, and reran desktop plus all three phone validations.

Implemented:
- McEliece:
  - added Otter spans inside `decodeErrorVector` and `pkGen` so keygen elimination, decapsulation syndrome, support generation, root evaluation, and packing are now visible separately.
  - added a `bitLimit` parameter to `synd` and used `p.syndBytes * 8` for the public ciphertext syndrome pass, avoiding a full `sysN` scan over zero-padded tail bytes while keeping the secret-dependent error-vector check on the full constant-time path.
  - kept the measured 4-vector SIMD masked row-XOR unroll for AVX2/SSE2/NEON in public-key generation.
- Frodo:
  - tested SHAKE streaming/block/batched matrix-generation paths and removed them after measurement because they were slower than the current direct baseline.
  - left the AES direct-streaming cleanup in place; current SHAKE bottleneck remains matrix generation plus generic multiply, not an obvious low-risk transpose/memory pass.
- Desktop tests:
  - split `tools/run_desktop_tests_parallel.ps1` further so symmetric algorithms run as separate jobs instead of one bundled symmetric group.
- Android harness:
  - redirected Zig and Gradle cache/temp paths into repo-local `build/` paths so the Android harness rebuild is independent of profile-specific cache permissions.

Rejected experiments:
- Frodo SHAKE row streaming/block/batching regressed desktop SHAKE:
  - `frodo640shake`: 10.568 ms direct baseline vs 15.694 ms batched experiment.
  - `frodo976shake`: 23.686 ms direct baseline vs 28.709 ms batched experiment.
  - `frodo1344shake`: 44.576 ms direct baseline vs 46.691 ms batched experiment.
- McEliece pivot-byte-start row XOR regressed keygen elimination and was reverted.
- McEliece AVX2 8-vector row-XOR unroll regressed keygen elimination by roughly 10-14 ms and was reverted.

Benchmark notes:
- Frodo final focused desktop cleanup:
  - `frodo640aes`: 1.226 ms baseline, 1.239 ms cleanup.
  - `frodo640shake`: 10.568 ms baseline, 10.423 ms cleanup.
  - `frodo976aes`: 2.367 ms baseline, 2.364 ms cleanup.
  - `frodo976shake`: 23.686 ms baseline, 23.639 ms cleanup.
  - `frodo1344aes`: 4.247 ms baseline, 4.074 ms cleanup.
  - `frodo1344shake`: 44.576 ms baseline, 43.491 ms cleanup.
- McEliece final focused desktop timings versus earlier direct baseline:
  - `mceliece6688128f`: 221.138 ms -> 194.443 ms.
  - `mceliece6960119f`: 206.511 ms -> 186.190 ms.
  - `mceliece8192128f`: 250.872 ms -> 214.161 ms.
- McEliece decoded hotspot after the syndrome limit:
  - first syndrome pass dropped from about 21-27 ms to about 5-6 ms across the three variants.
  - final secret-dependent syndrome check remains about 21-28 ms and still scans the full error vector.

Verification:
- Focused desktop checks:
  - `nim c -r -d:release tests\test_frodo_tyr.nim` (pass)
  - `nim c -r -d:release tests\test_mceliece_tyr.nim` (pass)
  - `nim check -d:sse2 -d:avx2 tests\test_mceliece_tyr.nim` (pass)
  - `nim check --cpu:arm64 -d:neon tests\test_mceliece_tyr.nim` (pass)
- Focused benchmark outputs:
  - `build/benchmarks/frodo_desktop_cleanup.json`
  - `build/benchmarks/mceliece_desktop_final.json`
- Regular desktop suite:
  - all 19 parallel desktop test groups passed; longest group was Falcon at 1359s.
  - the enclosing `nimble test` command returned exit 1 only after tests completed because Nimble could not save `C:\Users\n1ght\.nimble\nimbledata2.json` in the earlier restricted sandbox.
- Android:
  - `powershell -File tools/build_android_harness.ps1 -HarnessTarget asymmetric_full -Release` (pass)
  - Infinix X6871 / `124312552Q103525`: asymmetric-full harness pass, `exit=0`.
  - Motorola Edge 50 Fusion / `ZY22K9DZG9`: asymmetric-full harness pass, `exit=0`.
  - Moto G56 5G / `ZY32M27XLK`: asymmetric-full harness pass, `exit=0`.

Current conclusion:
- McEliece now has both the practical SIMD row-XOR optimization and a measured decapsulation reduction that avoids unnecessary public zero-tail syndrome work.
- Frodo SHAKE is still the slowest area, but the attempted streaming/batching variants were not worth keeping; a better SHAKE improvement likely needs a more substantial XOF/matrix multiply design rather than local buffering changes.

Docs update:
- Copied the kept Frodo/McEliece benchmark JSONs into `docs/benchmarks`:
  - `frodo_desktop_cleanup.json`
  - `mceliece_desktop_final.json`
  - `frodo_mceliece_desktop_direct_t.json`
  - `frodo_mceliece_infinix_direct_t.json`
  - `frodo_mceliece_edge50_direct_t.json`
  - `frodo_mceliece_motog56_direct_t.json`
- Regenerated:
  - `docs/benchmarks/asymmetric_bench_report_full.html`
  - `docs/benchmarks/asymmetric_bench_report_desktop_only.html`

## 2026-05-01 Falcon Split + Frodo Hybrid Probe Pass
Summary: checked the literature direction for further PQ SIMD work, split Falcon desktop tests/benchmarks by variant, tried deeper Frodo hybrid SSE/AVX ideas, rejected the measured regressions, and refreshed desktop plus three-phone validation.

Implemented:
- Falcon:
  - split `tools/run_desktop_tests_parallel.ps1` into `falcon512` and `falcon1024` groups, both still selectable through `-Only falcon`.
  - added `TYR_FALCON_TEST_VARIANT` filtering in `tests/test_falcon_tyr.nim` so each process runs only its assigned variant.
  - reduced Falcon benchmark loop/warmup counts in `tests/test_sigma_perf_falcon.nim` and `tools/bench_custom_crypto_table.nim`.
  - split `tools/bench_pq_profiles.nim` Falcon suites into `falcon512` and `falcon1024`.
  - added `--only=falcon512` / `--only=falcon1024` support to `tools/collect_asymmetric_benchmarks.nim`.
- Frodo:
  - factored AES stream accumulation dispatch through host wrappers so the AVX2/SSE2/NEON choice is centralized.
  - added an opt-in `-d:frodoAvx2SaStripeSse` probe path for the AVX2 build to force the smaller SSE128 `s*A` stripe kernel.
  - tried vectorizing the small `mulBs` dot products and an 8-lane `mulAddSbPlusE` row kernel, then reverted both from the default path after measurement.

Literature/source scan notes:
- Falcon literature and implementations point toward batched/vectorized Gaussian sampling and careful AVX/SSE transition handling; this repo's current portable Falcon SIMD path is intentionally 2-lane f64 SSE2/NEON, not a full AVX2 Falcon rewrite.
- Frodo's remaining slow area is still matrix generation plus matrix multiply, especially SHAKE matrix generation. The local SSE128-for-small-loop idea was worth measuring, but this pass did not find a default-safe win.

Rejected experiments:
- Frodo AVX2 build using the SSE128 `s*A` stripe path regressed all desktop Frodo variants in the probe:
  - `frodo640aes`: 1.395 ms -> 1.850 ms.
  - `frodo976aes`: 2.358 ms -> 3.231 ms.
  - `frodo1344aes`: 3.904 ms -> 5.751 ms.
- Frodo `mulAddSbPlusE` 8-lane SSE/NEON-shaped row kernel regressed desktop AVX2 summary timings by roughly 2-12% and was removed from the default path.
- Frodo `mulBs` SIMD dot-product refactor was mixed/noisy and was reverted to the stable scalar unroll.

Benchmark notes:
- Current Frodo desktop summary rerun after reverting the unstable dot experiments:
  - `frodo640aes`: 1.244 ms.
  - `frodo976aes`: 2.602 ms.
  - `frodo1344aes`: 4.151 ms.
  - `frodo640shake`: 11.297 ms.
  - `frodo976shake`: 26.661 ms.
  - `frodo1344shake`: 45.266 ms.
- Focused Frodo phone summary benchmarks:
  - Infinix X6871: `frodo1344aes` 86.685 ms, `frodo1344shake` 93.241 ms.
  - Edge 50 Fusion: `frodo1344aes` 113.409 ms, `frodo1344shake` 125.000 ms.
  - Moto G56 5G: `frodo1344aes` 123.576 ms, `frodo1344shake` 133.107 ms.
- Split Falcon desktop collector:
  - Falcon-512 sign/verify rows: about 12.06-12.31 s per operation depending on scalar/prepared mode.
  - Falcon-1024 sign/verify rows: about 84.40-86.19 s per operation depending on scalar/prepared mode.

Verification:
- Focused compile/runtime checks:
  - `nim check -d:sse2 -d:avx2 -d:aesni tests\test_frodo_tyr.nim` (pass)
  - `nim check --cpu:arm64 -d:neon tests\test_frodo_tyr.nim` (pass)
  - `nim c -d:release -r tests\test_frodo_tyr.nim` (pass)
  - `nim check tests\test_falcon_tyr.nim` (pass)
  - `nim check tests\test_sigma_perf_falcon.nim` (pass)
  - `nim check tools\bench_pq_profiles.nim` (pass)
  - `nim check tools\collect_asymmetric_benchmarks.nim` (pass)
- Regular desktop parallel suite:
  - `powershell -File tools/run_desktop_tests_parallel.ps1 -Only core,custom_crypto,sha3,poly1305,aes,gimli,blake3,xchacha20,random,hmac,otp,x25519,kyber,frodo,bike,dilithium,falcon,sphincs,mceliece -MaxParallel 6 -ChildNimFlags=-d:release`
  - all 20 selected non-NTRU/SABER groups passed; longest group was `falcon1024` at 921s.
- Android:
  - `powershell -File tools/build_android_harness.ps1 -HarnessTarget asymmetric_full -Release` (pass)
  - Infinix X6871 / `124312552Q103525`: asymmetric-full harness pass, `exit=0`.
  - Motorola Edge 50 Fusion / `ZY22K9DZG9`: asymmetric-full harness pass, `exit=0`.
  - Moto G56 5G / `ZY32M27XLK`: asymmetric-full harness pass, `exit=0`.

Docs update:
- Copied new benchmark JSONs into `docs/benchmarks`:
  - `frodo_desktop_deep_final.json`
  - `frodo_infinix_deep_final.json`
  - `frodo_edge50_deep_final.json`
  - `frodo_motog56_deep_final.json`
  - `frodo_desktop_hybrid_sse128_rejected.json`
  - `falcon512_desktop_split.json`
  - `falcon1024_desktop_split.json`
- Regenerated:
  - `docs/benchmarks/asymmetric_bench_report_full.html`
  - `docs/benchmarks/asymmetric_bench_report_desktop_only.html`

Current conclusion:
- The deeper Frodo SSE/AVX hybrid idea was measured and rejected for this machine; the default Frodo compute path remains the previous stable AVX2/NEON dispatch.
- Falcon is still expensive, but the test and benchmark tooling can now run 512 and 1024 independently, which prevents the old combined Falcon process from dominating every run.
- NTRU/SABER files were intentionally left untouched while the parallel implementation work continues.

