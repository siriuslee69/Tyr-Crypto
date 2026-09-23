import std/[os, strutils]

# Package descriptor for the crypto bindings sub-project.

version       = "0.1.0"
author        = "siriuslee69"
description   = "Bindings for classical and post-quantum cryptographic primitives."
license       = "Unlicense"
srcDir        = "src"
bin           = @[]
requires "nim >= 1.6.0", "nimcrypto >= 0.6.0", "nimsimd >= 1.3.2", "webui >= 2.5.0"

## Tyr keeps its own `test` (the parallel desktop runner); every other
## generic task comes from Nimble-Tasks, included at the end of this file.
const
  ownTasks: array[1, string] = ["test"]
  ## third-party code: moved by hand after testing, never by updateSubmodules
  frozenSubmodules: array[6, string] = ["submodules/libsodium",
    "submodules/liboqs", "submodules/openssl", "submodules/pqclean",
    "submodules/pqclean_falcon_ref_sources",
    "submodules/ntru_sampling_ref_sources"]

proc repoNimbleDir(): string =
  result = joinPath(getCurrentDir(), ".nimble_cache")

proc repoNimcacheDir(name: string): string =
  result = joinPath(getCurrentDir(), "build", name)

proc hostExeName(name: string): string =
  when defined(windows):
    result = name & ".exe"
  else:
    result = name

proc repoToolExe(name: string): string =
  result = joinPath(getCurrentDir(), "build", hostExeName(name)).replace('\\', '/')

proc buildToolExe(name: string): string =
  result = repoToolExe(name)
  exec "nim c --nimcache:" & repoNimcacheDir("nimcache_tool_" & name).replace('\\', '/') &
    " --out:" & result & " tools/" & name & ".nim"

proc withRepoCaches(cmd: string): string =
  putEnv("NIMBLE_DIR", repoNimbleDir().replace('\\', '/'))
  result = cmd

proc shellPath(p: string): string =
  result = quoteShell(p.replace('\\', '/'))

proc shellCommand(command: string; args: openArray[string]): string =
  var parts: seq[string] = @[shellPath(command)]
  for arg in args:
    parts.add(shellPath(arg))
  result = parts.join(" ")

proc runCommand(command: string; args: openArray[string]) =
  exec shellCommand(command, args)

proc probeCommand(command: string; args: openArray[string]): tuple[output: string, exitCode: int] =
  result = gorgeEx(shellCommand(command, args))

proc captureCommand(command: string; args: openArray[string]): string =
  let probe = probeCommand(command, args)
  result = probe.output
  if probe.exitCode != 0:
    if result.len > 0:
      echo result
    quit(probe.exitCode)

proc requireRepoPath(candidates: openArray[string], label: string): string =
  var
    i = 0
    l = candidates.len
  while i < l:
    if dirExists(candidates[i]):
      return candidates[i].replace('\\', '/')
    inc i
  raise newException(OSError, "Missing required path for " & label)

proc otterSrcDir(): string =
  result = requireRepoPath(
    @[
      joinPath(getCurrentDir(), "..", "Otter-RepoEvaluation", "src"),
      joinPath(getCurrentDir(), "submodules", "otter_repo_evaluation", "src")
    ],
    "Otter-RepoEvaluation"
  )

proc otterRootDir(): string =
  result = parentDir(otterSrcDir())

proc otterTestUiPath(): string =
  result = joinPath(getCurrentDir(), "build", hostExeName("otter-test-ui"))

proc buildOtterTestUi() =
  if not dirExists(joinPath(getCurrentDir(), "build")):
    mkDir(joinPath(getCurrentDir(), "build"))
  runCommand("nim", @["c", "--path:" & otterSrcDir(),
    "--out:" & otterTestUiPath(),
    joinPath(otterRootDir(), "src", "clients", "test_ui", "app.nim")])

task check, "Run nim check on core modules":
  exec withRepoCaches("nim check tools/meta/registry.nim")
  exec withRepoCaches("nim check --nimcache:" & repoNimcacheDir("nimcache_check_public").replace('\\', '/') & " src/tyr.nim")

task check_core, "Run nim check on core modules without Nimble's built-in package check":
  exec withRepoCaches("nim check tools/meta/registry.nim")
  exec withRepoCaches("nim check --nimcache:" & repoNimcacheDir("nimcache_check_public").replace('\\', '/') & " src/tyr.nim")

task check_asymmetric_references, "Check asymmetric function citations and locked references":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_check_asymmetric_references").replace('\\', '/') & " evaluation/statistics/check_asymmetric_references.nim")

task test_asymmetric_audit, "Run focused asymmetric conformance and malformed-input tests":
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_x25519").replace('\\', '/') & " evaluation/tests/test_x25519_custom.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_ed25519").replace('\\', '/') & " evaluation/tests/test_ed25519_custom.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_dilithium").replace('\\', '/') & " evaluation/tests/test_dilithium_tyr.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_kyber").replace('\\', '/') & " evaluation/tests/test_kyber_tyr.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_sphincs").replace('\\', '/') & " evaluation/tests/test_sphincs_tyr.nim")

task test, "Run the crypto bindings test suite":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " evaluation/tests/run_desktop_tests_parallel.nim")

task test_all, "Run the full crypto bindings test suite with libsodium, liboqs, and OpenSSL":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " evaluation/tests/run_desktop_tests_parallel.nim -- --full")

task test_all_threads_on, "Run test_all with threads enabled":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " evaluation/tests/run_desktop_tests_parallel.nim -- --full --childNimFlags:\"--gc:orc --threads:on\"")

task test_all_threads_off, "Run test_all with threads disabled":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " evaluation/tests/run_desktop_tests_parallel.nim -- --full --childNimFlags:\"--gc:orc --threads:off\"")

task test_gimli, "Run Gimli SSE tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli").replace('\\', '/') & " -r evaluation/tests/test_gimli_sse.nim")

task test_gimli_avx, "Run Gimli AVX tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli_avx").replace('\\', '/') & " --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r evaluation/tests/test_gimli_sse.nim")

task test_nugimli, "Run NuGimli reversible block permutation tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_nugimli").replace('\\', '/') & " -r evaluation/tests/test_nugimli.nim")

task evaluate_nugimli, "Run NuGimli security diagnostics and stable benchmarks":
  exec withRepoCaches("nim c -r -d:release --path:" & otterSrcDir() &
    " --out:" & repoToolExe("evaluate_nugimli") &
    " --nimcache:" & repoNimcacheDir("nimcache_evaluate_nugimli").replace('\\', '/') &
    " evaluation/benchmarks/evaluate_nugimli.nim")

task evaluate_nugimli_streams, "Run full threaded NuGimli stream campaign":
  exec withRepoCaches("nim c -r --threads:on -d:release --path:" & otterSrcDir() &
    " --out:" & repoToolExe("evaluate_nugimli_streams") &
    " --nimcache:" & repoNimcacheDir("nimcache_evaluate_nugimli_streams").replace('\\', '/') &
    " evaluation/benchmarks/evaluate_nugimli_streams.nim -- --quiet")

task evaluate_nugimli_streams_quick, "Run quick threaded NuGimli stream campaign":
  exec withRepoCaches("nim c -r --threads:on -d:release --path:" & otterSrcDir() &
    " --out:" & repoToolExe("evaluate_nugimli_streams") &
    " --nimcache:" & repoNimcacheDir("nimcache_evaluate_nugimli_streams_quick").replace('\\', '/') &
    " evaluation/benchmarks/evaluate_nugimli_streams.nim -- --quick --quiet")

task test_nugimli_streams, "Run threaded NuGimli stream campaign tests":
  exec withRepoCaches("nim c -r --threads:on --path:" & otterSrcDir() &
    " --out:" & repoToolExe("test_nugimli_stream_campaign") &
    " --nimcache:" & repoNimcacheDir("nimcache_test_nugimli_stream_campaign").replace('\\', '/') &
    " evaluation/tests/test_nugimli_stream_campaign.nim")

task test_nugimli_domain, "Run tagged NuGimli domain derivation tests":
  exec withRepoCaches("nim c -r --out:" & repoToolExe("test_nugimli_domain") &
    " --nimcache:" & repoNimcacheDir("nimcache_test_nugimli_domain").replace('\\', '/') &
    " evaluation/tests/test_nugimli_domain.nim")

task evaluate_nugimli_advanced, "Run Cascade algebraic and structural searches":
  exec withRepoCaches("nim c -r --threads:on -d:release --path:" & otterSrcDir() &
    " --out:" & repoToolExe("evaluate_nugimli_advanced") &
    " --nimcache:" & repoNimcacheDir("nimcache_evaluate_nugimli_advanced").replace('\\', '/') &
    " evaluation/benchmarks/evaluate_nugimli_advanced.nim")

task evaluate_nugimli_leakage, "Run Cascade fixed-random timing leakage tests":
  exec withRepoCaches("nim c -r -d:release --path:" & otterSrcDir() &
    " --out:" & repoToolExe("evaluate_nugimli_leakage") &
    " --nimcache:" & repoNimcacheDir("nimcache_evaluate_nugimli_leakage").replace('\\', '/') &
    " evaluation/benchmarks/evaluate_nugimli_leakage.nim")

task test_blake3_simd, "Run Blake3 SIMD tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_blake3_simd").replace('\\', '/') & " --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r evaluation/tests/test_blake3_simd.nim")

task test_ntru_saber, "Run NTRU and SABER KAT/roundtrip tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_ntru_tyr").replace('\\', '/') & " -r evaluation/tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_saber_tyr").replace('\\', '/') & " -r evaluation/tests/test_saber_tyr.nim")

task test_ntru_saber_avx2, "Run NTRU/SABER tests with AVX2 enabled where supported":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_ntru_tyr_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2 -mbmi2\" --passL:\"-mavx2\" -r evaluation/tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_saber_tyr_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2\" --passL:\"-mavx2\" -r evaluation/tests/test_saber_tyr.nim")

task test_frodo_native_fast, "Run Frodo with AVX2 matrix math and native AES-NI":
  exec withRepoCaches("nim c -d:release -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-mavx2\" --nimcache:" & repoNimcacheDir("nimcache_test_frodo_native_fast").replace('\\', '/') & " -r evaluation/tests/test_frodo_tyr.nim")

task test_hqc, "Run HQC roundtrip and single known-answer tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_hqc_tyr").replace('\\', '/') & " -r evaluation/tests/test_hqc_tyr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_hqc_kat").replace('\\', '/') & " -r evaluation/tests/test_hqc_kat.nim")

task test_hqc_kat_full, "Run all 100 published HQC known-answer records per parameter set":
  exec withRepoCaches("nim c -d:release -d:tyrHqcFullKat --nimcache:" & repoNimcacheDir("nimcache_test_hqc_kat_full").replace('\\', '/') & " -r evaluation/tests/test_hqc_kat.nim")

task test_neon_checks, "Compile-check the ARM64/NEON SIMD coverage matrix":
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_xchacha20").replace('\\', '/') & " evaluation/tests/test_xchacha20_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_blake3").replace('\\', '/') & " evaluation/tests/test_blake3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sha3").replace('\\', '/') & " evaluation/tests/test_sha3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_poly1305").replace('\\', '/') & " evaluation/tests/test_poly1305_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_gimli").replace('\\', '/') & " evaluation/tests/test_gimli_sse.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_aes").replace('\\', '/') & " evaluation/tests/test_aes_ctr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_custom").replace('\\', '/') & " evaluation/tests/test_custom_crypto.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_x25519").replace('\\', '/') & " evaluation/tests/test_x25519_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_kyber").replace('\\', '/') & " evaluation/tests/test_kyber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_frodo").replace('\\', '/') & " evaluation/tests/test_frodo_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_bike").replace('\\', '/') & " evaluation/tests/test_bike_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_ntru").replace('\\', '/') & " evaluation/tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_saber").replace('\\', '/') & " evaluation/tests/test_saber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_dilithium").replace('\\', '/') & " evaluation/tests/test_dilithium_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sphincs").replace('\\', '/') & " evaluation/tests/test_sphincs_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_mceliece").replace('\\', '/') & " evaluation/tests/test_mceliece_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_falcon").replace('\\', '/') & " evaluation/tests/test_falcon_tyr.nim")

task test_simd_matrix, "Run the host SIMD/runtime suite and the ARM64/NEON compile-check matrix":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_custom_crypto_matrix").replace('\\', '/') & " -r evaluation/tests/test_custom_crypto.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_aes_ctr_matrix").replace('\\', '/') & " -r evaluation/tests/test_aes_ctr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_xchacha20_matrix").replace('\\', '/') & " -r evaluation/tests/test_xchacha20_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_blake3_matrix").replace('\\', '/') & " -r evaluation/tests/test_blake3_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_sha3_matrix").replace('\\', '/') & " -r evaluation/tests/test_sha3_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_poly1305_matrix").replace('\\', '/') & " -r evaluation/tests/test_poly1305_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli_matrix").replace('\\', '/') & " -r evaluation/tests/test_gimli_sse.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_x25519_matrix").replace('\\', '/') & " -r evaluation/tests/test_x25519_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_ntru_matrix_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2 -mbmi2\" --passL:\"-mavx2\" -r evaluation/tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_saber_matrix_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2\" --passL:\"-mavx2\" -r evaluation/tests/test_saber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_xchacha20").replace('\\', '/') & " evaluation/tests/test_xchacha20_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_blake3").replace('\\', '/') & " evaluation/tests/test_blake3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sha3").replace('\\', '/') & " evaluation/tests/test_sha3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_poly1305").replace('\\', '/') & " evaluation/tests/test_poly1305_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_gimli").replace('\\', '/') & " evaluation/tests/test_gimli_sse.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_aes").replace('\\', '/') & " evaluation/tests/test_aes_ctr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_custom").replace('\\', '/') & " evaluation/tests/test_custom_crypto.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_x25519").replace('\\', '/') & " evaluation/tests/test_x25519_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_kyber").replace('\\', '/') & " evaluation/tests/test_kyber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_frodo").replace('\\', '/') & " evaluation/tests/test_frodo_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_bike").replace('\\', '/') & " evaluation/tests/test_bike_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_ntru").replace('\\', '/') & " evaluation/tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_saber").replace('\\', '/') & " evaluation/tests/test_saber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_dilithium").replace('\\', '/') & " evaluation/tests/test_dilithium_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sphincs").replace('\\', '/') & " evaluation/tests/test_sphincs_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_mceliece").replace('\\', '/') & " evaluation/tests/test_mceliece_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_falcon").replace('\\', '/') & " evaluation/tests/test_falcon_tyr.nim")

task test_wasm, "Run wasm bridge regression tests":
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_wasm_test").replace('\\', '/') & " evaluation/tests/test_wasm_bridge.nim")

task build_android_harness, "Cross-compile the Android native test binaries and build the harness APK":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_build_android_harness").replace('\\', '/') & " tools/build_android_harness.nim")

task build_android_harness_asymmetric_fast, "Build the Android harness APK with the reduced asymmetric/PQ native test bundle":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_build_android_harness").replace('\\', '/') & " tools/build_android_harness.nim -- --harnessTarget:asymmetric_fast --release")

task build_android_harness_asymmetric_full, "Build the Android harness APK with the full asymmetric/PQ native test bundle":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_build_android_harness").replace('\\', '/') & " tools/build_android_harness.nim -- --harnessTarget:asymmetric_full --release")

task test_pin, "Run interactive pin + key unwrap test.":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_pin").replace('\\', '/') & " -d:hasLibsodium -r evaluation/tests/test_pin_key_interactive.nim")

task perf_sigma, "Benchmark custom crypto with Otter helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma.nim")

task perf_sigma_pq, "Benchmark Tyr PQ backends against liboqs with Otter helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_pq").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma_pq.nim")

task perf_sigma_dilithium, "Benchmark split Tyr Dilithium phases against the current liboqs profile":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_dilithium").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma_dilithium.nim")

task perf_sigma_falcon, "Benchmark split Tyr Falcon phases against the current liboqs profile":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_falcon").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma_falcon.nim")

task perf_sigma_dilithium_scalar, "Benchmark scalar Tyr Dilithium against the scalar liboqs Dilithium profile":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_dilithium_scalar_zig_mingw"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_dilithium_scalar").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:tyrExplicitCapabilities -u:sse2 -u:avx2 -u:aesni -u:neon -r evaluation/benchmarks/bench_sigma_dilithium.nim")

task perf_sigma_kyber, "Benchmark Tyr Kyber against liboqs with Otter helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_kyber").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma_kyber_only.nim")

task perf_sigma_pq_aesni, "Benchmark Tyr PQ backends against liboqs with Otter helpers and AES-NI enabled":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_pq_aesni").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma_pq.nim")

task perf_sigma_frodo_portable, "Benchmark Tyr Frodo against the portable Frodo-focused liboqs build":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_portable"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_frodo_portable").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma_frodo_profile.nim")

task perf_sigma_frodo_ossl, "Benchmark Tyr Frodo against the OpenSSL-backed Frodo-focused liboqs build":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_ossl"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_frodo_ossl").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_sigma_frodo_profile.nim")

task bench_pq_profiles, "Build matched scalar/AVX2 liboqs profiles and run Otter PQ comparison benches":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_bench_pq_profiles").replace('\\', '/') & " evaluation/benchmarks/bench_pq_profiles.nim")

task bench_custom_crypto, "Run the unified Tyr-only custom-crypto benchmark report":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_bench_custom_crypto").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_custom_crypto_table.nim")

task bench_custom_crypto_stress, "Run the threaded Tyr-owned AVX2 custom-crypto stress benchmark":
  exec withRepoCaches("nim c --threads:on -d:release -d:sse2 -d:avx2 -d:aesni -d:danger --passC:\"-mavx2 -maes\" --passL:\"-mavx2 -maes\" --nimcache:" & repoNimcacheDir("nimcache_bench_custom_crypto_stress").replace('\\', '/') & " -r evaluation/benchmarks/bench_custom_crypto_stress.nim")

task build_tyr_avx_stress, "Build the threaded Tyr AVX2 custom-crypto stress executable":
  exec withRepoCaches("nim c --threads:on -d:release -d:sse2 -d:avx2 -d:aesni -d:danger --passC:\"-mavx2 -maes\" --passL:\"-mavx2 -maes\" --nimcache:" & repoNimcacheDir("nimcache_build_tyr_avx_stress").replace('\\', '/') & " --out:" & repoToolExe("tyr-avx-stress") & " evaluation/benchmarks/bench_custom_crypto_stress.nim")

task run_tyr_avx_stress, "Build and run the threaded Tyr AVX2 custom-crypto stress executable":
  exec "nimble build_tyr_avx_stress"
  exec repoToolExe("tyr-avx-stress")

task bench_curve25519_ed25519, "Benchmark pure Nim X25519 and Ed25519 implementations":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_bench_x25519").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_x25519.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_bench_ed25519").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_ed25519.nim")

task bench_custom_kdf, "Run the custom KDF generator benchmark table":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_bench_custom_kdf").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_custom_kdf.nim")

task perf_otter_pq, "Profile Tyr PQ functions with Otter timing instrumentation":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_otter_pq").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:otterTiming -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_otter_pq.nim")

task perf_otter_kyber, "Profile Tyr Kyber functions with Otter timing instrumentation":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_otter_kyber").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:otterTiming -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r evaluation/benchmarks/bench_otter_kyber_only.nim")


task build_libsodium, "Build libsodium and prepare combined headers":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_libsodium.nim"
  exec "nim r tools/prepare_libsodium_header.nim"

task build_liboqs, "Build liboqs and prepare combined headers":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_liboqs_frodo_portable, "Build a portable Frodo-focused liboqs profile with OpenSSL disabled":
  putEnv("LIBOQS_PROFILE_NAME", "frodo_portable")
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_portable"))
  putEnv("LIBOQS_USE_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_AES_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA2_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA3_OPENSSL", "OFF")
  putEnv("LIBOQS_DIST_BUILD", "OFF")
  putEnv("LIBOQS_OPT_TARGET", "generic")
  putEnv("LIBOQS_MINIMAL_BUILD", "KEM_frodokem_976_aes")
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_liboqs_frodo_ossl, "Build an OpenSSL-backed Frodo-focused liboqs profile":
  putEnv("LIBOQS_PROFILE_NAME", "frodo_ossl")
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_ossl"))
  putEnv("LIBOQS_USE_OPENSSL", "ON")
  putEnv("LIBOQS_USE_AES_OPENSSL", "ON")
  putEnv("LIBOQS_USE_SHA2_OPENSSL", "ON")
  putEnv("LIBOQS_USE_SHA3_OPENSSL", "OFF")
  putEnv("LIBOQS_DIST_BUILD", "ON")
  putEnv("LIBOQS_OPT_TARGET", "auto")
  putEnv("LIBOQS_MINIMAL_BUILD", "KEM_frodokem_976_aes")
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_liboqs_dilithium_scalar_zig, "Build a scalar Zig-backed liboqs profile focused on ML-DSA":
  let zigccWrapper = buildToolExe("zigcc_wrapper")
  putEnv("LIBOQS_PROFILE_NAME", "dilithium_scalar_zig")
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_dilithium_scalar_zig_mingw"))
  putEnv("LIBOQS_OVERWRITE_BUILD", "1")
  putEnv("LIBOQS_USE_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_AES_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA2_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA3_OPENSSL", "OFF")
  putEnv("LIBOQS_DIST_BUILD", "OFF")
  putEnv("LIBOQS_OPT_TARGET", "generic")
  putEnv("LIBOQS_MINIMAL_BUILD", "SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87")
  putEnv("LIBOQS_CMAKE_GENERATOR", "MinGW Makefiles")
  putEnv("LIBOQS_CMAKE_C_COMPILER", zigccWrapper)
  putEnv("LIBOQS_CMAKE_C_COMPILER_ARG1", "")
  putEnv("LIBOQS_CMAKE_ASM_COMPILER", zigccWrapper)
  putEnv("LIBOQS_CMAKE_ASM_COMPILER_ARG1", "")
  putEnv("LIBOQS_EXTRA_CMAKE_ARGS", "-DOQS_ENABLE_SIG_ml_dsa_44_avx2=OFF -DOQS_ENABLE_SIG_ml_dsa_65_avx2=OFF -DOQS_ENABLE_SIG_ml_dsa_87_avx2=OFF -DOQS_ENABLE_SHA3_xkcp_low_avx2=OFF -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY -DCMAKE_SH=CMAKE_SH-NOTFOUND")
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_openssl, "Build OpenSSL":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_openssl.nim"

task build_wasm, "Build JS/TS wasm bindings with Emscripten":
  exec "nim r --nimcache:build/nimcache_build_wasm tools/build_wasm.nim"

task build_wasm_debug, "Build debug JS/TS wasm bindings with Emscripten":
  exec "nim r --nimcache:build/nimcache_build_wasm tools/build_wasm.nim -- --debug"

task build_wasm_custom_crypto, "Build the custom_crypto WASM bridge and WebUI dashboard assets":
  exec "nimble build_wasm"
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_stage_wasm_webui").replace('\\', '/') & " tools/stage_wasm_webui.nim")

task buildTestUi, "Build the pragma-driven Otter test UI":
  buildOtterTestUi()

task testUi, "Discover Tyr Otter tests and open the isolated test UI":
  buildOtterTestUi()
  runCommand(otterTestUiPath(), @["--repo-root:" & getCurrentDir()])

task test_webui_interop, "Build WASM and run the automated WebUI browser/backend interoperability smoke test":
  exec "nimble build_wasm_custom_crypto"
  exec "nimble c -r -d:tyrWebUiInteropSmoke --out:build/" & hostExeName("test_webui_interop_smoke") & " --nimcache:" & repoNimcacheDir("nimcache_test_webui_interop").replace('\\', '/') & " evaluation/tests/test_interop_contracts.nim"

task test_interop_backend, "Run the retained native browser transport contracts":
  exec "nimble c -r --out:build/" & hostExeName("test_interop_backend") & " --nimcache:" & repoNimcacheDir("nimcache_test_interop_backend").replace('\\', '/') & " evaluation/tests/test_interop_contracts.nim"

task test_interop_catalog, "Run retained functional catalog entries":
  exec "nimble c -r -d:tyrTestCatalogContract --out:build/" & hostExeName("test_interop_catalog") & " --nimcache:" & repoNimcacheDir("nimcache_test_interop_catalog").replace('\\', '/') & " evaluation/tests/test_interop_contracts.nim"

task test_interop_processes, "Run retained native and WASM process isolation contracts":
  exec "nimble c -r -d:tyrTestProcessContract --out:build/" & hostExeName("test_interop_processes") & " --nimcache:" & repoNimcacheDir("nimcache_test_interop_processes").replace('\\', '/') & " evaluation/tests/test_interop_contracts.nim"

task test_testui_wasm_catalog, "Compile-check every Test UI card for executable WASM":
  exec "nimble c -r -d:tyrTestWasmCatalogContract --out:build/" & hostExeName("test_testui_wasm_catalog") & " --nimcache:" & repoNimcacheDir("nimcache_test_testui_wasm_catalog").replace('\\', '/') & " evaluation/tests/test_interop_contracts.nim"

task test_backend_matrix, "Run the backend matrix bench against liboqs and libsodium":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_backend_matrix").replace('\\', '/') & " -d:hasLibOqs -d:hasLibsodium -r evaluation/tests/test_backend_matrix.nim")

task test_public_api_surface, "Compile and run the top-level public API export smoke test":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_public_api_surface").replace('\\', '/') & " -d:hasLibOqs -d:hasLibsodium -r evaluation/tests/test_public_api_surface.nim")

task test_single_select, "Compile-check every -d:tyr...=<name> single-family build mode":
  ## Each module must build with no flag (all families) and with each value.
  for spec in @[("tyrKem", @["kyber","mceliece","frodo","bike","ntru","saber"], "kems"),
      ("tyrSig", @["dilithium","falcon","sphincs","ed25519"], "signatures"),
      ("tyrHash", @["blake3","sha256","sha512","sha3"], "hashes"),
      ("tyrMac", @["poly1305","hmac"], "macs"),
      ("tyrKdf", @["argon2","blake3gimli","custom"], "kdfs"),
      ("tyrCipher", @["chacha20","xchacha20","aesctr","gimli"], "ciphers")]:
    exec withRepoCaches("nim check --nimcache:" &
      repoNimcacheDir("nimcache_single_" & spec[2]).replace('\\', '/') &
      " src/tyr/" & spec[2] & "/single.nim")
    for v in spec[1]:
      exec withRepoCaches("nim check --nimcache:" &
        repoNimcacheDir("nimcache_single_" & spec[2] & "_" & v).replace('\\', '/') &
        " -d:" & spec[0] & "=" & v & " src/tyr/" & spec[2] & "/single.nim")


## Shared tasks (autopush, switch, applyNightly, updateSubmodules, clean, …):
## the sibling clone wins, the submodule is the fallback. `nimble sharedTasks`
when fileExists(thisDir() & "/../Nimble-Tasks/src/nimbleTasks.nims"):
  include "../Nimble-Tasks/src/nimbleTasks.nims"
elif fileExists(thisDir() & "/submodules/Nimble-Tasks/src/nimbleTasks.nims"):
  include "submodules/Nimble-Tasks/src/nimbleTasks.nims"
else:
  {.error: "Nimble-Tasks not found: git submodule update --init submodules/Nimble-Tasks".}
