import std/[os, strutils]

# Package descriptor for the crypto bindings sub-project.

version       = "0.1.0"
author        = "siriuslee69"
description   = "Bindings for classical and post-quantum cryptographic primitives."
license       = "Unlicense"
srcDir        = "src"
bin           = @[]
requires "nim >= 1.6.0", "nimcrypto >= 0.6.0", "nimsimd >= 1.3.2"

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

proc progressCommitMessage(): string =
  let candidatePaths = @[".iron/PROGRESS.md", ".iron/progress.md", "iron/progress.md"]
  var
    path: string = ""
    i: int = 0
  while i < candidatePaths.len:
    if fileExists(candidatePaths[i]):
      path = candidatePaths[i]
      break
    inc i
  if path.len > 0:
    let content = readFile(path)
    for line in content.splitLines:
      if line.startsWith("Commit Message:"):
        result = line["Commit Message:".len .. ^1].strip()
        break
  if result.len == 0:
    result = "No specific commit message given."

proc currentUpstreamBranch(): string =
  let probe = probeCommand("git", @["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
  if probe.exitCode == 0:
    result = probe.output.strip()

proc branchDivergenceCounts(): tuple[ahead: int, behind: int] =
  let probe = probeCommand("git", @["rev-list", "--left-right", "--count", "HEAD...@{u}"])
  if probe.exitCode != 0:
    return
  let parts = probe.output.strip().splitWhitespace()
  if parts.len >= 2:
    try:
      result.ahead = parseInt(parts[0])
      result.behind = parseInt(parts[1])
    except ValueError:
      discard

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
      joinPath(getCurrentDir(), "submodules", "otter_repo_evaluation", "src"),
      joinPath(getCurrentDir(), "..", "Otter-RepoEvaluation", "src")
    ],
    "Otter-RepoEvaluation"
  )

task check, "Run nim check on core modules":
  exec withRepoCaches("nim check .iron/meta/registry.nim")
  exec withRepoCaches("nim check --nimcache:" & repoNimcacheDir("nimcache_check_public").replace('\\', '/') & " src/tyr_crypto.nim")

task check_core, "Run nim check on core modules without Nimble's built-in package check":
  exec withRepoCaches("nim check .iron/meta/registry.nim")
  exec withRepoCaches("nim check --nimcache:" & repoNimcacheDir("nimcache_check_public").replace('\\', '/') & " src/tyr_crypto.nim")

task check_asymmetric_references, "Check asymmetric function citations and locked references":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_check_asymmetric_references").replace('\\', '/') & " tools/check_asymmetric_references.nim")

task test_asymmetric_audit, "Run focused asymmetric conformance and malformed-input tests":
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_x25519").replace('\\', '/') & " tests/test_x25519_custom.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_ed25519").replace('\\', '/') & " tests/test_ed25519_custom.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_dilithium").replace('\\', '/') & " tests/test_dilithium_tyr.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_kyber").replace('\\', '/') & " tests/test_kyber_tyr.nim")
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_audit_sphincs").replace('\\', '/') & " tests/test_sphincs_tyr.nim")

task test, "Run the crypto bindings test suite":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " tools/run_desktop_tests_parallel.nim")

task test_all, "Run the full crypto bindings test suite with libsodium, liboqs, and OpenSSL":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " tools/run_desktop_tests_parallel.nim -- --full")

task test_all_threads_on, "Run test_all with threads enabled":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " tools/run_desktop_tests_parallel.nim -- --full --childNimFlags:\"--gc:orc --threads:on\"")

task test_all_threads_off, "Run test_all with threads disabled":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_run_desktop_tests_parallel").replace('\\', '/') & " tools/run_desktop_tests_parallel.nim -- --full --childNimFlags:\"--gc:orc --threads:off\"")

task test_gimli, "Run Gimli SSE tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli").replace('\\', '/') & " -r tests/test_gimli_sse.nim")

task test_gimli_avx, "Run Gimli AVX tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli_avx").replace('\\', '/') & " --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r tests/test_gimli_sse.nim")

task test_blake3_simd, "Run Blake3 SIMD tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_blake3_simd").replace('\\', '/') & " --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r tests/test_blake3_simd.nim")

task test_ntru_saber, "Run NTRU and SABER KAT/roundtrip tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_ntru_tyr").replace('\\', '/') & " -r tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_saber_tyr").replace('\\', '/') & " -r tests/test_saber_tyr.nim")

task test_ntru_saber_avx2, "Run NTRU/SABER tests with AVX2 enabled where supported":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_ntru_tyr_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2 -mbmi2\" --passL:\"-mavx2\" -r tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_saber_tyr_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2\" --passL:\"-mavx2\" -r tests/test_saber_tyr.nim")

task test_frodo_native_fast, "Run Frodo with AVX2 matrix math and native AES-NI":
  exec withRepoCaches("nim c -d:release -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-mavx2\" --nimcache:" & repoNimcacheDir("nimcache_test_frodo_native_fast").replace('\\', '/') & " -r tests/test_frodo_tyr.nim")

task test_neon_checks, "Compile-check the ARM64/NEON SIMD coverage matrix":
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_xchacha20").replace('\\', '/') & " tests/test_xchacha20_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_blake3").replace('\\', '/') & " tests/test_blake3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sha3").replace('\\', '/') & " tests/test_sha3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_poly1305").replace('\\', '/') & " tests/test_poly1305_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_gimli").replace('\\', '/') & " tests/test_gimli_sse.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_aes").replace('\\', '/') & " tests/test_aes_ctr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_custom").replace('\\', '/') & " tests/test_custom_crypto.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_x25519").replace('\\', '/') & " tests/test_x25519_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_kyber").replace('\\', '/') & " tests/test_kyber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_frodo").replace('\\', '/') & " tests/test_frodo_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_bike").replace('\\', '/') & " tests/test_bike_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_ntru").replace('\\', '/') & " tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_saber").replace('\\', '/') & " tests/test_saber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_dilithium").replace('\\', '/') & " tests/test_dilithium_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sphincs").replace('\\', '/') & " tests/test_sphincs_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_mceliece").replace('\\', '/') & " tests/test_mceliece_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_falcon").replace('\\', '/') & " tests/test_falcon_tyr.nim")

task test_simd_matrix, "Run the host SIMD/runtime suite and the ARM64/NEON compile-check matrix":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_custom_crypto_matrix").replace('\\', '/') & " -r tests/test_custom_crypto.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_aes_ctr_matrix").replace('\\', '/') & " -r tests/test_aes_ctr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_xchacha20_matrix").replace('\\', '/') & " -r tests/test_xchacha20_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_blake3_matrix").replace('\\', '/') & " -r tests/test_blake3_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_sha3_matrix").replace('\\', '/') & " -r tests/test_sha3_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_poly1305_matrix").replace('\\', '/') & " -r tests/test_poly1305_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli_matrix").replace('\\', '/') & " -r tests/test_gimli_sse.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_x25519_matrix").replace('\\', '/') & " -r tests/test_x25519_simd.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_ntru_matrix_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2 -mbmi2\" --passL:\"-mavx2\" -r tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_saber_matrix_avx2").replace('\\', '/') & " -d:avx2 --passC:\"-mavx2\" --passL:\"-mavx2\" -r tests/test_saber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_xchacha20").replace('\\', '/') & " tests/test_xchacha20_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_blake3").replace('\\', '/') & " tests/test_blake3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sha3").replace('\\', '/') & " tests/test_sha3_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_poly1305").replace('\\', '/') & " tests/test_poly1305_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_gimli").replace('\\', '/') & " tests/test_gimli_sse.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_aes").replace('\\', '/') & " tests/test_aes_ctr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_custom").replace('\\', '/') & " tests/test_custom_crypto.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_x25519").replace('\\', '/') & " tests/test_x25519_simd.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_kyber").replace('\\', '/') & " tests/test_kyber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_frodo").replace('\\', '/') & " tests/test_frodo_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_bike").replace('\\', '/') & " tests/test_bike_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_ntru").replace('\\', '/') & " tests/test_ntru_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_saber").replace('\\', '/') & " tests/test_saber_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_dilithium").replace('\\', '/') & " tests/test_dilithium_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_sphincs").replace('\\', '/') & " tests/test_sphincs_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_mceliece").replace('\\', '/') & " tests/test_mceliece_tyr.nim")
  exec withRepoCaches("nim check --cpu:arm64 -d:neon --nimcache:" & repoNimcacheDir("nimcache_test_neon_falcon").replace('\\', '/') & " tests/test_falcon_tyr.nim")

task test_wasm, "Run wasm bridge regression tests":
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_wasm_test").replace('\\', '/') & " tests/test_wasm_bridge.nim")

task build_android_harness, "Cross-compile the Android native test binaries and build the harness APK":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_build_android_harness").replace('\\', '/') & " tools/build_android_harness.nim")

task build_android_harness_asymmetric_fast, "Build the Android harness APK with the reduced asymmetric/PQ native test bundle":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_build_android_harness").replace('\\', '/') & " tools/build_android_harness.nim -- --harnessTarget:asymmetric_fast --release")

task build_android_harness_asymmetric_full, "Build the Android harness APK with the full asymmetric/PQ native test bundle":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_build_android_harness").replace('\\', '/') & " tools/build_android_harness.nim -- --harnessTarget:asymmetric_full --release")

task test_pin, "Run interactive pin + key unwrap test.":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_pin").replace('\\', '/') & " -d:hasLibsodium -r tests/test_pin_key_interactive.nim")

task perf_sigma, "Benchmark custom crypto with Otter helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf.nim")

task perf_sigma_pq, "Benchmark Tyr PQ backends against liboqs with Otter helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_pq").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_pq.nim")

task perf_sigma_dilithium, "Benchmark split Tyr Dilithium phases against the current liboqs profile":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_dilithium").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_dilithium.nim")

task perf_sigma_falcon, "Benchmark split Tyr Falcon phases against the current liboqs profile":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_falcon").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_falcon.nim")

task perf_sigma_dilithium_scalar, "Benchmark scalar Tyr Dilithium against the scalar liboqs Dilithium profile":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_dilithium_scalar_zig_mingw"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_dilithium_scalar").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -r tests/test_sigma_perf_dilithium.nim")

task perf_sigma_kyber, "Benchmark Tyr Kyber against liboqs with Otter helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_kyber").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_kyber_only.nim")

task perf_sigma_pq_aesni, "Benchmark Tyr PQ backends against liboqs with Otter helpers and AES-NI enabled":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_pq_aesni").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_pq.nim")

task perf_sigma_frodo_portable, "Benchmark Tyr Frodo against the portable Frodo-focused liboqs build":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_portable"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_frodo_portable").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_frodo_profile.nim")

task perf_sigma_frodo_ossl, "Benchmark Tyr Frodo against the OpenSSL-backed Frodo-focused liboqs build":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_ossl"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_frodo_ossl").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_frodo_profile.nim")

task bench_pq_profiles, "Build matched scalar/AVX2 liboqs profiles and run Otter PQ comparison benches":
  exec withRepoCaches("nim r --nimcache:" & repoNimcacheDir("nimcache_bench_pq_profiles").replace('\\', '/') & " tools/bench_pq_profiles.nim")

task bench_custom_crypto, "Run the unified Tyr-only custom-crypto benchmark report":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_bench_custom_crypto").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tools/bench_custom_crypto_table.nim")

task bench_curve25519_ed25519, "Benchmark pure Nim X25519 and Ed25519 implementations":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_bench_x25519").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_x25519_perf.nim")
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_bench_ed25519").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_ed25519_perf.nim")

task bench_custom_kdf, "Run the custom KDF generator benchmark table":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_bench_custom_kdf").replace('\\', '/') & " -d:release -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tools/bench_custom_kdf.nim")

task perf_otter_pq, "Profile Tyr PQ functions with Otter timing instrumentation":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_otter_pq").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:otterTiming -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_otter_perf_pq.nim")

task perf_otter_kyber, "Profile Tyr Kyber functions with Otter timing instrumentation":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_otter_kyber").replace('\\', '/') & " --path:src --path:" & otterSrcDir() & " -d:release -d:otterTiming -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_otter_perf_kyber_only.nim")


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

task autopush, "Add, commit, and push the current branch with message from .iron/PROGRESS.md":
  var
    msg: string = progressCommitMessage()
    staged: string = ""
    branch: string = ""
    upstream: string = ""
    diverged: tuple[ahead: int, behind: int]
  runCommand("git", @["add", "-A", "."])
  staged = captureCommand("git", @["diff", "--cached", "--name-only"]).strip()
  if staged.len == 0:
    echo "No staged changes. Skipping commit."
  else:
    runCommand("git", @["commit", "-m", msg])
  branch = captureCommand("git", @["branch", "--show-current"]).strip()
  if branch.len == 0:
    quit "Refusing autopush from detached HEAD."
  upstream = currentUpstreamBranch()
  if upstream.len == 0:
    ## First push of this branch: create origin/<branch> and track it.
    runCommand("git", @["push", "--set-upstream", "origin", branch])
    return
  diverged = branchDivergenceCounts()
  if diverged.behind > 0:
    runCommand("git", @["pull", "--rebase", "--autostash"])
  ## Push the current branch explicitly so the result never depends on
  ## the local push.default setting.
  runCommand("git", @["push", "origin", branch])

task switch, "Toggle the working branch between nightly and main":
  var
    branch: string = captureCommand("git", @["branch", "--show-current"]).strip()
    target: string = ""
  ## nightly <-> main; from any other branch, land on nightly (the
  ## active development branch).
  if branch == "nightly":
    target = "main"
  else:
    target = "nightly"
  echo "Switching from '" & (if branch.len > 0: branch else: "(detached HEAD)") &
    "' to '" & target & "'."
  runCommand("git", @["checkout", target])

task applynightly, "Promote the current nightly state onto main (fast-forward) and push, keeping nightly":
  var
    branch: string = captureCommand("git", @["branch", "--show-current"]).strip()
  ## `git fetch` cannot update the currently checked-out branch, so this
  ## must run from nightly (or any branch other than main). nightly is
  ## never modified - main is the only ref that moves.
  if branch == "main":
    quit "On 'main'. Run `nimble switch` to move to nightly before applying."
  ## Fast-forward local main to nightly. Fetching into a branch ref
  ## refuses a non-fast-forward, so a diverged main fails loudly instead
  ## of silently discarding its commits.
  runCommand("git", @["fetch", ".", "nightly:main"])
  ## Publish the promoted state; the remote enforces fast-forward too.
  runCommand("git", @["push", "origin", "nightly:main"])
  echo "main is now at the nightly state; nightly branch left intact."

task find, "Use local clones for submodules in parent folder":
  let modulesPath = ".gitmodules"
  if not fileExists(modulesPath):
    echo "No .gitmodules found."
  else:
    let root = parentDir(getCurrentDir())
    var current = ""
    for line in readFile(modulesPath).splitLines:
      let s = line.strip()
      if s.startsWith("[submodule"):
        let start = s.find('"')
        let stop = s.rfind('"')
        if start >= 0 and stop > start:
          current = s[start + 1 .. stop - 1]
      elif current.len > 0 and s.startsWith("path"):
        let parts = s.split("=", maxsplit = 1)
        if parts.len == 2:
          let subPath = parts[1].strip()
          let tail = splitPath(subPath).tail
          let localDir = joinPath(root, tail)
          if dirExists(localDir):
            let localUrl = localDir.replace('\\', '/')
            exec "git config -f .gitmodules submodule." & current & ".url " & localUrl
            exec "git config submodule." & current & ".url " & localUrl
    exec "git submodule sync --recursive"

task test_backend_matrix, "Run the backend matrix bench against liboqs and libsodium":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_backend_matrix").replace('\\', '/') & " -d:hasLibOqs -d:hasLibsodium -r tests/test_backend_matrix.nim")

task test_public_api_surface, "Compile and run the top-level public API export smoke test":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_public_api_surface").replace('\\', '/') & " -d:hasLibOqs -d:hasLibsodium -r tests/test_public_api_surface.nim")
