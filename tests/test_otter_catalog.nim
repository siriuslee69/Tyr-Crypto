## -----------------------------------------------------------------
## Otter Test Catalog <- isolated entry points for Tyr desktop tests
## -----------------------------------------------------------------

import std/[json, os, osproc, strutils]

import otter_repo_evaluation
import ./webui_interop/test_catalog

proc repoRoot(): string =
  ## Returns the Tyr repository root used by the established test runner.
  result = parentDir(parentDir(currentSourcePath()))

proc selectedNimFlags(): string =
  ## Converts inherited Otter symbols into nested Nim compiler flags.
  var
    flag: string = ""
  if not existsEnv("OTTER_UI_FLAGS"):
    return
  result = "-d:tyrExplicitCapabilities -u:sse2 -u:avx2 -u:aesni -u:neon"
  for candidate in getEnv("OTTER_UI_FLAGS").split(','):
    flag = candidate.strip()
    if flag.len > 0:
      result.add(" ")
      case flag
      of "gcArc":
        result.add("--mm:arc")
      of "gcOrc":
        result.add("--mm:orc")
      of "sse2":
        result.add("-d:sse2 --passC:-msse2")
      of "avx2":
        result.add("-d:avx2 --passC:-mavx2 --passL:-mavx2")
      of "aesni":
        result.add("-d:aesni --passC:-maes")
      of "neon":
        result.add("-d:neon")
      else:
        result.add("-d:" & flag)

proc runDesktopGroup(name: string) =
  ## Runs one existing desktop group without duplicating its test definitions.
  var
    args: seq[string] = @["r", "tools/run_desktop_tests_parallel.nim", "--",
      "--runGroup:" & name]
    flags: string = selectedNimFlags()
    process: Process
    exitCode: int = 0
  if flags.len > 0:
    args.add("--childNimFlags:" & flags)
  process = startProcess("nim", workingDir = repoRoot(), args = args,
      options = {poParentStreams, poUsePath})
  exitCode = process.waitForExit()
  process.close()
  if exitCode != 0:
    raise newException(OSError, "Tyr desktop group failed: " & name)

proc runTask(name: string) =
  ## Runs one retained interoperability contract through its existing task.
  var
    process: Process = startProcess("nimble", workingDir = repoRoot(),
      args = @[name, "-y"], options = {poParentStreams, poUsePath})
    exitCode: int = 0
  exitCode = process.waitForExit()
  process.close()
  if exitCode != 0:
    raise newException(OSError, "Tyr test task failed: " & name)

proc runCatalogTest(id: string) =
  ## Runs one retained allowlisted Tyr test or benchmark definition.
  var
    response: JsonNode = parseJson(runCatalogEntry(id))
  if not response{"passed"}.getBool(false):
    raise newException(OSError, "Tyr catalog test failed: " & id & "\n" &
      response{"outputTail"}.getStr(""))

proc runCatalogWasmTest(id: string) =
  ## Compiles and runs one retained allowlisted Tyr test under Node-WASM.
  var
    response: JsonNode = parseJson(runCatalogWasmEntry(id))
  if not response{"passed"}.getBool(false):
    raise newException(OSError, "Tyr WASM catalog test failed: " & id & "\n" &
      response{"outputTail"}.getStr(""))

proc otterCore*() {.otterUiTest: ("Core APIs", "Tyr", "functional, api", "").} =
  runDesktopGroup("core")

proc otterCustomCrypto*() {.otterUiTest: ("Custom crypto", "Tyr", "functional, symmetric", "Native").} =
  runDesktopGroup("custom_crypto")

proc otterCustomCryptoWasm*() {.otterUiTest: ("Custom crypto", "Tyr", "functional, symmetric, wasm", "WASM").} =
  runCatalogWasmTest("foundation")

proc otterSha3*() {.otterUiTest: ("SHA-3", "Tyr", "functional, hash, simd", "Native").} =
  runDesktopGroup("sha3")

proc otterSha3Wasm*() {.otterUiTest: ("SHA-3", "Tyr", "functional, hash, simd, wasm", "WASM").} =
  runCatalogWasmTest("sha3")

proc otterPoly1305*() {.otterUiTest: ("Poly1305", "Tyr", "functional, mac, simd", "Native").} =
  runDesktopGroup("poly1305")

proc otterPoly1305Wasm*() {.otterUiTest: ("Poly1305", "Tyr", "functional, mac, simd, wasm", "WASM").} =
  runCatalogWasmTest("poly1305")

proc otterAes*() {.otterUiTest: ("AES", "Tyr", "functional, symmetric", "Native").} =
  runDesktopGroup("aes")

proc otterAesWasm*() {.otterUiTest: ("AES", "Tyr", "functional, symmetric, wasm", "WASM").} =
  runCatalogWasmTest("aes")

proc otterGimli*() {.otterUiTest: ("Gimli", "Tyr", "functional, hash, simd", "Native").} =
  runDesktopGroup("gimli")

proc otterGimliWasm*() {.otterUiTest: ("Gimli", "Tyr", "functional, hash, simd, wasm", "WASM").} =
  runCatalogWasmTest("gimli")

proc otterBlake3*() {.otterUiTest: ("BLAKE3", "Tyr", "functional, hash, simd", "Native").} =
  runDesktopGroup("blake3")

proc otterBlake3Wasm*() {.otterUiTest: ("BLAKE3", "Tyr", "functional, hash, simd, wasm", "WASM").} =
  runCatalogWasmTest("blake3")

proc otterArgon2*() {.otterUiTest: ("Argon2", "Tyr", "functional, password", "Native").} =
  runDesktopGroup("argon2")

proc otterArgon2Wasm*() {.otterUiTest: ("Argon2", "Tyr", "functional, password, wasm", "WASM").} =
  runCatalogWasmTest("argon2")

proc otterXchacha20*() {.otterUiTest: ("XChaCha20", "Tyr", "functional, symmetric, simd", "Native").} =
  runDesktopGroup("xchacha20")

proc otterXchacha20Wasm*() {.otterUiTest: ("XChaCha20", "Tyr", "functional, symmetric, simd, wasm", "WASM").} =
  runCatalogWasmTest("chacha")

proc otterRandom*() {.otterUiTest: ("Random entropy", "Tyr", "functional, entropy", "Native").} =
  runDesktopGroup("random")

proc otterRandomWasm*() {.otterUiTest: ("Random entropy", "Tyr", "functional, entropy, wasm", "WASM").} =
  runCatalogWasmTest("random")

proc otterHmac*() {.otterUiTest: ("HMAC", "Tyr", "functional, mac", "Native").} =
  runDesktopGroup("hmac")

proc otterHmacWasm*() {.otterUiTest: ("HMAC", "Tyr", "functional, mac, wasm", "WASM").} =
  runCatalogWasmTest("hmac")

proc otterOtp*() {.otterUiTest: ("One-time passwords", "Tyr", "functional, password", "Native").} =
  runDesktopGroup("otp")

proc otterOtpWasm*() {.otterUiTest: ("One-time passwords", "Tyr", "functional, password, wasm", "WASM").} =
  runCatalogWasmTest("otp")

proc otterX25519*() {.otterUiTest: ("X25519", "Tyr", "functional, classical, simd", "Native").} =
  runDesktopGroup("x25519")

proc otterX25519Wasm*() {.otterUiTest: ("X25519", "Tyr", "functional, classical, simd, wasm", "WASM").} =
  runCatalogWasmTest("x25519")

proc otterEd25519*() {.otterUiTest: ("Ed25519", "Tyr", "functional, classical", "Native").} =
  runDesktopGroup("ed25519")

proc otterEd25519Wasm*() {.otterUiTest: ("Ed25519", "Tyr", "functional, classical, wasm", "WASM").} =
  runCatalogWasmTest("ed25519")

proc otterKyber*() {.otterUiTest: ("Kyber", "Tyr", "functional, pq-kem, kat", "Native").} =
  runDesktopGroup("kyber")

proc otterKyberWasm*() {.otterUiTest: ("Kyber", "Tyr", "functional, pq-kem, kat, wasm", "WASM").} =
  runCatalogWasmTest("kyber")

proc otterFrodo*() {.otterUiTest: ("FrodoKEM", "Tyr", "functional, pq-kem, kat", "Native").} =
  runDesktopGroup("frodo")

proc otterFrodoWasm*() {.otterUiTest: ("FrodoKEM", "Tyr", "functional, pq-kem, kat, wasm", "WASM").} =
  runCatalogWasmTest("frodo")

proc otterBike*() {.otterUiTest: ("BIKE", "Tyr", "functional, pq-kem, kat", "Native").} =
  runDesktopGroup("bike")

proc otterBikeWasm*() {.otterUiTest: ("BIKE", "Tyr", "functional, pq-kem, kat, wasm", "WASM").} =
  runCatalogWasmTest("bike")

proc otterNtru*() {.otterUiTest: ("NTRU", "Tyr", "functional, pq-kem", "Native").} =
  runDesktopGroup("ntru")

proc otterNtruWasm*() {.otterUiTest: ("NTRU", "Tyr", "functional, pq-kem, wasm", "WASM").} =
  runCatalogWasmTest("ntru")

proc otterSaber*() {.otterUiTest: ("SABER", "Tyr", "functional, pq-kem", "Native").} =
  runDesktopGroup("saber")

proc otterSaberWasm*() {.otterUiTest: ("SABER", "Tyr", "functional, pq-kem, wasm", "WASM").} =
  runCatalogWasmTest("saber")

proc otterDilithium*() {.otterUiTest: ("Dilithium", "Tyr", "functional, pq-signature, kat", "Native").} =
  runDesktopGroup("dilithium")

proc otterDilithiumWasm*() {.otterUiTest: ("Dilithium", "Tyr", "functional, pq-signature, kat, wasm", "WASM").} =
  runCatalogWasmTest("dilithium")

proc otterFalcon512*() {.otterUiTest: ("Falcon-512", "Tyr", "functional, pq-signature", "Native").} =
  runDesktopGroup("falcon512")

proc otterFalcon512Wasm*() {.otterUiTest: ("Falcon-512", "Tyr", "functional, pq-signature, wasm", "WASM").} =
  runCatalogWasmTest("falcon512")

proc otterFalcon1024*() {.otterUiTest: ("Falcon-1024", "Tyr", "functional, pq-signature, long", "Native").} =
  runDesktopGroup("falcon1024")

proc otterFalcon1024Wasm*() {.otterUiTest: ("Falcon-1024", "Tyr", "functional, pq-signature, long, wasm", "WASM").} =
  runCatalogWasmTest("falcon1024")

proc otterSphincs*() {.otterUiTest: ("SPHINCS+", "Tyr", "functional, pq-signature, kat", "Native").} =
  runDesktopGroup("sphincs")

proc otterSphincsWasm*() {.otterUiTest: ("SPHINCS+", "Tyr", "functional, pq-signature, kat, wasm", "WASM").} =
  runCatalogWasmTest("sphincs")

proc otterMceliece*() {.otterUiTest: ("Classic McEliece", "Tyr", "functional, pq-kem", "Native").} =
  runDesktopGroup("mceliece")

proc otterMcelieceWasm*() {.otterUiTest: ("Classic McEliece", "Tyr", "functional, pq-kem, wasm", "WASM").} =
  runCatalogWasmTest("mceliece")

proc otterInteropBackend*() {.otterUiTest: ("Browser interop contracts", "Tyr", "functional, interop", "Native backend").} =
  runTask("test_interop_backend")

proc otterInteropCatalog*() {.otterUiTest: ("Browser interop contracts", "Tyr", "functional, interop", "Catalog execution").} =
  runTask("test_interop_catalog")

proc otterInteropProcesses*() {.otterUiTest: ("Browser interop contracts", "Tyr", "functional, interop, process", "Process isolation").} =
  runTask("test_interop_processes")

proc otterInteropWasmAudit*() {.otterUiTest: ("Browser interop contracts", "Tyr", "interop, wasm, compile", "WASM catalog").} =
  runTask("test_testui_wasm_catalog")

proc otterBrowserWasm*() {.otterUiTest: ("Browser interop contracts", "Tyr", "interop, wasm, browser", "Browser matrix").} =
  runTask("test_webui_interop")

proc otterBenchBytes*() {.otterUiTest: ("Byte primitives", "Tyr benchmarks", "benchmark, symmetric, hash, mac", "").} =
  runTask("bench_custom_crypto")

proc otterBenchKdf*() {.otterUiTest: ("KDF generators", "Tyr benchmarks", "benchmark, password", "").} =
  runTask("bench_custom_kdf")

proc otterBenchClassical*() {.otterUiTest: ("Curve25519 and Ed25519", "Tyr benchmarks", "benchmark, classical", "").} =
  runTask("bench_curve25519_ed25519")

proc otterBenchSigmaCore*() {.otterUiTest: ("Otter comparisons", "Tyr benchmarks", "benchmark, symmetric, hash", "Core").} =
  runTask("perf_sigma")

proc otterBenchSigmaPq*() {.otterUiTest: ("Otter comparisons", "Tyr benchmarks", "benchmark, pq-kem, pq-signature", "Post-quantum").} =
  runTask("perf_sigma_pq")

proc otterBenchSigmaKyber*() {.otterUiTest: ("Otter comparisons", "Tyr benchmarks", "benchmark, pq-kem", "Kyber").} =
  runTask("perf_sigma_kyber")

proc otterBenchSigmaDilithium*() {.otterUiTest: ("Otter comparisons", "Tyr benchmarks", "benchmark, pq-signature", "Dilithium").} =
  runTask("perf_sigma_dilithium")

proc otterBenchSigmaFalcon*() {.otterUiTest: ("Otter comparisons", "Tyr benchmarks", "benchmark, pq-signature", "Falcon").} =
  runTask("perf_sigma_falcon")

proc otterProfilePq*() {.otterUiTest: ("Otter timing", "Tyr benchmarks", "benchmark, profile, pq-kem, pq-signature", "Post-quantum").} =
  runTask("perf_otter_pq")

proc otterProfileKyber*() {.otterUiTest: ("Otter timing", "Tyr benchmarks", "benchmark, profile, pq-kem", "Kyber").} =
  runTask("perf_otter_kyber")

proc otterTlsPrimitives*() {.otterUiTest: ("SHA-256 and TLS KDF", "Tyr retained catalog", "functional, vectors, hash", "Native").} =
  runCatalogTest("sha256")

proc otterTlsPrimitivesWasm*() {.otterUiTest: ("SHA-256 and TLS KDF", "Tyr retained catalog", "functional, vectors, hash, wasm", "WASM").} =
  runCatalogWasmTest("sha256")

proc otterComposite*() {.otterUiTest: ("Composite cipher suites", "Tyr retained catalog", "functional, symmetric, edge", "Native").} =
  runCatalogTest("composite")

proc otterCompositeWasm*() {.otterUiTest: ("Composite cipher suites", "Tyr retained catalog", "functional, symmetric, edge, wasm", "WASM").} =
  runCatalogWasmTest("composite")

proc otterChunkedCrypto*() {.otterUiTest: ("Chunked encryption", "Tyr retained catalog", "functional, symmetric, edge", "Native").} =
  runCatalogTest("chunky")

proc otterChunkedCryptoWasm*() {.otterUiTest: ("Chunked encryption", "Tyr retained catalog", "functional, symmetric, edge, wasm", "WASM").} =
  runCatalogWasmTest("chunky")

proc otterWrapper*() {.otterUiTest: ("Wrapper authentication", "Tyr retained catalog", "functional, api, vectors", "Native").} =
  runCatalogTest("wrapper")

proc otterWrapperWasm*() {.otterUiTest: ("Wrapper authentication", "Tyr retained catalog", "functional, api, vectors, wasm", "WASM").} =
  runCatalogWasmTest("wrapper")

proc otterPublicApi*() {.otterUiTest: ("Public API surfaces", "Tyr retained catalog", "functional, api, edge", "Native").} =
  runCatalogTest("public-api")

proc otterPublicApiWasm*() {.otterUiTest: ("Public API surfaces", "Tyr retained catalog", "functional, api, edge, wasm", "WASM").} =
  runCatalogWasmTest("public-api")

proc otterWasmBridge*() {.otterUiTest: ("JSON bridge", "Tyr retained catalog", "functional, interop", "Native").} =
  runCatalogTest("wasm-bridge")

proc otterWasmBridgeWasm*() {.otterUiTest: ("JSON bridge", "Tyr retained catalog", "functional, interop, wasm", "WASM").} =
  runCatalogWasmTest("wasm-bridge")

proc otterBenchKem*() {.otterUiTest: ("Custom crypto table", "Tyr retained benchmarks", "benchmark, pq-kem", "KEM").} =
  runCatalogTest("bench-kem")

proc otterBenchSignature*() {.otterUiTest: ("Custom crypto table", "Tyr retained benchmarks", "benchmark, pq-signature", "Signatures").} =
  runCatalogTest("bench-signature")

proc otterBenchFalconPrepared*() {.otterUiTest: ("Custom crypto table", "Tyr retained benchmarks", "benchmark, pq-signature", "Falcon prepared").} =
  runCatalogTest("bench-falcon")

proc otterBenchAsymmetric*() {.otterUiTest: ("Asymmetric collector", "Tyr retained benchmarks", "benchmark, classical, pq-kem, pq-signature", "").} =
  runCatalogTest("bench-asymmetric")

proc otterSigmaCompare*() {.otterUiTest: ("Otter comparisons", "Tyr retained benchmarks", "benchmark, symmetric, hash", "BLAKE3 and ChaCha").} =
  runCatalogTest("bench-sigma-compare")

proc otterSigmaFrodo*() {.otterUiTest: ("Otter comparisons", "Tyr retained benchmarks", "benchmark, pq-kem", "Frodo profile").} =
  runCatalogTest("bench-sigma-frodo")

proc otterProfileBytes*() {.otterUiTest: ("Otter timing", "Tyr retained benchmarks", "benchmark, profile, symmetric, hash", "Byte primitives").} =
  runCatalogTest("bench-otter-bytes")

proc otterProfileX25519*() {.otterUiTest: ("Otter timing", "Tyr retained benchmarks", "benchmark, profile, classical", "X25519").} =
  runCatalogTest("bench-otter-x25519")

proc otterProfileDilithium*() {.otterUiTest: ("Otter timing", "Tyr retained benchmarks", "benchmark, profile, pq-signature", "Dilithium").} =
  runCatalogTest("bench-otter-dilithium")
