## -----------------------------------------------------------------------
## Test Catalog <- allowlisted custom_crypto tests, benches, and log export
## -----------------------------------------------------------------------

import std/[algorithm, json, os, osproc, strutils, times]

import ../../.iron/meta/metaPragmas

type
  TestCommandKind* = enum
    tckTests,
    tckCustomBench,
    tckKdfBench,
    tckAsymmetricBench

  TestCatalogEntry* {.role: {truthState}.} = object
    id*: string
    title*: string
    family*: string
    tags*: seq[string]
    sources*: seq[string]
    commandKind*: TestCommandKind
    argument*: string
    environment*: seq[tuple[key: string, value: string]]
    wasmThreads*: bool

var
  GResultsDirectory: string = ""
  GResultCounter: int = 0

proc repoRoot(): string {.role: {helper}.} =
  ## Returns the Tyr-Crypto repository root.
  result = parentDir(parentDir(parentDir(currentSourcePath())))

proc defaultResultsDirectory*(): string {.role: {helper}.} =
  ## Returns the default persistent UI result directory.
  result = joinPath(repoRoot(), "testResults")

proc appendPairedTest(C: var seq[TestCatalogEntry], id, title, family: string,
    tags, sources: openArray[string], kind: TestCommandKind = tckTests,
    argument: string = "", environment: openArray[(string, string)] = [],
    wasmThreads: bool = false)
    {.role: {truthBuilder}.} =
  ## C: catalog receiving one fixed test definition.
  ## id/title/family: stable identifier and display labels.
  ## tags/sources: filters and allowlisted Nim entrypoints.
  ## kind/argument/environment: fixed command behavior.
  var
    e: TestCatalogEntry
    i: int = 0
  e.id = id
  e.title = title
  e.family = family
  e.commandKind = kind
  e.argument = argument
  e.wasmThreads = wasmThreads
  while i < tags.len:
    e.tags.add(tags[i])
    i = i + 1
  i = 0
  while i < sources.len:
    e.sources.add(sources[i])
    i = i + 1
  i = 0
  while i < environment.len:
    e.environment.add((key: environment[i][0], value: environment[i][1]))
    i = i + 1
  C.add(e)

template pairedTest*(C: var seq[TestCatalogEntry], id, title, family: string,
    tags, sources: untyped, kind: TestCommandKind = tckTests,
    argument: string = "", environment: untyped = [],
    wasmThreads: bool = false): untyped =
  ## Declares one process-isolated native -> WASM test pair.
  ## Native/WASM commands, phase logs, status, and cancellation are shared.
  appendPairedTest(C, id, title, family, tags, sources, kind, argument,
    environment, wasmThreads)

template addEntry(C: var seq[TestCatalogEntry], id, title, family: string,
    tags, sources: untyped, kind: TestCommandKind = tckTests,
    argument: string = "", environment: untyped = [],
    wasmThreads: bool = false): untyped =
  ## Compatibility spelling; every catalog entry is a paired test declaration.
  pairedTest(C, id, title, family, tags, sources, kind, argument, environment,
    wasmThreads)

proc buildCatalog*(): seq[TestCatalogEntry] {.role: {truthBuilder}.} =
  ## Builds the complete public custom_crypto test and benchmark catalog.
  addEntry(result, "foundation", "Core vectors and KDF", "symmetric",
    ["functional", "vectors", "edge"], ["tests/test_custom_crypto.nim"])
  addEntry(result, "sha256", "SHA-256 and TLS KDF", "hash",
    ["functional", "vectors", "edge"], ["tests/test_tls_primitives.nim"])
  addEntry(result, "sha3", "SHA-3 / SHAKE", "hash",
    ["functional", "vectors", "simd", "edge"],
    ["tests/test_sha3_custom.nim", "tests/test_sha3_simd.nim"])
  addEntry(result, "blake3", "BLAKE3", "hash",
    ["functional", "vectors", "simd", "edge"],
    ["tests/test_blake3_simd.nim", "tests/test_blake3_stream.nim"])
  addEntry(result, "chacha", "ChaCha20 / XChaCha20", "symmetric",
    ["functional", "vectors", "simd", "edge"],
    ["tests/test_xchacha20_simd.nim"])
  addEntry(result, "aes", "AES core and CTR", "symmetric",
    ["functional", "vectors", "simd", "edge"],
    ["tests/test_aes_ctr.nim", "tests/test_aes_gcm_compare.nim"])
  addEntry(result, "gimli", "Gimli permutation and sponge", "hash",
    ["functional", "vectors", "simd"],
    ["tests/test_gimli_sse.nim", "tests/test_gimli_vectors.nim"])
  addEntry(result, "poly1305", "Poly1305", "mac",
    ["functional", "vectors", "simd", "edge"],
    ["tests/test_poly1305_custom.nim", "tests/test_poly1305_simd.nim"])
  addEntry(result, "hmac", "Custom HMAC", "mac",
    ["functional", "vectors", "edge"], ["tests/test_custom_hmac.nim"])
  addEntry(result, "argon2", "Argon2", "password",
    ["functional", "vectors", "simd", "edge"], ["tests/test_argon2_simd.nim"])
  addEntry(result, "random", "Random entropy", "entropy",
    ["functional", "edge"], ["tests/test_random_entropy.nim"])
  addEntry(result, "otp", "One-time passwords", "password",
    ["functional", "vectors", "edge"], ["tests/test_otp.nim"])
  addEntry(result, "x25519", "X25519", "classical",
    ["functional", "vectors", "simd", "edge"],
    ["tests/test_x25519_custom.nim", "tests/test_x25519_simd.nim"])
  addEntry(result, "ed25519", "Ed25519", "classical",
    ["functional", "vectors", "edge"], ["tests/test_ed25519_custom.nim"])
  addEntry(result, "kyber", "Kyber-768 / 1024", "pq-kem",
    ["functional", "vectors", "kat", "simd", "edge"],
    ["tests/test_kyber_tyr.nim", "tests/test_kyber_kat.nim"])
  addEntry(result, "frodo", "FrodoKEM", "pq-kem",
    ["functional", "vectors", "kat", "simd", "edge"],
    ["tests/test_frodo_tyr.nim", "tests/test_frodo_kat.nim"])
  addEntry(result, "bike", "BIKE", "pq-kem",
    ["functional", "vectors", "kat", "edge"],
    ["tests/test_bike_tyr.nim", "tests/test_bike_kat.nim"])
  addEntry(result, "ntru", "NTRU", "pq-kem",
    ["functional", "vectors", "kat", "simd", "edge"],
    ["tests/test_ntru_tyr.nim"])
  addEntry(result, "saber", "SABER", "pq-kem",
    ["functional", "vectors", "kat", "simd", "edge"],
    ["tests/test_saber_tyr.nim"])
  addEntry(result, "mceliece", "Classic McEliece", "pq-kem",
    ["functional", "vectors", "edge"],
    ["tests/test_mceliece_tyr.nim", "tests/test_ct_verify.nim"])
  addEntry(result, "dilithium", "ML-DSA / Dilithium", "pq-signature",
    ["functional", "vectors", "kat", "simd", "edge"],
    ["tests/test_dilithium_tyr.nim", "tests/test_dilithium_kat.nim",
      "tests/test_ct_verify.nim"])
  addEntry(result, "falcon512", "Falcon-512", "pq-signature",
    ["functional", "vectors", "edge"], ["tests/test_falcon_tyr.nim"],
    environment = [("TYR_FALCON_TEST_VARIANT", "512")])
  addEntry(result, "falcon1024", "Falcon-1024", "pq-signature",
    ["functional", "vectors", "edge"], ["tests/test_falcon_tyr.nim"],
    environment = [("TYR_FALCON_TEST_VARIANT", "1024")])
  addEntry(result, "sphincs", "SPHINCS+", "pq-signature",
    ["functional", "vectors", "kat", "edge"],
    ["tests/test_sphincs_tyr.nim", "tests/test_sphincs_kat.nim",
      "tests/test_ct_verify.nim"])
  addEntry(result, "composite", "Composite cipher suites", "composite",
    ["functional", "edge"],
    ["tests/test_aes_gimli.nim", "tests/test_xchacha20_gimli.nim",
      "tests/test_xchacha20_aes_gimli.nim",
      "tests/test_xchacha20_aes_gimli_poly1305.nim"])
  addEntry(result, "chunky", "Chunked encryption", "composite",
    ["functional", "edge"], ["tests/test_chunky_crypto.nim"])
  addEntry(result, "wrapper", "Wrapper authentication", "api",
    ["functional", "vectors", "edge"], ["tests/test_wrapper.nim"])
  addEntry(result, "hybrid", "Hybrid KEX duo and triple", "api",
    ["functional", "edge"],
    ["tests/test_hybrid_kex_duo.nim", "tests/test_hybrid_kex_triple.nim"])
  addEntry(result, "public-api", "Public API surfaces", "api",
    ["functional", "edge"],
    ["tests/test_quick_api.nim", "tests/test_primitives_api.nim",
      "tests/test_public_api_surface.nim", "tests/test_signatures.nim"])
  addEntry(result, "wasm-bridge", "WASM JSON bridge", "interop",
    ["functional", "vectors", "edge"], ["tests/test_wasm_bridge.nim"])
  addEntry(result, "bench-bytes", "Byte primitive benchmarks", "benchmark",
    ["benchmark", "symmetric", "hash", "mac"],
    ["tools/bench_custom_crypto_table.nim"], tckCustomBench, "bytes")
  addEntry(result, "bench-kem", "KEM benchmarks", "benchmark",
    ["benchmark", "pq-kem"], ["tools/bench_custom_crypto_table.nim"],
    tckCustomBench, "kem")
  addEntry(result, "bench-signature", "Signature benchmarks", "benchmark",
    ["benchmark", "pq-signature"], ["tools/bench_custom_crypto_table.nim"],
    tckCustomBench, "signature")
  addEntry(result, "bench-falcon", "Falcon prepared benchmarks", "benchmark",
    ["benchmark", "pq-signature"], ["tools/bench_custom_crypto_table.nim"],
    tckCustomBench, "falcon")
  addEntry(result, "bench-kdf", "KDF generator benchmarks", "benchmark",
    ["benchmark", "password"], ["tools/bench_custom_kdf.nim"], tckKdfBench)
  addEntry(result, "bench-x25519", "X25519 benchmarks", "benchmark",
    ["benchmark", "classical", "simd"], ["tests/test_x25519_perf.nim"])
  addEntry(result, "bench-ed25519", "Ed25519 benchmarks", "benchmark",
    ["benchmark", "classical"], ["tests/test_ed25519_perf.nim"])
  addEntry(result, "bench-asymmetric", "Asymmetric benchmark collector", "benchmark",
    ["benchmark", "classical", "pq-kem", "pq-signature"],
    ["tools/collect_asymmetric_benchmarks.nim"], tckAsymmetricBench)
  addEntry(result, "bench-sigma-core", "Otter core crypto comparison", "benchmark",
    ["benchmark", "symmetric", "hash"], ["tests/test_sigma_perf.nim"],
    wasmThreads = true)
  addEntry(result, "bench-sigma-compare", "BLAKE3 / ChaCha comparison", "benchmark",
    ["benchmark", "symmetric", "hash"],
    ["tests/test_sigma_perf_blake3_chacha_compare.nim"])
  addEntry(result, "bench-sigma-pq", "PQ backend comparison", "benchmark",
    ["benchmark", "pq-kem", "pq-signature"], ["tests/test_sigma_perf_pq.nim"])
  addEntry(result, "bench-sigma-kyber", "Kyber backend comparison", "benchmark",
    ["benchmark", "pq-kem"], ["tests/test_sigma_perf_kyber_only.nim"])
  addEntry(result, "bench-sigma-frodo", "Frodo profile comparison", "benchmark",
    ["benchmark", "pq-kem"], ["tests/test_sigma_perf_frodo_profile.nim"])
  addEntry(result, "bench-sigma-dilithium", "Dilithium phase comparison", "benchmark",
    ["benchmark", "pq-signature"], ["tests/test_sigma_perf_dilithium.nim"])
  addEntry(result, "bench-sigma-falcon", "Falcon phase comparison", "benchmark",
    ["benchmark", "pq-signature"], ["tests/test_sigma_perf_falcon.nim"])
  addEntry(result, "bench-otter-bytes", "Otter byte profiling", "benchmark",
    ["benchmark", "profile", "symmetric", "hash"],
    ["tests/test_otter_perf_blake3_chacha.nim"])
  addEntry(result, "bench-otter-pq", "Otter PQ profiling", "benchmark",
    ["benchmark", "profile", "pq-kem", "pq-signature"],
    ["tests/test_otter_perf_pq.nim"])
  addEntry(result, "bench-otter-x25519", "Otter X25519 profiling", "benchmark",
    ["benchmark", "profile", "classical", "simd"],
    ["tests/test_otter_perf_x25519.nim"])
  addEntry(result, "bench-otter-kyber", "Otter Kyber profiling", "benchmark",
    ["benchmark", "profile", "pq-kem"],
    ["tests/test_otter_perf_kyber_only.nim"])
  addEntry(result, "bench-otter-dilithium", "Otter Dilithium profiling", "benchmark",
    ["benchmark", "profile", "pq-signature"],
    ["tests/test_otter_perf_dilithium.nim"])

proc catalogEntry*(id: string): TestCatalogEntry {.role: {parser}.} =
  ## id: stable allowlisted catalog identifier.
  var
    C: seq[TestCatalogEntry] = buildCatalog()
    i: int = 0
  while i < C.len:
    if C[i].id == id:
      return C[i]
    i = i + 1
  raise newException(ValueError, "unknown test catalog id: " & id)

proc quoteArgs(A: openArray[string]): string {.role: {helper}.} =
  ## A: fixed command arguments to shell-quote.
  var i: int = 0
  while i < A.len:
    if i > 0:
      result.add(" ")
    result.add(quoteShell(A[i]))
    i = i + 1

proc ensureResultsDirectory(path: string): string {.role: {helper}.} =
  ## path: user-selected result directory.
  var expanded: string = path.strip()
  if expanded == "~":
    expanded = getHomeDir()
  elif expanded.startsWith("~/") or expanded.startsWith("~\\"):
    expanded = joinPath(getHomeDir(), expanded[2 .. ^1])
  if expanded.len == 0:
    expanded = defaultResultsDirectory()
  if not expanded.isAbsolute():
    expanded = joinPath(repoRoot(), expanded)
  expanded = normalizedPath(expanded)
  createDir(expanded)
  if not dirExists(expanded):
    raise newException(IOError, "result directory could not be created: " & expanded)
  result = expanded

proc setResultsDirectory*(path: string): string {.role: {helper}.} =
  ## path: editable output location from the dashboard.
  GResultsDirectory = ensureResultsDirectory(path)
  result = GResultsDirectory

proc resultsDirectory*(): string {.role: {helper}.} =
  ## Returns the active output location, creating the default when needed.
  if GResultsDirectory.len == 0:
    discard setResultsDirectory(defaultResultsDirectory())
  result = GResultsDirectory

proc expandDirectory(path: string): string {.role: {helper}.} =
  ## path: editable directory path, including optional home shorthand.
  var expanded: string = path.strip()
  if expanded == "~":
    expanded = getHomeDir()
  elif expanded.startsWith("~/") or expanded.startsWith("~\\"):
    expanded = joinPath(getHomeDir(), expanded[2 .. ^1])
  if expanded.len == 0:
    expanded = resultsDirectory()
  if not expanded.isAbsolute():
    expanded = joinPath(repoRoot(), expanded)
  result = normalizedPath(expanded)

proc browseDirectoryPayload*(path: string): string {.role: {dataFetcher}.} =
  ## path: folder whose direct child folders should be listed.
  var
    current: string = expandDirectory(path)
    directories: seq[string] = @[]
    itemPath: string = ""
  if not dirExists(current):
    raise newException(IOError, "folder does not exist: " & current)
  for kind, child in walkDir(current, relative = false):
    if kind == pcDir:
      itemPath = child
      directories.add(splitPath(itemPath).tail)
  directories.sort(system.cmp[string])
  result = $(%*{
    "ok": true,
    "path": current.replace('\\', '/'),
    "parent": parentDir(current).replace('\\', '/'),
    "directories": directories
  })

proc pickerAvailable(): bool {.role: {helper}.} =
  ## Reports whether this OS has a supported native folder picker.
  when defined(windows):
    result = findExe("powershell.exe").len > 0 or findExe("powershell").len > 0
  elif defined(macosx):
    result = findExe("osascript").len > 0
  else:
    result = findExe("yad").len > 0 or findExe("zenity").len > 0 or
      findExe("kdialog").len > 0

proc pickerCommand(initialPath: string): string {.role: {helper}.} =
  ## initialPath: directory shown first by the native picker.
  when defined(windows):
    result = "powershell -NoProfile -STA -Command \"Add-Type -AssemblyName System.Windows.Forms; " &
      "$d = New-Object System.Windows.Forms.FolderBrowserDialog; " &
      "$d.SelectedPath = '" & initialPath.replace("'", "''") & "'; " &
      "if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) " &
      "{ [Console]::Write($d.SelectedPath) } else { exit 1 }\""
  elif defined(macosx):
    result = "osascript -e 'POSIX path of (choose folder with prompt \"Select test result folder\")'"
  else:
    if findExe("yad").len > 0:
      result = "yad --file --directory --title=\"Select test result folder\" --filename=" &
        quoteShell(initialPath & DirSep)
    elif findExe("zenity").len > 0:
      result = "zenity --file-selection --directory --title=\"Select test result folder\" --filename=" &
        quoteShell(initialPath & DirSep)
    elif findExe("kdialog").len > 0:
      result = "kdialog --getexistingdirectory " & quoteShell(initialPath) &
        " \"Select test result folder\""

proc chooseResultsDirectory*(): string {.role: {actor}.} =
  ## Opens a native folder picker and returns the chosen result directory.
  var
    command: string = pickerCommand(resultsDirectory())
    probe: tuple[output: string, exitCode: int]
    selected: string = ""
  if command.len == 0:
    raise newException(IOError, "no native folder picker is installed; edit the path directly")
  probe = execCmdEx(command, options = {poUsePath, poStdErrToStdOut})
  if probe.exitCode != 0:
    raise newException(IOError, "folder selection was cancelled")
  selected = probe.output.splitLines()[0].strip().strip(chars = {'\'', '"'})
  result = setResultsDirectory(selected)

proc entryJson(e: TestCatalogEntry): JsonNode {.role: {dataWriter}.} =
  ## e: catalog entry to expose to the dashboard.
  result = %*{
    "id": e.id,
    "title": e.title,
    "family": e.family,
    "tags": e.tags,
    "sources": e.sources,
    "wasmThreads": e.wasmThreads
  }

proc catalogPayload*(smokeMode: bool): string {.role: {dataWriter}.} =
  ## smokeMode: true for the hidden browser interoperability smoke process.
  var
    C: seq[TestCatalogEntry] = buildCatalog()
    entries: JsonNode = newJArray()
    i: int = 0
  while i < C.len:
    entries.add(entryJson(C[i]))
    i = i + 1
  result = $(%*{
    "ok": true,
    "entries": entries,
    "resultsPath": resultsDirectory().replace('\\', '/'),
    "defaultResultsPath": defaultResultsDirectory().replace('\\', '/'),
    "folderPicker": true,
    "nativeFolderPicker": pickerAvailable(),
    "smokeMode": smokeMode
  })

proc cachePath(e: TestCatalogEntry, source: string): string {.role: {helper}.} =
  ## e/source: test identity used for an isolated Nim cache path.
  result = joinPath(repoRoot(), "build", "nimcache_test_ui_" & e.id & "_" &
    splitFile(source).name)

proc binaryPath(e: TestCatalogEntry, source: string): string {.role: {helper}.} =
  ## e/source: test identity used for an ignored native executable path.
  var name: string = e.id & "_" & splitFile(source).name
  when defined(windows):
    name.add(".exe")
  result = joinPath(repoRoot(), "build", "test_ui_bins", name)

proc commonNimArgs(e: TestCatalogEntry, source: string): seq[string]
    {.role: {truthBuilder}.} =
  ## e/source: fixed catalog definition and Nim entrypoint.
  createDir(joinPath(repoRoot(), "build", "test_ui_bins"))
  result = @["c", "-r", "--nimcache:" & cachePath(e, source),
    "--out:" & binaryPath(e, source)]
  if e.commandKind != tckTests or e.id.startsWith("bench-"):
    result.add("-d:release")
  if e.id.startsWith("bench-otter") or e.id.startsWith("bench-sigma") or
      e.commandKind == tckAsymmetricBench:
    result.add("--path:" & joinPath(repoRoot(), "submodules", "otter_repo_evaluation", "src"))
  if e.id.startsWith("bench-otter"):
    result.add("-d:otterTiming")
  result.add(source)

proc commandArgs(e: TestCatalogEntry, source: string): seq[string]
    {.role: {truthBuilder}.} =
  ## e/source: catalog definition used to construct only known commands.
  result = commonNimArgs(e, source)
  case e.commandKind
  of tckCustomBench:
    result.add(e.argument)
  of tckKdfBench:
    result.add(@["64", "3", "2", "64", "1", "1"])
  of tckAsymmetricBench:
    result.add(@["--phase:summary", "--scale:0.02"])
  of tckTests:
    discard

proc resultStem(e: TestCatalogEntry): string {.role: {helper}.} =
  ## e: catalog entry receiving a unique result filename stem.
  GResultCounter = GResultCounter + 1
  result = now().format("yyyyMMdd-HHmmss") & "-" & align($GResultCounter, 3, '0') &
    "-" & e.id

proc recordInteropResult*(passed: bool, durationMs: int64, output: string): string
    {.role: {dataWriter}.} =
  ## passed/durationMs/output: browser-WASM matrix result to persist.
  var
    stamp: string = now().format("yyyyMMdd-HHmmss") & "-browser-wasm-interop"
    logPath: string = joinPath(resultsDirectory(), stamp & ".log")
    jsonPath: string = joinPath(resultsDirectory(), stamp & ".json")
    metadata: JsonNode
  writeFile(logPath, output & "\n")
  metadata = %*{
    "id": "browser-wasm-interop",
    "title": "Browser-WASM interoperability matrix",
    "family": "interop",
    "tags": ["functional", "interop"],
    "passed": passed,
    "exitCode": (if passed: 0 else: 1),
    "durationMs": durationMs,
    "startedAt": $now(),
    "logPath": logPath.replace('\\', '/'),
    "resultPath": jsonPath.replace('\\', '/')
  }
  writeFile(jsonPath, pretty(metadata) & "\n")
  metadata["ok"] = %true
  result = $metadata

proc runCatalogEntry*(id: string): string {.role: {orchestrator}.} =
  ## id: fixed allowlisted test or benchmark identifier.
  var
    e: TestCatalogEntry = catalogEntry(id)
    startTime: DateTime = now()
    stem: string = resultStem(e)
    logPath: string = joinPath(resultsDirectory(), stem & ".log")
    jsonPath: string = joinPath(resultsDirectory(), stem & ".json")
    log: string = ""
    outputTail: string = ""
    args: seq[string] = @[]
    probe: tuple[output: string, exitCode: int]
    exitCode: int = 0
    elapsedMs: int64 = 0
    i: int = 0
    oldValues: seq[string] = @[]
  while i < e.environment.len:
    oldValues.add(getEnv(e.environment[i].key))
    putEnv(e.environment[i].key, e.environment[i].value)
    i = i + 1
  try:
    i = 0
    while i < e.sources.len:
      args = commandArgs(e, e.sources[i])
      log.add("$ nim " & quoteArgs(args) & "\n\n")
      probe = execCmdEx("nim " & quoteArgs(args), options = {poUsePath, poStdErrToStdOut},
        workingDir = repoRoot())
      log.add(probe.output)
      log.add("\n[exit " & $probe.exitCode & "]\n")
      exitCode = probe.exitCode
      if exitCode != 0:
        break
      i = i + 1
  finally:
    i = 0
    while i < e.environment.len:
      putEnv(e.environment[i].key, oldValues[i])
      i = i + 1
  elapsedMs = (now() - startTime).inMilliseconds
  writeFile(logPath, log)
  if log.len > 6000:
    outputTail = log[log.len - 6000 .. ^1]
  else:
    outputTail = log
  var metadata: JsonNode = %*{
    "id": e.id,
    "title": e.title,
    "family": e.family,
    "tags": e.tags,
    "sources": e.sources,
    "passed": exitCode == 0,
    "exitCode": exitCode,
    "durationMs": elapsedMs,
    "startedAt": $startTime,
    "logPath": logPath.replace('\\', '/'),
    "resultPath": jsonPath.replace('\\', '/')
  }
  writeFile(jsonPath, pretty(metadata) & "\n")
  metadata["ok"] = %true
  metadata["outputTail"] = %outputTail
  result = $metadata
