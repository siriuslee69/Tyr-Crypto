## =====================================================================
## PQ Profile Bench <- build matched liboqs profiles and run Sigma benches
## =====================================================================

import std/[os, osproc, parseopt, strutils]

type
  BenchMode = enum
    bmScalar,
    bmAvx2

  BenchSuite = enum
    bsPq,
    bsKyber,
    bsFrodo,
    bsDilithium

  EnvBackup = object
    key: string
    value: string
    existed: bool

  CliConfig = object
    rebuild: bool
    runScalar: bool
    runAvx2: bool
    dryRun: bool
    suites: seq[BenchSuite]
    logsDir: string

  StepResult = object
    label: string
    logPath: string
    exitCode: int

const
  minimalBuildArg = "KEM_kyber_768;KEM_kyber_1024;KEM_frodokem_976_aes;" &
    "KEM_bike_l1;KEM_classic_mceliece_6688128f;SIG_ml_dsa_44;" &
    "SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_sphincs_shake_128f_simple"
  envKeys = [
    "LIBOQS_PROFILE_NAME",
    "LIBOQS_BUILD_ROOT",
    "LIBOQS_LIB_DIRS",
    "LIBOQS_OVERWRITE_BUILD",
    "LIBOQS_USE_OPENSSL",
    "LIBOQS_USE_AES_OPENSSL",
    "LIBOQS_USE_SHA2_OPENSSL",
    "LIBOQS_USE_SHA3_OPENSSL",
    "LIBOQS_DIST_BUILD",
    "LIBOQS_OPT_TARGET",
    "LIBOQS_MINIMAL_BUILD",
    "LIBOQS_EXTRA_CMAKE_ARGS",
    "NIMBLE_DIR",
    "PATH"
  ]

proc toolDir(): string =
  ## Returns the absolute tool directory.
  var
    f: string = currentSourcePath()
  result = splitFile(f).dir

proc repoDir(): string =
  ## Returns the Tyr-Crypto repo root.
  var
    d: string = toolDir()
  result = parentDir(d)

proc workspaceDir(): string =
  ## Returns the shared workspace root one level above the repo.
  var
    d: string = repoDir()
  result = parentDir(d)

proc repoBuildDir(): string =
  ## Returns the repo-local build directory.
  var
    d: string = repoDir()
  result = joinPath(d, "build")

proc workspaceBuildDir(): string =
  ## Returns the workspace-shared build directory.
  var
    d: string = workspaceDir()
  result = joinPath(d, "build")

proc repoNimbleDir(): string =
  ## Returns the repo-local nimble cache.
  var
    d: string = repoDir()
  result = joinPath(d, ".nimble_cache")

proc repoNimcacheDir(a: string): string =
  ## a: nimcache leaf directory.
  ## Returns a repo-local nimcache directory.
  var
    d: string = repoBuildDir()
  result = joinPath(d, a)

proc replaceSlash(a: string): string =
  ## a: filesystem path.
  ## Converts backslashes for Nim/CMake command arguments.
  result = a.replace('\\', '/')

proc modeName(a: BenchMode): string =
  ## a: benchmark mode.
  case a
  of bmScalar:
    result = "scalar"
  of bmAvx2:
    result = "avx2"

proc suiteName(a: BenchSuite): string =
  ## a: benchmark suite.
  case a
  of bsPq:
    result = "pq"
  of bsKyber:
    result = "kyber"
  of bsFrodo:
    result = "frodo"
  of bsDilithium:
    result = "dilithium"

proc suiteTestPath(a: BenchSuite): string =
  ## a: benchmark suite.
  case a
  of bsPq:
    result = "tests/test_sigma_perf_pq.nim"
  of bsKyber:
    result = "tests/test_sigma_perf_kyber_only.nim"
  of bsFrodo:
    result = "tests/test_sigma_perf_frodo_profile.nim"
  of bsDilithium:
    result = "tests/test_sigma_perf_dilithium.nim"

proc suiteUsesFrodo(a: BenchSuite): bool =
  ## a: benchmark suite.
  result = a in [bsPq, bsFrodo]

proc buildRoot(a: BenchMode): string =
  ## a: benchmark mode.
  var
    d: string = workspaceBuildDir()
  result = joinPath(d, "liboqs_min_pq_" & modeName(a))

proc profileBinDir(a: BenchMode): string =
  ## a: benchmark mode.
  var
    root: string = buildRoot(a)
    installBin: string = joinPath(root, "install", "bin")
    rootBin: string = joinPath(root, "bin")
  if dirExists(installBin):
    result = installBin
  else:
    result = rootBin

proc profileHasLib(a: BenchMode): bool =
  ## a: benchmark mode.
  var
    root: string = buildRoot(a)
    candidates: seq[string] = @[]
    i: int = 0
  candidates.add(joinPath(root, "install", "lib", "liboqs.dll.a"))
  candidates.add(joinPath(root, "install", "lib", "liboqs.a"))
  candidates.add(joinPath(root, "install", "bin", "liboqs.dll"))
  candidates.add(joinPath(root, "lib", "liboqs.dll.a"))
  candidates.add(joinPath(root, "lib", "liboqs.a"))
  candidates.add(joinPath(root, "bin", "liboqs.dll"))
  i = 0
  while i < candidates.len:
    if fileExists(candidates[i]):
      return true
    i = i + 1
  result = false

proc scalarExtraCmakeArgs(): string =
  result = "-DOQS_ENABLE_KEM_kyber_768_x86_64=OFF " &
    "-DOQS_ENABLE_KEM_kyber_1024_x86_64=OFF " &
    "-DOQS_ENABLE_KEM_ml_kem_768_x86_64=OFF " &
    "-DOQS_ENABLE_KEM_ml_kem_1024_x86_64=OFF " &
    "-DOQS_USE_AES_INSTRUCTIONS=OFF " &
    "-DOQS_USE_AVX_INSTRUCTIONS=OFF " &
    "-DOQS_USE_AVX2_INSTRUCTIONS=OFF " &
    "-DOQS_USE_AVX512_INSTRUCTIONS=OFF " &
    "-DOQS_USE_BMI1_INSTRUCTIONS=OFF " &
    "-DOQS_USE_BMI2_INSTRUCTIONS=OFF " &
    "-DOQS_USE_PCLMULQDQ_INSTRUCTIONS=OFF " &
    "-DOQS_USE_VPCLMULQDQ_INSTRUCTIONS=OFF " &
    "-DOQS_USE_POPCNT_INSTRUCTIONS=OFF " &
    "-DOQS_USE_SSE_INSTRUCTIONS=OFF " &
    "-DOQS_USE_SSE2_INSTRUCTIONS=OFF " &
    "-DOQS_USE_SSE3_INSTRUCTIONS=OFF"

proc avx2ExtraCmakeArgs(): string =
  result = "-DOQS_USE_AES_INSTRUCTIONS=ON " &
    "-DOQS_USE_AVX_INSTRUCTIONS=ON " &
    "-DOQS_USE_AVX2_INSTRUCTIONS=ON " &
    "-DOQS_USE_AVX512_INSTRUCTIONS=OFF " &
    "-DOQS_USE_BMI1_INSTRUCTIONS=ON " &
    "-DOQS_USE_BMI2_INSTRUCTIONS=ON " &
    "-DOQS_USE_PCLMULQDQ_INSTRUCTIONS=ON " &
    "-DOQS_USE_VPCLMULQDQ_INSTRUCTIONS=OFF " &
    "-DOQS_USE_POPCNT_INSTRUCTIONS=ON " &
    "-DOQS_USE_SSE_INSTRUCTIONS=ON " &
    "-DOQS_USE_SSE2_INSTRUCTIONS=ON " &
    "-DOQS_USE_SSE3_INSTRUCTIONS=ON"

proc profileExtraCmakeArgs(a: BenchMode): string =
  ## a: benchmark mode.
  case a
  of bmScalar:
    result = scalarExtraCmakeArgs()
  of bmAvx2:
    result = avx2ExtraCmakeArgs()

proc profileOptTarget(a: BenchMode): string =
  ## a: benchmark mode.
  case a
  of bmScalar:
    result = "generic"
  of bmAvx2:
    result = "auto"

proc appendSuite(S: var seq[BenchSuite], a: BenchSuite) =
  ## S: suite list to mutate.
  ## a: suite to append when absent.
  var
    i: int = 0
  i = 0
  while i < S.len:
    if S[i] == a:
      return
    i = i + 1
  S.add(a)

proc addSuiteToken(S: var seq[BenchSuite], a: string) =
  ## S: suite list to mutate.
  ## a: cli suite token.
  var
    t: string = a.strip().toLowerAscii()
  if t.len == 0:
    return
  if t == "all":
    appendSuite(S, bsPq)
    appendSuite(S, bsKyber)
    appendSuite(S, bsFrodo)
    appendSuite(S, bsDilithium)
    return
  if t == "pq":
    appendSuite(S, bsPq)
    return
  if t == "kyber":
    appendSuite(S, bsKyber)
    return
  if t == "frodo":
    appendSuite(S, bsFrodo)
    return
  if t == "dilithium":
    appendSuite(S, bsDilithium)
    return
  raise newException(ValueError, "unknown suite: " & a)

proc setDefaultSuites(S: var seq[BenchSuite]) =
  ## S: suite list to mutate with all default suites.
  if S.len > 0:
    return
  appendSuite(S, bsPq)
  appendSuite(S, bsKyber)
  appendSuite(S, bsFrodo)
  appendSuite(S, bsDilithium)

proc printHelp() =
  echo "bench_pq_profiles.nim"
  echo "  Build matched liboqs scalar/avx2 profiles and run Sigma comparisons."
  echo ""
  echo "Options:"
  echo "  --mode=scalar|avx2|all"
  echo "  --suite=pq|kyber|frodo|dilithium|all"
  echo "  --no-rebuild"
  echo "  --dry-run"
  echo "  --logs-dir=<dir>"
  echo "  --help"

proc parseArgs(): CliConfig =
  var
    p: OptParser
    args: seq[string] = @[]
    modeSet: bool = false
    key: string = ""
    val: string = ""
    token: string = ""
    parts: seq[string] = @[]
    i: int = 0
  result.rebuild = true
  result.runScalar = true
  result.runAvx2 = true
  result.dryRun = false
  result.logsDir = repoBuildDir()
  args = commandLineParams()
  if args.len > 0 and args[0] == "--":
    args.delete(0)
  p = initOptParser(args)
  while true:
    next(p)
    case p.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      key = p.key.toLowerAscii()
      val = p.val
      if key == "help" or key == "h":
        printHelp()
        quit(0)
      if key == "dry-run":
        result.dryRun = true
        continue
      if key == "no-rebuild":
        result.rebuild = false
        continue
      if key == "logs-dir":
        if val.len == 0:
          raise newException(ValueError, "--logs-dir requires a value")
        result.logsDir = absolutePath(val)
        continue
      if key == "mode":
        modeSet = true
        result.runScalar = false
        result.runAvx2 = false
        if val.len == 0:
          raise newException(ValueError, "--mode requires a value")
        if val.toLowerAscii() == "all":
          result.runScalar = true
          result.runAvx2 = true
          continue
        if val.toLowerAscii() == "scalar":
          result.runScalar = true
          continue
        if val.toLowerAscii() == "avx2":
          result.runAvx2 = true
          continue
        raise newException(ValueError, "unknown mode: " & val)
      if key == "suite":
        if val.len == 0:
          raise newException(ValueError, "--suite requires a value")
        parts = val.split(',')
        i = 0
        while i < parts.len:
          token = parts[i]
          addSuiteToken(result.suites, token)
          i = i + 1
        continue
      raise newException(ValueError, "unknown option: --" & key)
    of cmdArgument:
      raise newException(ValueError, "unexpected argument: " & p.key)
  if not modeSet:
    result.runScalar = true
    result.runAvx2 = true
  setDefaultSuites(result.suites)

proc backupEnv(A: openArray[string]): seq[EnvBackup] =
  ## A: env keys to snapshot.
  var
    i: int = 0
    key: string = ""
    value: string = ""
  i = 0
  while i < A.len:
    key = A[i]
    value = getEnv(key)
    result.add(EnvBackup(key: key, value: value, existed: existsEnv(key)))
    i = i + 1

proc restoreEnv(B: openArray[EnvBackup]) =
  ## B: env snapshot to restore.
  var
    i: int = 0
  i = 0
  while i < B.len:
    if B[i].existed:
      putEnv(B[i].key, B[i].value)
    else:
      delEnv(B[i].key)
    i = i + 1

proc ensureDir(a: string) =
  ## a: directory path to create when missing.
  if not dirExists(a):
    createDir(a)

proc prependPath(a: string) =
  ## a: directory path to prepend to PATH.
  var
    current: string = getEnv("PATH")
  if current.len == 0:
    putEnv("PATH", a)
    return
  putEnv("PATH", a & PathSep & current)

proc writeLog(a, b, c: string, code: int) =
  ## a: log file path.
  ## b: human step label.
  ## c: full command output.
  ## code: exit code to record.
  var
    text: string = ""
  text = "# " & b & "\n"
  text = text & "exit_code=" & $code & "\n\n"
  text = text & c
  writeFile(a, text)

proc runLogged(a, b: string, dryRun: bool): int =
  ## a: shell command to execute.
  ## b: log file path.
  ## dryRun: true to print only.
  var
    res: tuple[output: string, exitCode: int]
    body: string = ""
  echo ""
  echo ">> ", a
  if dryRun:
    writeLog(b, a, "dry_run=1\n", 0)
    return 0
  res = execCmdEx(a)
  body = res.output
  if body.len > 0:
    echo body
  writeLog(b, a, body, res.exitCode)
  result = res.exitCode

proc sigmaFlags(): string =
  result = "--path:src --path:submodules/sigma_bench_and_eval/src " &
    "--path:submodules/sigma_bench_and_eval/submodules/fylgia/src"

proc modeFlags(a: BenchMode): string =
  ## a: benchmark mode.
  case a
  of bmScalar:
    result = "-d:danger -d:hasLibOqs -u:sse2 -u:ssse3 -u:avx2 -u:aesni"
  of bmAvx2:
    result = "-d:danger -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni"

proc suitePassCFlags(a: BenchMode, b: BenchSuite): string =
  ## a: benchmark mode.
  ## b: benchmark suite.
  if a != bmAvx2:
    return ""
  if not suiteUsesFrodo(b):
    return ""
  result = "--passC:-maes --passC:-msse2"

proc benchCommand(a: BenchMode, b: BenchSuite): string =
  ## a: benchmark mode.
  ## b: benchmark suite.
  var
    nimcacheName: string = ""
    passC: string = ""
  nimcacheName = "nimcache_bench_" & suiteName(b) & "_" & modeName(a)
  passC = suitePassCFlags(a, b)
  result = "nim c --threads:on --nimcache:" &
    quoteShell(replaceSlash(repoNimcacheDir(nimcacheName))) & " " &
    sigmaFlags() & " " &
    modeFlags(a)
  if passC.len > 0:
    result = result & " " & passC
  result = result & " -r " & suiteTestPath(b)

proc buildCommand(a: BenchMode): string =
  ## a: benchmark mode.
  var
    nimcacheName: string = ""
  nimcacheName = "nimcache_build_liboqs_" & modeName(a)
  result = "nim r --nimcache:" &
    quoteShell(replaceSlash(repoNimcacheDir(nimcacheName))) & " tools/build_liboqs.nim"

proc setBuildEnv(a: BenchMode, rebuild: bool) =
  ## a: benchmark mode.
  ## rebuild: true to force overwrite.
  putEnv("LIBOQS_PROFILE_NAME", "min_pq_" & modeName(a))
  putEnv("LIBOQS_BUILD_ROOT", buildRoot(a))
  putEnv("LIBOQS_USE_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_AES_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA2_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA3_OPENSSL", "OFF")
  putEnv("LIBOQS_DIST_BUILD", "OFF")
  putEnv("LIBOQS_OPT_TARGET", profileOptTarget(a))
  putEnv("LIBOQS_MINIMAL_BUILD", minimalBuildArg)
  putEnv("LIBOQS_EXTRA_CMAKE_ARGS", profileExtraCmakeArgs(a))
  putEnv("NIMBLE_DIR", replaceSlash(repoNimbleDir()))
  if rebuild:
    putEnv("LIBOQS_OVERWRITE_BUILD", "1")
  else:
    delEnv("LIBOQS_OVERWRITE_BUILD")

proc setBenchEnv(a: BenchMode) =
  ## a: benchmark mode.
  var
    root: string = ""
    binDir: string = ""
  root = buildRoot(a)
  binDir = profileBinDir(a)
  putEnv("LIBOQS_BUILD_ROOT", root)
  putEnv("LIBOQS_LIB_DIRS", binDir)
  putEnv("NIMBLE_DIR", replaceSlash(repoNimbleDir()))
  prependPath(binDir)

proc buildProfile(a: BenchMode, cfg: CliConfig): StepResult =
  ## a: benchmark mode.
  ## cfg: tool configuration.
  var
    backups: seq[EnvBackup] = @[]
    reuseText: string = ""
  result.label = "build_" & modeName(a)
  result.logPath = joinPath(cfg.logsDir, "build_liboqs_min_pq_" & modeName(a) & ".log")
  if (not cfg.rebuild) and profileHasLib(a):
    reuseText = "reused_existing_profile=1\nbuild_root=" & buildRoot(a) & "\n"
    writeLog(result.logPath, result.label, reuseText, 0)
    result.exitCode = 0
    return
  backups = backupEnv(envKeys)
  try:
    setBuildEnv(a, cfg.rebuild)
    result.exitCode = runLogged(buildCommand(a), result.logPath, cfg.dryRun)
  finally:
    restoreEnv(backups)

proc runBench(a: BenchMode, b: BenchSuite, cfg: CliConfig): StepResult =
  ## a: benchmark mode.
  ## b: benchmark suite.
  ## cfg: tool configuration.
  var
    backups: seq[EnvBackup] = @[]
  result.label = suiteName(b) & "_" & modeName(a)
  result.logPath = joinPath(cfg.logsDir,
    "bench_sigma_" & suiteName(b) & "_" & modeName(a) & ".log")
  backups = backupEnv(envKeys)
  try:
    setBenchEnv(a)
    result.exitCode = runLogged(benchCommand(a, b), result.logPath, cfg.dryRun)
  finally:
    restoreEnv(backups)

proc appendResult(S: var seq[StepResult], a: StepResult) =
  ## S: result list to mutate.
  ## a: step result.
  S.add(a)

proc writeSummary(A: openArray[StepResult], cfg: CliConfig) =
  ## A: finished steps.
  ## cfg: tool configuration.
  var
    path: string = joinPath(cfg.logsDir, "bench_pq_profiles_summary.txt")
    lines: seq[string] = @[]
    i: int = 0
  lines.add("repo_dir=" & repoDir())
  lines.add("workspace_dir=" & workspaceDir())
  lines.add("dry_run=" & $(cfg.dryRun))
  lines.add("rebuild=" & $(cfg.rebuild))
  lines.add("")
  i = 0
  while i < A.len:
    lines.add(A[i].label & ": exit=" & $A[i].exitCode & " log=" & A[i].logPath)
    i = i + 1
  writeFile(path, lines.join("\n") & "\n")
  echo ""
  echo "Summary: ", path

proc runMode(a: BenchMode, cfg: CliConfig, S: var seq[StepResult]) =
  ## a: benchmark mode.
  ## cfg: tool configuration.
  ## S: result accumulator.
  var
    step: StepResult
    i: int = 0
  step = buildProfile(a, cfg)
  appendResult(S, step)
  if step.exitCode != 0:
    raise newException(OSError, "build failed for mode " & modeName(a))
  i = 0
  while i < cfg.suites.len:
    step = runBench(a, cfg.suites[i], cfg)
    appendResult(S, step)
    if step.exitCode != 0:
      raise newException(OSError, "benchmark failed for " & suiteName(cfg.suites[i]) &
        " in mode " & modeName(a))
    i = i + 1

proc main() =
  var
    cfg: CliConfig
    results: seq[StepResult] = @[]
  cfg = parseArgs()
  ensureDir(cfg.logsDir)
  setCurrentDir(repoDir())
  if cfg.runScalar:
    runMode(bmScalar, cfg, results)
  if cfg.runAvx2:
    runMode(bmAvx2, cfg, results)
  writeSummary(results, cfg)

when isMainModule:
  main()
