## ----------------------------------------------------------------
## Desktop Test Runner <- Nim replacement for PowerShell test runner
## ----------------------------------------------------------------

import std/[os, osproc, strutils, times]

type
  RunnerConfig = object
    full: bool
    maxParallel: int
    only: string
    childNimFlags: string
    runGroupName: string

  TestGroup = object
    name: string
    aliases: seq[string]
    tests: seq[string]
    env: seq[tuple[key: string, value: string]]

  TestResult = object
    name: string
    passed: bool
    logPath: string
    seconds: int

  RunningGroup = object
    name: string
    logPath: string
    process: Process
    start: DateTime

proc repoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc quoteArgs(args: openArray[string]): string =
  var
    i: int = 0
  while i < args.len:
    if i > 0:
      result.add(" ")
    result.add(quoteShell(args[i]))
    i = i + 1

proc parseConfig(): RunnerConfig =
  var
    i: int = 1
    arg: string = ""
  while i <= paramCount():
    arg = paramStr(i)
    if arg == "--":
      discard
    elif arg == "--full":
      result.full = true
    elif arg.startsWith("--maxParallel:"):
      result.maxParallel = parseInt(arg.split(":", 1)[1])
    elif arg.startsWith("--maxParallel="):
      result.maxParallel = parseInt(arg.split("=", 1)[1])
    elif arg == "--maxParallel" and i < paramCount():
      i = i + 1
      result.maxParallel = parseInt(paramStr(i))
    elif arg.startsWith("--only:"):
      result.only = arg.split(":", 1)[1]
    elif arg.startsWith("--only="):
      result.only = arg.split("=", 1)[1]
    elif arg == "--only" and i < paramCount():
      i = i + 1
      result.only = paramStr(i)
    elif arg.startsWith("--childNimFlags:"):
      result.childNimFlags = arg.split(":", 1)[1]
    elif arg.startsWith("--childNimFlags="):
      result.childNimFlags = arg.split("=", 1)[1]
    elif arg == "--childNimFlags" and i < paramCount():
      i = i + 1
      result.childNimFlags = paramStr(i)
    elif arg.startsWith("--runGroup:"):
      result.runGroupName = arg.split(":", 1)[1]
    elif arg.startsWith("--runGroup="):
      result.runGroupName = arg.split("=", 1)[1]
    elif arg == "--runGroup" and i < paramCount():
      i = i + 1
      result.runGroupName = paramStr(i)
    else:
      raise newException(ValueError, "unknown argument: " & arg)
    i = i + 1

proc addGroup(G: var seq[TestGroup], name: string, tests: openArray[string],
    aliases: openArray[string] = [], env: openArray[(string, string)] = []) =
  var
    g: TestGroup
    i: int = 0
  g.name = name
  i = 0
  while i < tests.len:
    g.tests.add(tests[i])
    i = i + 1
  i = 0
  while i < aliases.len:
    g.aliases.add(aliases[i])
    i = i + 1
  i = 0
  while i < env.len:
    g.env.add((key: env[i][0], value: env[i][1]))
    i = i + 1
  G.add(g)

proc buildGroups(): seq[TestGroup] =
  addGroup(result, "core", [
    "test_common.nim", "test_config.nim", "test_registry.nim", "test_libsodium.nim",
    "test_nimcrypto.nim", "test_quick_api.nim", "test_primitives_api.nim",
    "test_hybrid_kex_triple.nim", "test_hybrid_kex_duo.nim",
    "test_signatures.nim", "test_liboqs.nim", "test_openssl.nim"])
  addGroup(result, "custom_crypto", ["test_custom_crypto.nim"])
  addGroup(result, "sha3", ["test_sha3_custom.nim", "test_sha3_simd.nim"])
  addGroup(result, "poly1305", ["test_poly1305_custom.nim", "test_poly1305_simd.nim"])
  addGroup(result, "aes", ["test_aes_ctr.nim", "test_aes_gcm_compare.nim"])
  addGroup(result, "gimli", ["test_gimli_sse.nim", "test_gimli_vectors.nim"])
  addGroup(result, "blake3", ["test_blake3_simd.nim", "test_blake3_stream.nim"])
  addGroup(result, "xchacha20", ["test_xchacha20_simd.nim"])
  addGroup(result, "random", ["test_random_entropy.nim"])
  addGroup(result, "hmac", ["test_custom_hmac.nim"])
  addGroup(result, "otp", ["test_otp.nim"])
  addGroup(result, "x25519", ["test_x25519_custom.nim", "test_x25519_simd.nim"])
  addGroup(result, "kyber", ["test_kyber_tyr.nim", "test_kyber_kat.nim"])
  addGroup(result, "frodo", ["test_frodo_tyr.nim", "test_frodo_kat.nim"])
  addGroup(result, "bike", ["test_bike_tyr.nim", "test_bike_kat.nim"])
  addGroup(result, "ntru", ["test_ntru_tyr.nim"])
  addGroup(result, "saber", ["test_saber_tyr.nim"])
  addGroup(result, "dilithium", ["test_dilithium_tyr.nim", "test_dilithium_kat.nim", "test_ct_verify.nim"])
  addGroup(result, "falcon512", ["test_falcon_tyr.nim"], ["falcon"],
    [("TYR_FALCON_TEST_VARIANT", "512")])
  addGroup(result, "falcon1024", ["test_falcon_tyr.nim"], ["falcon"],
    [("TYR_FALCON_TEST_VARIANT", "1024")])
  addGroup(result, "sphincs", ["test_sphincs_tyr.nim", "test_sphincs_kat.nim", "test_ct_verify.nim"])
  addGroup(result, "mceliece", ["test_mceliece_tyr.nim", "test_ct_verify.nim"])

proc wantedSet(value: string): seq[string] =
  var
    parts: seq[string] = @[]
    i: int = 0
    item: string = ""
  if value.strip().len == 0:
    return @[]
  parts = value.split(",")
  i = 0
  while i < parts.len:
    item = parts[i].strip().toLowerAscii()
    if item.len > 0:
      result.add(item)
    i = i + 1

proc containsName(A: openArray[string], name: string): bool =
  var i: int = 0
  while i < A.len:
    if A[i] == name:
      return true
    i = i + 1

proc groupSelected(g: TestGroup, wanted: openArray[string]): bool =
  var
    i: int = 0
    name: string = g.name.toLowerAscii()
  if wanted.len == 0:
    return true
  if containsName(wanted, name):
    return true
  i = 0
  while i < g.aliases.len:
    if containsName(wanted, g.aliases[i].toLowerAscii()):
      return true
    i = i + 1

proc selectedGroups(G: seq[TestGroup], only: string): seq[TestGroup] =
  var
    wanted: seq[string] = wantedSet(only)
    i: int = 0
  i = 0
  while i < G.len:
    if groupSelected(G[i], wanted):
      result.add(G[i])
    i = i + 1
  if result.len == 0:
    raise newException(ValueError, "no test groups matched --only " & only)

proc findGroup(G: seq[TestGroup], name: string): TestGroup =
  var
    i: int = 0
    wanted: string = name.toLowerAscii()
  while i < G.len:
    if G[i].name.toLowerAscii() == wanted:
      return G[i]
    i = i + 1
  raise newException(ValueError, "no exact test group named " & name)

proc childFlags(value: string): seq[string] =
  if value.strip().len == 0:
    return @[]
  result = value.splitWhitespace()

proc tailFile(path: string, lineCount: int): seq[string] =
  var
    lines: seq[string] = @[]
    start: int = 0
    i: int = 0
  if not fileExists(path):
    return @[]
  lines = readFile(path).splitLines()
  start = max(0, lines.len - lineCount)
  i = start
  while i < lines.len:
    result.add(lines[i])
    i = i + 1

proc runGroup(g: TestGroup, root, logRoot: string, defines,
    extraFlags: openArray[string], full: bool): TestResult =
  var
    start: DateTime = now()
    logPath: string = joinPath(logRoot, g.name & ".log")
    log: string = ""
    i: int = 0
    j: int = 0
    args: seq[string] = @[]
    testBase: string = ""
    cache: string = ""
    res: tuple[output: string, exitCode: int]
  result.name = g.name
  result.logPath = logPath
  result.passed = true
  i = 0
  while i < g.env.len:
    putEnv(g.env[i].key, g.env[i].value)
    i = i + 1
  log.add("[" & g.name & "] start " & $start & " full=" & $full & "\n")
  i = 0
  while i < g.tests.len:
    testBase = splitFile(g.tests[i]).name
    cache = joinPath(root, "build", "nimcache_test_parallel_" & g.name & "_" & testBase)
    args = @["c", "--nimcache:" & cache]
    j = 0
    while j < extraFlags.len:
      args.add(extraFlags[j])
      j = j + 1
    j = 0
    while j < defines.len:
      args.add(defines[j])
      j = j + 1
    args.add("-r")
    args.add(joinPath("tests", g.tests[i]))
    log.add("\n[" & g.name & "] nim " & args.join(" ") & "\n")
    res = execCmdEx("nim " & quoteArgs(args))
    log.add(res.output)
    if res.exitCode != 0:
      log.add("[" & g.name & "] failed " & g.tests[i] & " exit=" & $res.exitCode & "\n")
      result.passed = false
      break
    i = i + 1
  result.seconds = int((now() - start).inSeconds)
  if result.passed:
    log.add("[" & g.name & "] pass elapsed=" & $result.seconds & "s\n")
  writeFile(logPath, log)

proc childArgs(config: RunnerConfig, groupName: string): seq[string] =
  result.add("--runGroup:" & groupName)
  if config.full:
    result.add("--full")
  if config.childNimFlags.strip().len > 0:
    result.add("--childNimFlags:" & config.childNimFlags)

proc startGroupProcess(g: TestGroup, root, logRoot: string,
    config: RunnerConfig): RunningGroup =
  result.name = g.name
  result.logPath = joinPath(logRoot, g.name & ".log")
  result.start = now()
  if fileExists(result.logPath):
    removeFile(result.logPath)
  result.process = startProcess(getAppFilename(), workingDir = root,
    args = childArgs(config, g.name), options = {poParentStreams})

proc finishCompleted(running: var seq[RunningGroup],
    results: var seq[TestResult]): bool =
  var
    i: int = 0
    code: int = 0
    item: RunningGroup
    res: TestResult
  while i < running.len:
    if running[i].process.running():
      i = i + 1
    else:
      item = running[i]
      code = waitForExit(item.process)
      close(item.process)
      res.name = item.name
      res.logPath = item.logPath
      res.seconds = int((now() - item.start).inSeconds)
      res.passed = code == 0
      results.add(res)
      if res.passed:
        echo "[" & res.name & "] pass in " & $res.seconds & "s"
      else:
        echo "[" & res.name & "] FAILED in " & $res.seconds & "s; log=" & res.logPath
      running.delete(i)
      result = true

when isMainModule:
  var
    config: RunnerConfig = parseConfig()
    root: string = repoRoot()
    logRoot: string = joinPath(root, "build", "parallel_tests")
    allGroups: seq[TestGroup] = buildGroups()
    groups: seq[TestGroup] = selectedGroups(allGroups, config.only)
    defines: seq[string] = @[]
    flags: seq[string] = childFlags(config.childNimFlags)
    results: seq[TestResult] = @[]
    i: int = 0
    failed: bool = false
    running: seq[RunningGroup] = @[]
    totalSeconds: int = 0
    lines: seq[string] = @[]
  setCurrentDir(root)
  createDir(logRoot)
  putEnv("NIMBLE_DIR", joinPath(root, ".nimble_cache"))
  putEnv("LIBOQS_AUTO_BUILD", "yes")
  putEnv("LIBSODIUM_AUTO_BUILD", "yes")
  if config.full:
    defines.add("-d:hasLiboqs")
    defines.add("-d:hasLibsodium")
    defines.add("-d:hasOpenSSL3")

  if config.runGroupName.strip().len > 0:
    results.add(runGroup(findGroup(allGroups, config.runGroupName), root,
      logRoot, defines, flags, config.full))
    if results[0].passed:
      quit 0
    quit 1

  if config.maxParallel <= 0 or config.maxParallel > groups.len:
    config.maxParallel = groups.len
  echo "Running " & $groups.len & " desktop test groups with MaxParallel=" &
    $config.maxParallel
  echo "Logs: " & logRoot

  while i < groups.len or running.len > 0:
    while i < groups.len and running.len < config.maxParallel:
      echo "[" & groups[i].name & "] queued"
      running.add(startGroupProcess(groups[i], root, logRoot, config))
      i = i + 1
    if not finishCompleted(running, results):
      sleep(250)

  i = 0
  while i < results.len:
    if not results[i].passed:
      failed = true
    if results[i].seconds > totalSeconds:
      totalSeconds = results[i].seconds
    i = i + 1
  if failed:
    echo ""
    echo "Failed test groups:"
    i = 0
    while i < results.len:
      if not results[i].passed:
        echo "- " & results[i].name & ": " & results[i].logPath
        lines = tailFile(results[i].logPath, 120)
        if lines.len > 0:
          echo "  tail:"
          for line in lines:
            echo "  " & line
      i = i + 1
    quit 1
  echo ""
  echo "All desktop test groups passed. Longest group: " & $totalSeconds & "s"
