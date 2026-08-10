## ---------------------------------------------------------------------
## Test Jobs <- supervisor IPC and isolated native -> WASM worker runtime
## ---------------------------------------------------------------------

import std/[json, monotimes, os, osproc, sets, strutils, tables, times]

import ../../.iron/meta/metaPragmas
import ./test_catalog

const
  runtimeEnv = "TYR_TEST_UI_RUNTIME"
  requestWaitCount = 100
  requestWaitMs = 50
  workerPollMs = 100

type
  ManagedJob {.role: {memory}.} = object
    id: string
    process: Process

proc repoRoot(): string {.role: {helper}.} =
  ## Returns the Tyr-Crypto repository root.
  result = parentDir(parentDir(parentDir(currentSourcePath())))

proc runtimeDirectory*(): string {.role: {helper}.} =
  ## Returns the active supervisor/spawner IPC directory.
  result = getEnv(runtimeEnv).strip()
  if result.len == 0:
    raise newException(IOError, "test UI runtime directory is not configured")

proc requestsDirectory(dir: string): string {.role: {helper}.} =
  ## dir: process runtime root.
  result = joinPath(dir, "requests")

proc responsesDirectory(dir: string): string {.role: {helper}.} =
  ## dir: process runtime root.
  result = joinPath(dir, "responses")

proc jobsDirectory(dir: string): string {.role: {helper}.} =
  ## dir: process runtime root.
  result = joinPath(dir, "jobs")

proc ensureRuntimeDirectories*(dir: string) {.role: {helper}.} =
  ## dir: process runtime root to initialize.
  createDir(dir)
  createDir(requestsDirectory(dir))
  createDir(responsesDirectory(dir))
  createDir(jobsDirectory(dir))

proc atomicWrite(path, content: string) {.role: {dataWriter}.} =
  ## path/content: state file and complete replacement payload.
  var temporary: string = path & ".tmp-" & $getCurrentProcessId()
  writeFile(temporary, content)
  moveFile(temporary, path)

proc requestId(): string {.role: {helper}.} =
  ## Builds one process-unique request identifier.
  result = $getCurrentProcessId() & "-" & $epochTime().int64 & "-" &
    $getTime().nanosecond

proc spawnerRequest*(request: JsonNode): JsonNode {.role: {dataFetcher}.} =
  ## request: short command sent to the dedicated test-spawner process.
  var
    dir: string = runtimeDirectory()
    id: string = requestId()
    requestPath: string = joinPath(requestsDirectory(dir), id & ".json")
    responsePath: string = joinPath(responsesDirectory(dir), id & ".json")
    i: int = 0
  atomicWrite(requestPath, $request)
  while i < requestWaitCount and not fileExists(responsePath):
    sleep(requestWaitMs)
    i = i + 1
  if not fileExists(responsePath):
    raise newException(IOError, "test spawner did not answer")
  result = parseJson(readFile(responsePath))
  removeFile(responsePath)

proc jobStatePath(dir, id: string): string {.role: {helper}.} =
  ## dir/id: runtime root and catalog identifier.
  result = joinPath(jobsDirectory(dir), id & ".json")

proc cancelPath(dir, id: string): string {.role: {helper}.} =
  ## dir/id: runtime root and catalog identifier.
  result = joinPath(jobsDirectory(dir), id & ".cancel")

proc phaseState(name, status: string, passed: bool = false, exitCode: int = 0,
    durationMs: int64 = 0, logPath: string = ""): JsonNode {.role: {truthBuilder}.} =
  ## name/status/passed/exitCode/durationMs/logPath: one phase truth state.
  result = %*{
    "name": name,
    "status": status,
    "passed": passed,
    "exitCode": exitCode,
    "durationMs": durationMs,
    "logPath": logPath.replace('\\', '/')
  }

proc initialJobState(e: TestCatalogEntry, jobId: string): JsonNode
    {.role: {truthBuilder}.} =
  ## e/jobId: catalog definition and unique worker run identifier.
  result = %*{
    "ok": true,
    "id": e.id,
    "jobId": jobId,
    "title": e.title,
    "status": "queued",
    "stopped": false,
    "native": phaseState("native", "queued"),
    "wasm": phaseState("wasm", "queued")
  }

proc updatePhase(S: var JsonNode, phase, status: string, passed: bool = false,
    exitCode: int = 0, durationMs: int64 = 0, logPath: string = "")
    {.role: {truthBuilder}.} =
  ## S/phase/status/passed/exitCode/durationMs/logPath: state update fields.
  S[phase] = phaseState(phase, status, passed, exitCode, durationMs, logPath)
  S["status"] = %status

proc quoteArgs(A: openArray[string]): string {.role: {helper}.} =
  ## A: command arguments to quote for display and shell execution.
  var i: int = 0
  while i < A.len:
    if i > 0:
      result.add(" ")
    result.add(quoteShell(A[i]))
    i = i + 1

proc sourceStem(source: string): string {.role: {helper}.} =
  ## source: Nim test or benchmark entrypoint.
  result = splitFile(source).name

proc nativeBinaryPath(e: TestCatalogEntry, source: string): string
    {.role: {helper}.} =
  ## e/source: catalog entry and source file.
  var filename: string = e.id & "-" & sourceStem(source) & "-native"
  when defined(windows):
    filename.add(".exe")
  result = joinPath(repoRoot(), "build", "test_ui_bins", filename)

proc wasmModulePath(e: TestCatalogEntry, source: string): string
    {.role: {helper}.} =
  ## e/source: catalog entry and source file.
  result = joinPath(repoRoot(), "build", "test_ui_bins",
    e.id & "-" & sourceStem(source) & "-wasm.js")

proc runtimeArguments(e: TestCatalogEntry): seq[string] {.role: {truthBuilder}.} =
  ## e: catalog entry whose fixed runtime arguments are returned.
  case e.commandKind
  of tckCustomBench:
    result.add(e.argument)
  of tckKdfBench:
    result.add(@["64", "3", "2", "64", "1", "1"])
  of tckAsymmetricBench:
    result.add(@["--phase:summary", "--scale:0.02"])
  of tckTests:
    discard

proc commonCompileFlags(e: TestCatalogEntry): seq[string]
    {.role: {truthBuilder}.} =
  ## e: catalog entry whose fixed compiler flags are returned.
  if e.commandKind != tckTests or e.id.startsWith("bench-"):
    result.add("-d:release")
  if e.id.startsWith("bench-otter") or e.id.startsWith("bench-sigma") or
      e.commandKind == tckAsymmetricBench:
    result.add("--path:" & joinPath(repoRoot(), "submodules",
      "otter_repo_evaluation", "src"))
  if e.id.startsWith("bench-otter"):
    result.add("-d:otterTiming")

proc nativeCompileArgs(e: TestCatalogEntry, source: string): seq[string]
    {.role: {truthBuilder}.} =
  ## e/source: catalog definition and native Nim entrypoint.
  result = @["c", "--nimcache:" & joinPath(repoRoot(), "build",
    "nimcache_test_ui_native_" & e.id & "_" & sourceStem(source)),
    "--out:" & nativeBinaryPath(e, source)]
  result.add(commonCompileFlags(e))
  result.add(source)

proc wasmCompileArgs(e: TestCatalogEntry, source: string): seq[string]
    {.role: {truthBuilder}.} =
  ## e/source: catalog definition and executable Node-WASM entrypoint.
  result = @["c", "--cpu:wasm32", "--cc:clang", "--clang.exe:emcc",
    "--clang.linkerexe:emcc", (if e.wasmThreads: "--threads:on" else:
      "--threads:off"), "-d:tyrWasm",
    "-u:hasLibsodium", "-u:hasLibOqs", "-u:hasOpenSSL3",
    "--nimcache:" & joinPath(repoRoot(), "build",
      "nimcache_test_ui_wasm_" & e.id & "_" & sourceStem(source)),
    "--out:" & wasmModulePath(e, source), "--passL:-sWASM=1",
    "--passL:-sENVIRONMENT=node", "--passL:-sNODERAWFS=1"]
  if e.wasmThreads:
    result.add("--passL:-pthread")
    result.add("--passL:-sPTHREAD_POOL_SIZE=8")
  result.add(commonCompileFlags(e))
  result.add(source)

proc shellRedirectCommand(command: string, args: openArray[string], logPath: string,
    append: bool): string {.role: {helper}.} =
  ## command/args/logPath/append: command and output redirection contract.
  var redirect: string = if append: " >> " else: " > "
  result = quoteShell(command) & " " & quoteArgs(args) & redirect &
    quoteShell(logPath) & " 2>&1"

proc terminateProcessTree(p: Process) {.role: {actor}.} =
  ## p: active compiler or test process whose child tree should stop.
  if p == nil:
    return
  when defined(windows):
    discard execCmd("taskkill /PID " & $processID(p) & " /T /F")
  else:
    discard execCmd("pkill -TERM -P " & $processID(p))
    terminate(p)

proc runCancellable(command: string, args: openArray[string], workingDir,
    logPath, cancelFile: string, append: bool): int {.role: {actor}.} =
  ## command/args/workingDir/logPath/cancelFile/append: cancellable child process.
  var
    shellCommand: string = shellRedirectCommand(command, args, logPath, append)
    p: Process = startProcess(shellCommand, workingDir = workingDir,
      options = {poEvalCommand, poUsePath})
  while p.running():
    if fileExists(cancelFile):
      terminateProcessTree(p)
      discard p.waitForExit(3000)
      p.close()
      return 130
    sleep(workerPollMs)
  result = p.waitForExit()
  p.close()

proc appendCommandHeader(path, phase, command: string, args: openArray[string],
    append: bool) {.role: {dataWriter}.} =
  ## path/phase/command/args/append: phase log header.
  var content: string = "[" & phase & "] $ " & command & " " &
    quoteArgs(args) & "\n\n"
  if append and fileExists(path):
    var prior: string = readFile(path)
    writeFile(path, prior & "\n" & content)
  else:
    writeFile(path, content)

proc phaseLogPath(resultsPath, stem, phase: string): string {.role: {helper}.} =
  ## resultsPath/stem/phase: phase log destination.
  result = joinPath(resultsPath, stem & "-" & phase & ".log")

proc runNativePhase(e: TestCatalogEntry, resultsPath, stem, cancelFile: string,
    S: var JsonNode, statePath: string): bool {.role: {orchestrator}.} =
  ## e/resultsPath/stem/cancelFile/S/statePath: native phase truth and output.
  var
    logPath: string = phaseLogPath(resultsPath, stem, "native")
    startTime: MonoTime = getMonoTime()
    args: seq[string] = @[]
    runArgs: seq[string] = runtimeArguments(e)
    exitCode: int = 0
    i: int = 0
  updatePhase(S, "native", "running", logPath = logPath)
  atomicWrite(statePath, $S)
  while i < e.sources.len:
    args = nativeCompileArgs(e, e.sources[i])
    appendCommandHeader(logPath, "native compile", "nim", args, i > 0)
    exitCode = runCancellable("nim", args, repoRoot(), logPath, cancelFile, true)
    if exitCode != 0:
      break
    appendCommandHeader(logPath, "native run", nativeBinaryPath(e, e.sources[i]),
      runArgs, true)
    exitCode = runCancellable(nativeBinaryPath(e, e.sources[i]), runArgs,
      repoRoot(), logPath, cancelFile, true)
    if exitCode != 0:
      break
    i = i + 1
  updatePhase(S, "native", (if exitCode == 0: "pass" elif exitCode == 130:
    "stopped" else: "fail"), exitCode == 0, exitCode,
    inMilliseconds(getMonoTime() - startTime), logPath)
  atomicWrite(statePath, $S)
  result = exitCode == 0

proc runWasmPhase(e: TestCatalogEntry, resultsPath, stem, cancelFile: string,
    S: var JsonNode, statePath: string): bool {.role: {orchestrator}.} =
  ## e/resultsPath/stem/cancelFile/S/statePath: WASM phase truth and output.
  var
    logPath: string = phaseLogPath(resultsPath, stem, "wasm")
    startTime: MonoTime = getMonoTime()
    args: seq[string] = @[]
    runArgs: seq[string] = @[]
    exitCode: int = 0
    i: int = 0
  updatePhase(S, "wasm", "running", logPath = logPath)
  atomicWrite(statePath, $S)
  while i < e.sources.len:
    args = wasmCompileArgs(e, e.sources[i])
    appendCommandHeader(logPath, "wasm compile", "nim", args, i > 0)
    exitCode = runCancellable("nim", args, repoRoot(), logPath, cancelFile, true)
    if exitCode != 0:
      break
    runArgs = @[wasmModulePath(e, e.sources[i])]
    runArgs.add(runtimeArguments(e))
    appendCommandHeader(logPath, "wasm run", "node", runArgs, true)
    exitCode = runCancellable("node", runArgs, repoRoot(), logPath, cancelFile,
      true)
    if exitCode != 0:
      break
    i = i + 1
  updatePhase(S, "wasm", (if exitCode == 0: "pass" elif exitCode == 130:
    "stopped" else: "fail"), exitCode == 0, exitCode,
    inMilliseconds(getMonoTime() - startTime), logPath)
  atomicWrite(statePath, $S)
  result = exitCode == 0

proc runWorker*(id, jobId, resultsPath, dir: string) {.role: {metaOrchestrator}.} =
  ## id/jobId/resultsPath/dir: paired worker launch contract.
  var
    e: TestCatalogEntry = catalogEntry(id)
    stem: string = now().format("yyyyMMdd-HHmmss") & "-" & jobId & "-" & id
    statePath: string = jobStatePath(dir, id)
    stopFile: string = cancelPath(dir, id)
    S: JsonNode = initialJobState(e, jobId)
    nativePassed: bool = false
    wasmPassed: bool = false
    summaryPath: string = joinPath(resultsPath, stem & ".json")
    i: int = 0
  createDir(resultsPath)
  while i < e.environment.len:
    putEnv(e.environment[i].key, e.environment[i].value)
    i = i + 1
  atomicWrite(statePath, $S)
  nativePassed = runNativePhase(e, resultsPath, stem, stopFile, S, statePath)
  if not fileExists(stopFile):
    wasmPassed = runWasmPhase(e, resultsPath, stem, stopFile, S, statePath)
  elif fileExists(stopFile):
    updatePhase(S, "wasm", "stopped", exitCode = 130)
  S["status"] = %(if fileExists(stopFile): "stopped" elif nativePassed and
    wasmPassed: "pass" else: "fail")
  S["stopped"] = %(fileExists(stopFile))
  S["resultPath"] = %summaryPath.replace('\\', '/')
  atomicWrite(summaryPath, pretty(S) & "\n")
  atomicWrite(statePath, $S)

proc auditWasmCatalog*(): seq[string] {.role: {orchestrator}.} =
  ## Compile-checks every unique catalog source with its declared WASM flags.
  var
    C: seq[TestCatalogEntry] = buildCatalog()
    seen: HashSet[string]
    key: string = ""
    args: seq[string] = @[]
    probe: tuple[output: string, exitCode: int]
    i: int = 0
    j: int = 0
  while i < C.len:
    j = 0
    while j < C[i].sources.len:
      key = C[i].id & "|" & C[i].sources[j]
      if key notin seen:
        seen.incl(key)
        args = wasmCompileArgs(C[i], C[i].sources[j])
        probe = execCmdEx("nim " & quoteArgs(args),
          options = {poUsePath, poStdErrToStdOut}, workingDir = repoRoot())
        if probe.exitCode != 0:
          result.add(C[i].id & " / " & C[i].sources[j] & "\n" & probe.output)
      j = j + 1
    i = i + 1

proc parseArg(args: openArray[string], prefix: string): string {.role: {parser}.} =
  ## args/prefix: command arguments and key prefix to parse.
  var i: int = 0
  while i < args.len:
    if args[i].startsWith(prefix):
      return args[i][prefix.len .. ^1]
    i = i + 1

proc workerArgs(id, jobId, resultsPath, dir: string): seq[string]
    {.role: {truthBuilder}.} =
  ## id/jobId/resultsPath/dir: child worker command arguments.
  result = @["--tyr-mode:worker", "--test-id:" & id, "--job-id:" & jobId,
    "--results-path:" & resultsPath, "--runtime-path:" & dir]

proc startManagedJob(id, resultsPath, dir: string): ManagedJob
    {.role: {actor}.} =
  ## id/resultsPath/dir: allowlisted test and process directories.
  var
    e: TestCatalogEntry = catalogEntry(id)
    jobId: string = $getCurrentProcessId() & "-" & $epochTime().int64 & "-" & id
    statePath: string = jobStatePath(dir, id)
    stopFile: string = cancelPath(dir, id)
    S: JsonNode = initialJobState(e, jobId)
  if fileExists(stopFile):
    removeFile(stopFile)
  atomicWrite(statePath, $S)
  result.id = id
  result.process = startProcess(getAppFilename(), workingDir = repoRoot(),
    args = workerArgs(id, jobId, resultsPath, dir), options = {poParentStreams})

proc collectStates(dir: string): JsonNode {.role: {dataFetcher}.} =
  ## dir: runtime directory containing atomic job states.
  var path: string = ""
  result = newJArray()
  for kind, candidate in walkDir(jobsDirectory(dir), relative = false):
    if kind == pcFile and candidate.endsWith(".json"):
      path = candidate
      try:
        result.add(parseJson(readFile(path)))
      except CatchableError:
        discard

proc responseFor(request: JsonNode, jobs: var Table[string, ManagedJob],
    dir: string): JsonNode {.role: {orchestrator}.} =
  ## request/jobs/dir: spawner command, process registry, and runtime directory.
  var
    action: string = request{"action"}.getStr("")
    id: string = request{"id"}.getStr("")
    resultsPath: string = request{"resultsPath"}.getStr(defaultResultsDirectory())
    job: ManagedJob
  case action
  of "start":
    discard catalogEntry(id)
    if jobs.hasKey(id) and jobs[id].process.running():
      return %*{"ok": true, "alreadyRunning": true, "id": id}
    job = startManagedJob(id, resultsPath, dir)
    jobs[id] = job
    result = %*{"ok": true, "id": id, "pid": processID(job.process)}
  of "poll":
    result = %*{"ok": true, "jobs": collectStates(dir)}
  of "stop":
    discard catalogEntry(id)
    writeFile(cancelPath(dir, id), "stop\n")
    result = %*{"ok": true, "id": id}
  of "stopAll":
    for key, managed in jobs.pairs:
      if managed.process.running():
        writeFile(cancelPath(dir, key), "stop\n")
    result = %*{"ok": true}
  of "shutdown":
    for key, managed in jobs.pairs:
      if managed.process.running():
        writeFile(cancelPath(dir, key), "stop\n")
    result = %*{"ok": true, "shutdown": true}
  else:
    result = %*{"ok": false, "error": "unsupported spawner action"}

proc cleanupJobs(jobs: var Table[string, ManagedJob]) {.role: {helper}.} =
  ## jobs: process registry whose completed handles should close.
  var
    completed: seq[string] = @[]
    dir: string = runtimeDirectory()
    statePath: string = ""
    S: JsonNode
    exitCode: int = 0
  for id, managed in jobs.mpairs:
    if not managed.process.running():
      exitCode = managed.process.waitForExit()
      managed.process.close()
      statePath = jobStatePath(dir, id)
      if fileExists(statePath):
        try:
          S = parseJson(readFile(statePath))
          if S{"status"}.getStr("") in ["queued", "running"]:
            S["status"] = %"fail"
            if S{"native"}{"status"}.getStr("") in ["queued", "running"]:
              updatePhase(S, "native", "fail", exitCode = exitCode)
              updatePhase(S, "wasm", "blocked", exitCode = 1)
            elif S{"wasm"}{"status"}.getStr("") in ["queued", "running"]:
              updatePhase(S, "wasm", "fail", exitCode = exitCode)
            atomicWrite(statePath, $S)
        except CatchableError:
          discard
      completed.add(id)
  for id in completed:
    jobs.del(id)

proc runSpawner*(dir: string) {.role: {metaOrchestrator}.} =
  ## dir: dedicated IPC directory owned by this spawner process.
  var
    jobs: Table[string, ManagedJob]
    request: JsonNode
    response: JsonNode
    responsePath: string = ""
    requestName: string = ""
    shuttingDown: bool = false
  ensureRuntimeDirectories(dir)
  while not shuttingDown:
    cleanupJobs(jobs)
    for kind, requestPath in walkDir(requestsDirectory(dir), relative = false):
      if kind != pcFile or not requestPath.endsWith(".json"):
        continue
      requestName = splitFile(requestPath).name
      try:
        request = parseJson(readFile(requestPath))
        response = responseFor(request, jobs, dir)
        shuttingDown = response{"shutdown"}.getBool(false)
      except CatchableError as exc:
        response = %*{"ok": false, "error": exc.msg}
      responsePath = joinPath(responsesDirectory(dir), requestName & ".json")
      atomicWrite(responsePath, $response)
      removeFile(requestPath)
    sleep(20)
  for id, managed in jobs.mpairs:
    if managed.process.running():
      writeFile(cancelPath(dir, id), "stop\n")
  sleep(200)
  for id, managed in jobs.mpairs:
    if managed.process.running():
      terminateProcessTree(managed.process)
    discard managed.process.waitForExit(3000)
    managed.process.close()

proc workerModeArgs*(args: openArray[string]): tuple[id, jobId, resultsPath,
    runtimePath: string] {.role: {parser}.} =
  ## args: worker command-line arguments.
  result.id = parseArg(args, "--test-id:")
  result.jobId = parseArg(args, "--job-id:")
  result.resultsPath = parseArg(args, "--results-path:")
  result.runtimePath = parseArg(args, "--runtime-path:")
