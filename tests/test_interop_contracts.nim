## -------------------------------------------------------------------
## Interop Contracts <- browser WASM and native basic_api test runner
## -------------------------------------------------------------------

import std/[json, locks, os, osproc, strutils, unittest]

import webui
import webui/bindings as webuiBindings

import ../.iron/meta/metaPragmas
import ./webui_interop/[interop_backend, test_catalog, test_jobs]

var
  GEventLock: Lock
  GEventHandled: Cond
  GPendingEvent: ptr webuiBindings.Event = nil
  GPendingKind: int = 0
  GEventResponse: string = ""
  GResponseReady: bool = false
  GSmokeComplete: bool = false
  GSmokeReport: string = ""

proc commandMode(args: openArray[string]): string {.role: {parser}.} =
  ## args: launcher arguments containing an optional process mode.
  var i: int = 0
  while i < args.len:
    if args[i].startsWith("--tyr-mode:"):
      return args[i]["--tyr-mode:".len .. ^1]
    i = i + 1

proc runtimeArg(args: openArray[string]): string {.role: {parser}.} =
  ## args: launcher arguments containing an optional runtime directory.
  var i: int = 0
  while i < args.len:
    if args[i].startsWith("--runtime-path:"):
      return args[i]["--runtime-path:".len .. ^1]
    i = i + 1

proc eventString(e: ptr webuiBindings.Event): string {.role: {helper}.} =
  ## Copies one WebUI string argument out of the foreign callback frame.
  var
    source: cstring = webuiBindings.getString(e)
    length: int = int(webuiBindings.getSize(e))
  result = newString(length)
  if length > 0:
    copyMem(addr result[0], source, length)

proc handoffEvent(e: ptr webuiBindings.Event, kind: int) {.role: {helper}.} =
  ## Hands a foreign-thread callback to the main Nim thread and waits for it.
  acquire(GEventLock)
  while GPendingEvent != nil:
    wait(GEventHandled, GEventLock)
  GPendingKind = kind
  GPendingEvent = e
  while not GResponseReady:
    wait(GEventHandled, GEventLock)
  webuiBindings.returnString(e, cstring(GEventResponse))
  GEventResponse = ""
  GResponseReady = false
  GPendingKind = 0
  GPendingEvent = nil
  broadcast(GEventHandled)
  release(GEventLock)

proc bindInterop(e: ptr webuiBindings.Event) {.cdecl, role: {actor}.} =
  ## Hands one browser crypto request to the main-thread transport pump.
  handoffEvent(e, 1)

proc bindInteropComplete(e: ptr webuiBindings.Event) {.cdecl, role: {actor}.} =
  ## Hands the browser matrix report to the main-thread transport pump.
  handoffEvent(e, 2)

proc bindWindow(window: Window; name: string;
    callback: proc(e: ptr webuiBindings.Event) {.cdecl.}) {.role: {helper}.} =
  ## Registers a callback without allocating nim-webui Event refs on C threads.
  discard webuiBindings.bind(csize_t(int(window)), cstring(name), callback)

proc pumpInteropEvent() {.role: {orchestrator}.} =
  ## Processes one queued WebUI callback on Nim's main thread.
  var
    event: ptr webuiBindings.Event = nil
    kind: int = 0
    request: string = ""
    response: string = ""
  acquire(GEventLock)
  event = GPendingEvent
  kind = GPendingKind
  if GResponseReady:
    event = nil
  release(GEventLock)
  if event == nil:
    return
  request = eventString(event)
  if kind == 1:
    response = processInteropRequest(request)
  else:
    GSmokeReport = request
    GSmokeComplete = true
    response = "ok"
  acquire(GEventLock)
  GEventResponse = response
  GResponseReady = true
  broadcast(GEventHandled)
  release(GEventLock)

proc webDirectory(): string {.role: {helper}.} =
  ## Returns the local browser dashboard asset directory.
  result = currentSourcePath().splitFile.dir / "webui_interop" / "web"

proc encodeTestBytes(B: openArray[uint8]): string {.role: {helper}.} =
  ## Encodes test data with the same binary/base64 form used by WebUI.
  result = encodeBytes(B)

proc catalogHasId(E: JsonNode, id: string): bool {.role: {parser}.} =
  ## E/id: catalog entry array and stable identifier to locate.
  var i: int = 0
  while i < E.len:
    if E[i]["id"].getStr() == id:
      return true
    i = i + 1

proc jobWithId(J: JsonNode, id: string): JsonNode {.role: {parser}.} =
  ## J/id: polled job array and catalog identifier to locate.
  var i: int = 0
  while i < J.len:
    if J[i]{"id"}.getStr("") == id:
      return J[i]
    i = i + 1
  result = newJNull()

proc runBackendContract() {.role: {orchestrator}.} =
  ## Runs native transport checks that are also used by the browser dashboard.
  var
    key: seq[uint8] = newSeq[uint8](32)
    nonce: seq[uint8] = newSeq[uint8](24)
    message: seq[uint8] = @[byte 84, 121, 114, 32, 105, 110, 116, 101, 114, 111, 112]
    encrypted: JsonNode
    decrypted: JsonNode
    request: JsonNode
  key[0] = 17
  nonce[0] = 29
  request = %*{
    "action": "symEncrypt", "algo": "xchacha20", "key": encodeTestBytes(key),
    "nonce": encodeTestBytes(nonce), "message": encodeTestBytes(message)
  }
  encrypted = parseJson(processInteropRequest($request))
  check encrypted["ok"].getBool()
  request = %*{
    "action": "symDecrypt", "algo": "xchacha20", "key": encodeTestBytes(key),
    "nonce": encodeTestBytes(nonce), "payload": encrypted["bytes"].getStr()
  }
  decrypted = parseJson(processInteropRequest($request))
  check decrypted["ok"].getBool()
  check decrypted["bytes"].getStr() == encodeTestBytes(message)

proc terminateChild(p: Process) {.role: {actor}.} =
  ## p: supervisor-owned process to stop with its immediate child tree.
  if p == nil or not p.running():
    return
  when defined(windows):
    discard execCmd("taskkill /PID " & $processID(p) & " /T /F")
  else:
    discard execCmd("pkill -TERM -P " & $processID(p))
    p.terminate()

proc runBrowserSmoke() {.role: {metaOrchestrator}.} =
  ## Waits for the real browser page to complete its WASM/native exchange matrix.
  const
    pollLimit = 240
    pollDelayMs = 250
  var
    root: string = webDirectory()
    window: Window = webui.newWindow()
    browserProfile: string = getTempDir() / ("tyr-webui-smoke-" & $getCurrentProcessId())
    poll: int = 0
    statusParts: seq[string] = @[]
    failed: int = 0
    exchanges: int = 0
    shown: bool = false
  if not fileExists(root / "index.html"):
    raise newException(IOError, "WebUI interop entrypoint is missing: " & root)
  webui.setConfig(webuiBindings.WebuiConfig.wcMonitor, false)
  webui.setTimeout(15)
  GSmokeComplete = false
  GSmokeReport = ""
  createDir(browserProfile)
  window.eventBlocking = true
  window.hidden = true
  window.setProfile("tyr-webui-smoke", browserProfile)
  if not (window.rootFolder = root):
    raise newException(IOError, "WebUI could not register the interop asset folder")
  bindWindow(window, "interop", bindInterop)
  bindWindow(window, "interopComplete", bindInteropComplete)
  if browserExist(webuiBindings.WebuiBrowser.wbBrave):
    shown = window.show("index.html", webuiBindings.WebuiBrowser.wbBrave)
  if not shown and browserExist(webuiBindings.WebuiBrowser.wbChromium):
    shown = window.show("index.html", webuiBindings.WebuiBrowser.wbChromium)
  if not shown and browserExist(webuiBindings.WebuiBrowser.wbFirefox):
    shown = window.show("index.html", webuiBindings.WebuiBrowser.wbFirefox)
  if not shown:
    raise newException(IOError, "WebUI could not open an isolated interop smoke browser")
  try:
    while poll < pollLimit and not GSmokeComplete:
      pumpInteropEvent()
      sleep(pollDelayMs)
      poll = poll + 1
    pumpInteropEvent()
    if not GSmokeComplete:
      raise newException(IOError, "browser interoperability matrix timed out")
    statusParts = GSmokeReport.split('|')
    if statusParts.len < 2:
      raise newException(ValueError, "browser returned malformed interoperability status")
    failed = parseInt(statusParts[0])
    exchanges = parseInt(statusParts[1])
    if failed != 0:
      raise newException(ValueError, "browser interoperability matrix reported failures: " &
        (if statusParts.len > 2: statusParts[2 .. ^1].join("|") else: "no browser error given"))
    if exchanges < 30:
      raise newException(ValueError, "browser interoperability matrix ran too few exchanges")
    acquire(GEventLock)
    while GPendingEvent != nil:
      wait(GEventHandled, GEventLock)
    release(GEventLock)
  finally:
    window.destroy()
    webui.clean()

if commandMode(commandLineParams()).len == 0:
  suite "WebUI interop backend":
    test "native browser transport contract encrypts and decrypts":
      runBackendContract()

    test "catalog exposes complete custom crypto coverage":
      var
        payload: JsonNode = parseJson(catalogPayload(false))
        i: int = 0
        j: int = 0
        source: string = ""
      check payload["ok"].getBool()
      check payload["entries"].len >= 50
      check catalogHasId(payload["entries"], "sha256")
      check catalogHasId(payload["entries"], "kyber")
      check catalogHasId(payload["entries"], "bench-asymmetric")
      while i < payload["entries"].len:
        j = 0
        while j < payload["entries"][i]["sources"].len:
          source = payload["entries"][i]["sources"][j].getStr()
          check fileExists(parentDir(currentSourcePath()) / ".." / source)
          j = j + 1
        i = i + 1

    test "result path can be changed and browser results are persisted":
      var
        outputDir: string = getTempDir() / ("tyr-test-ui-results-" & $getCurrentProcessId())
        response: JsonNode
      if dirExists(outputDir):
        removeDir(outputDir)
      check setResultsDirectory(outputDir) == outputDir
      response = parseJson(recordInteropResult(true, 7, "interop contract pass"))
      check fileExists(response["logPath"].getStr())
      check fileExists(response["resultPath"].getStr())
      discard setResultsDirectory(defaultResultsDirectory())

    when defined(tyrTestCatalogContract):
      test "catalog executes functional vector and benchmark entries":
        var
          outputDir: string = getTempDir() / ("tyr-test-ui-catalog-" & $getCurrentProcessId())
          response: JsonNode
        discard setResultsDirectory(outputDir)
        for id in ["otp", "sha256", "bench-kdf"]:
          checkpoint("catalog entry " & id)
          response = parseJson(runCatalogEntry(id))
          check response["ok"].getBool()
          check response["passed"].getBool()
          check fileExists(response["logPath"].getStr())
          check fileExists(response["resultPath"].getStr())
        discard setResultsDirectory(defaultResultsDirectory())

    when defined(tyrTestProcessContract):
      test "spawner isolates concurrent native WASM jobs and cancellation":
        var
          dir: string = getTempDir() / ("tyr-test-ui-process-" &
            $getCurrentProcessId())
          outputDir: string = dir / "results"
          previousRuntime: string = getEnv("TYR_TEST_UI_RUNTIME")
          spawner: Process
          response: JsonNode
          otpState: JsonNode
          shaState: JsonNode
          i: int = 0
        ensureRuntimeDirectories(dir)
        putEnv("TYR_TEST_UI_RUNTIME", dir)
        spawner = startProcess(getAppFilename(), workingDir = getCurrentDir(),
          args = @["--tyr-mode:spawner", "--runtime-path:" & dir],
          options = {poParentStreams})
        try:
          sleep(150)
          response = spawnerRequest(%*{
            "action": "start", "id": "otp", "resultsPath": outputDir})
          check response["ok"].getBool()
          response = spawnerRequest(%*{
            "action": "start", "id": "sha256", "resultsPath": outputDir})
          check response["ok"].getBool()
          response = spawnerRequest(%*{"action": "stop", "id": "sha256"})
          check response["ok"].getBool()
          while i < 1200:
            response = spawnerRequest(%*{"action": "poll"})
            otpState = jobWithId(response["jobs"], "otp")
            shaState = jobWithId(response["jobs"], "sha256")
            if otpState.kind != JNull and shaState.kind != JNull and
                otpState{"status"}.getStr("") notin ["queued", "running"] and
                shaState{"status"}.getStr("") notin ["queued", "running"]:
              break
            sleep(100)
            i = i + 1
          check otpState{"status"}.getStr("") == "pass"
          check otpState{"native"}{"status"}.getStr("") == "pass"
          check otpState{"wasm"}{"status"}.getStr("") == "pass"
          check shaState{"status"}.getStr("") == "stopped"
          response = spawnerRequest(%*{"action": "shutdown"})
          check response["ok"].getBool()
        finally:
          sleep(150)
          terminateChild(spawner)
          if spawner != nil:
            discard spawner.waitForExit(3000)
            spawner.close()
          putEnv("TYR_TEST_UI_RUNTIME", previousRuntime)

    when defined(tyrTestWasmCatalogContract):
      test "every paired catalog card compiles to executable WASM":
        var failures: seq[string] = auditWasmCatalog()
        if failures.len > 0:
          checkpoint(failures.join("\n\n"))
        check failures.len == 0

when isMainModule:
  var
    args: seq[string] = commandLineParams()
    mode: string = commandMode(args)
    workerArgs = workerModeArgs(args)
    dir: string = runtimeArg(args)
  if mode == "spawner":
    runSpawner(dir)
  elif mode == "worker":
    runWorker(workerArgs.id, workerArgs.jobId, workerArgs.resultsPath,
      workerArgs.runtimePath)
  elif mode == "pair":
    ensureRuntimeDirectories(workerArgs.runtimePath)
    runWorker(workerArgs.id, workerArgs.jobId, workerArgs.resultsPath,
      workerArgs.runtimePath)
  else:
    initLock(GEventLock)
    initCond(GEventHandled)
    when defined(tyrWebUiInteropSmoke):
      runBrowserSmoke()
    elif defined(tyrTestCatalogContract) or defined(tyrTestProcessContract) or
        defined(tyrTestWasmCatalogContract):
      discard
    else:
      discard
    deinitCond(GEventHandled)
    deinitLock(GEventLock)
