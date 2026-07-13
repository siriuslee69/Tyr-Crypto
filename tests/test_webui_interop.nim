## -------------------------------------------------------------------
## WebUI Interop Test <- browser WASM and native basic_api test runner
## -------------------------------------------------------------------

import std/[json, locks, os, strutils, unittest]

import webui
import webui/bindings as webuiBindings

import ../.iron/meta/metaPragmas
import ./webui_interop/interop_backend

var
  GEventLock: Lock
  GEventHandled: Cond
  GPendingEvent: ptr webuiBindings.Event = nil
  GPendingKind: int = 0
  GEventResponse: string = ""
  GResponseReady: bool = false
  GSmokeComplete: bool = false
  GSmokeReport: string = ""

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

proc runDashboard() {.role: {metaOrchestrator}.} =
  ## Hosts the dashboard and connects its WebUI RPC transport to native crypto.
  var
    root: string = webDirectory()
    window: Window = webui.newWindow()
  window.eventBlocking = true
  if not fileExists(root / "index.html"):
    raise newException(IOError, "WebUI interop entrypoint is missing: " & root)
  webui.setTimeout(0)
  window.setSize(1440, 940)
  if not (window.rootFolder = root):
    raise newException(IOError, "WebUI could not register the interop asset folder")
  bindWindow(window, "interop", bindInterop)
  bindWindow(window, "interopComplete", bindInteropComplete)
  if not window.show("index.html"):
    raise newException(IOError, "WebUI could not open the interop dashboard")
  while window.shown():
    pumpInteropEvent()
    sleep(2)
  webui.clean()

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

suite "WebUI interop backend":
  test "native browser transport contract encrypts and decrypts":
    runBackendContract()

when isMainModule:
  initLock(GEventLock)
  initCond(GEventHandled)
  when defined(tyrWebUiInteropSmoke):
    runBrowserSmoke()
  else:
    runDashboard()
  deinitCond(GEventHandled)
  deinitLock(GEventLock)
