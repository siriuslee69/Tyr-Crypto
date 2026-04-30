## ---------------------------------------------------------
## Otter Support <- optional no-op bridge to Otter timings
## ---------------------------------------------------------

import std/macros

when defined(otterTiming):
  import otter_repo_evaluation

when defined(otterTrace):
  import std/[locks, os, times]

  var
    gOtterTraceLock: Lock
    gOtterTraceLockReady: bool = false

  proc ensureOtterTraceLock() =
    if gOtterTraceLockReady:
      return
    initLock(gOtterTraceLock)
    gOtterTraceLockReady = true

  proc otterTracePath(): string =
    result = getEnv("TYR_OTTER_TRACE_PATH")
    if result.len == 0:
      result = getEnv("OTTER_TRACE_PATH")
    if result.len == 0:
      result = "build/otter_trace.log"

  proc ensureOtterTraceDir(p: string) =
    var
      dir: string = parentDir(p)
    if dir.len == 0 or dir == ".":
      return
    if dirExists(dir):
      return
    createDir(dir)

  proc otterTraceMark*(stage: string, n: string) =
    var
      line: string = ""
      path: string = ""
      f: File
    path = otterTracePath()
    line = $now() & "\t" & stage & "\t" & n & "\n"
    ensureOtterTraceLock()
    acquire(gOtterTraceLock)
    ensureOtterTraceDir(path)
    if open(f, path, fmAppend):
      defer:
        f.close()
      f.write(line)
    release(gOtterTraceLock)

  template otterTraceSpan*(n: string, body: untyped): untyped =
    otterTraceMark("enter", n)
    try:
      body
    finally:
      otterTraceMark("leave", n)
else:
  proc otterTraceMark*(stage: string, n: string) =
    discard stage
    discard n

  template otterTraceSpan*(n: string, body: untyped): untyped =
    body

template otterSpan*(n: string, body: untyped): untyped =
  when defined(otterTiming):
    otter_repo_evaluation.otterSpan(n):
      body
  else:
    body

proc instrumentRoutineWithWrapper(n: NimNode, wrapperName: string): NimNode {.compileTime.} =
  var
    r: NimNode
    b: NimNode
    i: int = 0
    s: NimNode
  r = copyNimTree(n)
  i = r.len - 1
  b = r[i]
  s = newLit($(if n[0].kind == nnkPostfix and n[0].len > 1: n[0][1] else: n[0]))
  let wrapperIdent = newIdentNode(wrapperName)
  r[i] = quote do:
    `wrapperIdent`(`s`):
      `b`
  result = r

proc instrumentNodeWithWrapper(n: NimNode, wrapperName: string): NimNode {.compileTime.} =
  const
    OtterRoutineKinds = {
      nnkProcDef,
      nnkFuncDef,
      nnkMethodDef,
      nnkConverterDef
    }
  var
    t: NimNode
  if n.kind in OtterRoutineKinds:
    return instrumentRoutineWithWrapper(n, wrapperName)
  t = copyNimNode(n)
  for c in n:
    t.add(instrumentNodeWithWrapper(c, wrapperName))
  result = t

macro otterTimed*(body: untyped): untyped =
  result = instrumentNodeWithWrapper(body, "otterSpan")

macro otterInstrument*(body: untyped): untyped =
  result = instrumentNodeWithWrapper(body, "otterSpan")

macro otterBench*(body: untyped): untyped =
  result = instrumentNodeWithWrapper(body, "otterSpan")

macro otterTrace*(body: untyped): untyped =
  result = instrumentNodeWithWrapper(body, "otterTraceSpan")
