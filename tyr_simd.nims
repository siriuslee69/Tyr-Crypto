## -------------------------------------------------------------------------
## Tyr SIMD selection <- one flag decides which vector code Tyr compiles
## -------------------------------------------------------------------------
##
## Included by Tyr's own `config.nims` AND by every repository that builds
## Tyr (Bifrost does). There is one copy, so the flag means the same thing
## wherever the build starts.
##
## `SIMD` := one instruction working on several values at once (AVX2 on
## x86, NEON on ARM). `scalar` := one value at a time; the smallest code,
## and the only kind that runs on every CPU.
##
##   -d:tyrSimd=<list>   Nim defines it sets               C flags it adds
##   -----------------   -------------------------------   ------------------
##   scalar              (none)                            (none)
##   sse2                sse2                              -msse2
##   avx2                sse2 avx2 simdNexusEnableAvx2     -msse2 -mavx2
##   aesni               aesni                             -maes
##   neon                neon                              (none needed)
##   native              whatever this CPU has (asks the C compiler)
##
##   Lists combine:  -d:tyrSimd=avx2,aesni
##
## Two more promises:
##
##   1  A bare `-d:avx2` (or sse2 / aesni) still works. The C flag the
##      intrinsics need is added for it, so it can no longer be forgotten.
##   2  With no -d:tyrSimd at all, the including repository's own default
##      applies: `native` inside Tyr, `scalar` inside Bifrost.
##
##   nim c -d:tyrSimd=avx2 app.nim
##          |
##          +--> switch("define", "sse2")      -> Tyr's `when defined(sse2)`
##          +--> switch("define", "avx2")      -> Tyr's `when defined(avx2)`
##          +--> switch("define", "simdNexusEnableAvx2")  -> SIMD-Nexus
##          +--> switch("passC", "-msse2 -mavx2")  -> the C compiler
##          +--> switch("passL", "-mavx2")     -> the linker (matters for LTO)
##
## Every name here starts with `tyrSimd` so it cannot collide with the
## including file's own helpers.

import std/[os, strutils]

proc tyrSimdOption(name: string): string =
  ## name: a `--name:value` / `--name=value` command-line option -> value.
  var
    i: int = 1
    arg: string = ""
  while i <= paramCount():
    arg = paramStr(i)
    if arg.startsWith("--" & name & ":") or arg.startsWith("--" & name & "="):
      return arg[name.len + 3 .. ^1]
    if arg == "--" & name and i < paramCount():
      return paramStr(i + 1)
    i = i + 1

proc tyrSimdDefineArg(arg, name: string): string =
  ## arg/name: one argument -> "" when it does not define `name`, "=" when it
  ## defines it with no value, or "=<value>".
  for prefix in ["-d:", "--define:", "--d:"]:
    if arg == prefix & name:
      return "="
    if arg.startsWith(prefix & name & "=") or
        arg.startsWith(prefix & name & ":"):
      return "=" & arg[prefix.len + name.len + 1 .. ^1]

proc tyrSimdDefine(name: string): string =
  ## name: define looked up on the command line -> "" when absent, "=" when
  ## given bare, "=<value>" when given a value.
  var
    i: int = 1
  while i <= paramCount():
    result = tyrSimdDefineArg(paramStr(i), name)
    if result.len > 0:
      return
    i = i + 1

proc tyrSimdCpu(): string =
  ## The target CPU, with the two spellings of each architecture merged.
  result = tyrSimdOption("cpu").toLowerAscii()
  if result.len == 0:
    result = buildCPU.toLowerAscii()
  if result == "x86_64":
    result = "amd64"
  if result == "aarch64":
    result = "arm64"

proc tyrSimdCompiler(): tuple[kind, path: string] =
  ## The C compiler this build uses: its family and its executable.
  result.kind = tyrSimdOption("cc").toLowerAscii()
  if result.kind.len == 0:
    result.kind = "gcc"
  result.path = tyrSimdOption(result.kind & ".exe")
  if result.path.len == 0:
    result.path = get(result.kind & ".exe")
  if result.path.len == 0:
    result.path = result.kind

proc tyrSimdMsvc(): bool =
  ## True for the Microsoft-style compilers, which take no -m flags.
  result = tyrSimdCompiler().kind in ["vcc", "clang_cl", "icl"]

proc tyrSimdNativeMacros(): string =
  ## What `-march=native` switches on for this machine, as the C compiler
  ## reports it ("#define __AVX2__ 1" ...). Empty when cross-compiling.
  var
    c: tuple[kind, path: string] = tyrSimdCompiler()
    nullPath: string = "/dev/null"
    probe: tuple[output: string, exitCode: int] = ("", 0)
  if buildOS == "windows":
    nullPath = "NUL"
  if tyrSimdMsvc() or tyrSimdOption(c.kind & ".exe").len > 0:
    return
  if tyrSimdCpu() != buildCPU.toLowerAscii().replace("x86_64", "amd64"):
    return
  probe = gorgeEx(quoteShell(c.path) & " -march=native -dM -E -x c " &
    quoteShell(nullPath))
  if probe.exitCode == 0:
    result = probe.output

proc tyrSimdCFlag(capability: string): string =
  ## capability: sse2 / avx2 / aesni -> the C compiler flag its intrinsics
  ## need. Empty for NEON (arm64 always has it) and for MSVC.
  if tyrSimdMsvc():
    return
  case capability
  of "sse2": result = "-msse2"
  of "avx2": result = "-mavx2"
  of "aesni": result = "-maes"
  else: result = ""

proc tyrSimdEnable(capability: string) =
  ## capability: switches on one capability, with its define and C flag.
  var
    flag: string = tyrSimdCFlag(capability)
  switch("define", capability)
  if capability == "avx2":
    switch("define", "simdNexusEnableAvx2")
  if flag.len > 0:
    switch("passC", flag)
    switch("passL", flag)

proc tyrSimdNativeList(): seq[string] =
  ## What `native` means on this machine and target.
  var
    cpu: string = tyrSimdCpu()
    macros: string = tyrSimdNativeMacros()
  if tyrSimdOption("os").toLowerAscii() in ["any", "standalone", "js"]:
    return
  if cpu == "arm64":
    return @["neon"]
  if cpu notin ["amd64", "i386"]:
    return
  if cpu == "amd64" or macros.contains("__SSE2__"):
    result.add("sse2")
  if macros.contains("__AVX2__"):
    result.add("avx2")
  if macros.contains("__AES__"):
    result.add("aesni")

proc tyrSimdRequireX86(word: string) =
  ## word: an x86-only entry; stops the build on any other target.
  if tyrSimdCpu() notin ["amd64", "i386"]:
    quit("-d:tyrSimd=" & word & " needs an x86 target, not " & tyrSimdCpu(), 1)

proc tyrSimdList(s: string): seq[string] =
  ## s: the -d:tyrSimd= value -> the capabilities to switch on. An unknown
  ## word, or an x86 capability on an ARM target, stops the build.
  var
    word: string = ""
  for raw in s.split(','):
    word = raw.strip().toLowerAscii()
    if word in ["sse2", "avx2", "aesni"]:
      tyrSimdRequireX86(word)
    case word
    of "", "scalar": discard
    of "native": result.add(tyrSimdNativeList())
    of "sse2": result.add("sse2")
    of "avx2": result.add(@["sse2", "avx2"])
    of "aesni": result.add("aesni")
    of "neon": result.add("neon")
    else:
      quit("-d:tyrSimd: unknown entry '" & raw & "' (expected scalar, " &
        "native, sse2, avx2, aesni, neon)", 1)

proc applyTyrSimd(fallback: string) =
  ## fallback: what applies when the command line gives no -d:tyrSimd.
  ## Also completes bare -d:sse2 / -d:avx2 / -d:aesni with their C flags.
  var
    given: string = tyrSimdDefine("tyrSimd")
    selection: string = fallback
    done: seq[string] = @[]
  if tyrSimdCpu() in ["wasm32", "js"] or tyrSimdDefine("tyrWasm").len > 0:
    return
  if given.len > 1:
    selection = given[1 .. ^1]
  for c in ["sse2", "avx2", "aesni"]:
    if tyrSimdDefine(c).len > 0 and tyrSimdCFlag(c).len > 0:
      switch("passC", tyrSimdCFlag(c))
      switch("passL", tyrSimdCFlag(c))
  for c in tyrSimdList(selection):
    if c notin done and tyrSimdDefine(c).len == 0:
      tyrSimdEnable(c)
      done.add(c)
