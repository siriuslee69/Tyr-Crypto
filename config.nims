# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
import std/[os, strutils]

const
  tyrCapabilityOverride = "tyrExplicitCapabilities"

var
  repoRoot: string = thisDir()

proc addPathIfExists(pathArg: string) =
  if dirExists(pathArg):
    switch("path", pathArg.replace('\\', '/'))

proc commandOption(name: string): string =
  var
    i: int = 1
    arg: string = ""
    colonPrefix: string = "--" & name & ":"
    equalsPrefix: string = "--" & name & "="
  while i <= paramCount():
    arg = paramStr(i)
    if arg.startsWith(colonPrefix):
      return arg[colonPrefix.len .. ^1]
    if arg.startsWith(equalsPrefix):
      return arg[equalsPrefix.len .. ^1]
    if arg == "--" & name and i < paramCount():
      return paramStr(i + 1)
    i = i + 1

proc commandDefines(name: string): bool =
  var
    i: int = 1
    arg: string = ""
  while i <= paramCount():
    arg = paramStr(i)
    if arg == "-d:" & name or arg == "--define:" & name or
        arg.startsWith("-d:" & name & "=") or
        arg.startsWith("--define:" & name & "=") or
        arg.startsWith("-d:" & name & ":") or
        arg.startsWith("--define:" & name & ":"):
      return true
    i = i + 1

proc normalizedCpu(cpu: string): string =
  result = cpu.toLowerAscii()
  if result == "x86_64":
    result = "amd64"
  if result == "aarch64":
    result = "arm64"

proc selectedCompiler(): tuple[kind, path: string] =
  result.kind = commandOption("cc").toLowerAscii()
  if result.kind.len == 0:
    result.kind = "gcc"
  result.path = commandOption(result.kind & ".exe")
  if result.path.len == 0:
    result.path = get(result.kind & ".exe")
  if result.path.len == 0:
    result.path = result.kind

proc nativeCompilerMacros(compiler: tuple[kind, path: string]): string =
  var
    nullPath: string = "/dev/null"
    probe: tuple[output: string, exitCode: int]
  if buildOS == "windows":
    nullPath = "NUL"
  if compiler.kind in ["vcc", "clang_cl", "icl"]:
    return
  probe = gorgeEx(quoteShell(compiler.path) &
    " -march=native -dM -E -x c " & quoteShell(nullPath))
  if probe.exitCode == 0:
    result = probe.output

proc enableX86Capability(name, cFlag: string, available: bool,
    msvc: bool) =
  if not available:
    return
  switch("define", name)
  if not msvc and cFlag.len > 0:
    switch("passC", cFlag)

proc applyTyrBuildDefaults() =
  var
    targetCpu: string = normalizedCpu(commandOption("cpu"))
    targetOs: string = commandOption("os").toLowerAscii()
    compiler: tuple[kind, path: string]
    compilerOverride: string = ""
    macros: string = ""
    nativeTarget: bool = false
    msvc: bool = false
  if targetCpu.len == 0:
    targetCpu = normalizedCpu(buildCPU)
  if targetOs.len == 0:
    targetOs = buildOS.toLowerAscii()
  if commandOption("opt").len == 0:
    switch("opt", "speed")
  if targetCpu in ["wasm32", "js"] or targetOs in ["any", "js"] or
      commandDefines("tyrWasm"):
    return
  if commandDefines(tyrCapabilityOverride) or commandDefines("OtterUiTarget"):
    return
  if targetCpu == "arm64":
    switch("define", "neon")
    return
  if targetCpu notin ["amd64", "i386"]:
    return
  compiler = selectedCompiler()
  compilerOverride = commandOption(compiler.kind & ".exe")
  msvc = compiler.kind in ["vcc", "clang_cl", "icl"]
  nativeTarget = targetCpu == normalizedCpu(buildCPU) and
    targetOs == buildOS.toLowerAscii() and compilerOverride.len == 0
  if nativeTarget:
    macros = nativeCompilerMacros(compiler)
  enableX86Capability("sse2", "-msse2", targetCpu == "amd64" or
    macros.contains("__SSE2__"), msvc)
  enableX86Capability("avx2", "-mavx2", macros.contains("__AVX2__"), msvc)
  enableX86Capability("aesni", "-maes", macros.contains("__AES__"), msvc)

addPathIfExists(joinPath(repoRoot, "src"))
addPathIfExists(joinPath(repoRoot, ".iron", "meta"))
addPathIfExists(joinPath(repoRoot, "submodules", "simd_nexus", "src"))
addPathIfExists(joinPath(repoRoot, "..", "SIMD-Nexus", "src"))
addPathIfExists(joinPath(repoRoot, "..", "Fylgia-Utils", "src"))
if dirExists(joinPath(repoRoot, "..", "Otter-RepoEvaluation", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "Otter-RepoEvaluation", "src"))
else:
  addPathIfExists(joinPath(repoRoot, "submodules", "otter_repo_evaluation", "src"))

var nimblePkgs: string = joinPath(getHomeDir(), ".nimble", "pkgs2")
if dirExists(nimblePkgs):
  for kind, path in walkDir(nimblePkgs):
    if kind == pcDir and path.contains("nimsimd-"):
      var candidate: string = joinPath(path, "nimsimd")
      if dirExists(candidate):
        switch("path", path.replace('\\', '/'))
        break

applyTyrBuildDefaults()
