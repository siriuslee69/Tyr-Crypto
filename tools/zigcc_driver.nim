## ---------------------------------------------------------
## Zig CC Driver <- Nim replacement for local command wrappers
## ---------------------------------------------------------

import std/[os, osproc]

type
  ZigCcMode* = enum
    zigPathCompiler
    zigBundledCompiler

proc repoRootFromHere(): string =
  var
    appDir: string = getAppDir()
    sourceDir: string = parentDir(currentSourcePath())
    candidate: string = ""
  candidate = parentDir(appDir)
  if fileExists(joinPath(candidate, "tyr_crypto.nimble")):
    return candidate
  candidate = parentDir(sourceDir)
  result = candidate

proc hostExeName(name: string): string =
  when defined(windows):
    result = name & ".exe"
  else:
    result = name

proc bundledZigPath(repoRoot: string): string =
  result = joinPath(repoRoot, "build", "zig-windows-x86_64-0.13.0", hostExeName("zig"))

proc ensureDir(path: string) =
  if not dirExists(path):
    createDir(path)

proc configureCaches(repoRoot, suffix: string) =
  var
    buildDir: string = joinPath(repoRoot, "build")
    globalDir: string = joinPath(buildDir, "zig-global-cache")
    localDir: string = joinPath(buildDir, "zig-local-cache" & suffix)
    tmpDir: string = joinPath(buildDir, "tmp")
  ensureDir(globalDir)
  ensureDir(localDir)
  ensureDir(tmpDir)
  putEnv("ZIG_GLOBAL_CACHE_DIR", globalDir)
  putEnv("ZIG_LOCAL_CACHE_DIR", localDir)
  putEnv("TMP", tmpDir)
  putEnv("TEMP", tmpDir)

proc runZigCc*(target: string = ""; staticLink: bool = false;
    cacheSuffix: string = ""; mode: ZigCcMode = zigBundledCompiler) =
  var
    repoRoot: string = repoRootFromHere()
    zigExe: string = ""
    args: seq[string] = @[]
    command: string = ""
    res: tuple[output: string, exitCode: int]
    i: int = 1
  if cacheSuffix.len > 0:
    configureCaches(repoRoot, cacheSuffix)
  if mode == zigPathCompiler:
    zigExe = "zig"
  else:
    zigExe = bundledZigPath(repoRoot)
    if not fileExists(zigExe):
      stderr.writeLine("Missing Zig toolchain at " & zigExe)
      quit 1
  args.add("cc")
  if target.len > 0:
    args.add("-target")
    args.add(target)
  if staticLink:
    args.add("-static")
  i = 1
  while i <= paramCount():
    args.add(paramStr(i))
    i = i + 1
  command = quoteShell(zigExe)
  i = 0
  while i < args.len:
    command.add(" ")
    command.add(quoteShell(args[i]))
    i = i + 1
  res = execCmdEx(command)
  if res.output.len > 0:
    stdout.write(res.output)
  quit res.exitCode
