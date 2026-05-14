## ---------------------------------------------------------------
## Android Harness Builder <- Nim replacement for PowerShell build
## ---------------------------------------------------------------

import std/[httpclient, os, osproc, strutils]

type
  HarnessTarget = enum
    targetCustomCrypto
    targetAsymmetricFast
    targetAsymmetricFull

  BuildConfig = object
    harnessTarget: HarnessTarget
    release: bool

  TargetInfo = object
    entryPoint: string
    binaryBase: string
    nimcacheBase: string

const
  zigVersion = "0.13.0"
  zigArchive = "zig-windows-x86_64-" & zigVersion & ".zip"
  zigDirName = "zig-windows-x86_64-" & zigVersion
  zigUrl = "https://ziglang.org/download/" & zigVersion & "/" & zigArchive

proc hostExeName(name: string): string =
  when defined(windows):
    result = name & ".exe"
  else:
    result = name

proc quoteArgs(args: openArray[string]): string =
  var
    i: int = 0
  while i < args.len:
    if i > 0:
      result.add(" ")
    result.add(quoteShell(args[i]))
    i = i + 1

proc runChecked(command: string) =
  var
    res: tuple[output: string, exitCode: int]
  echo command
  res = execCmdEx(command)
  if res.output.len > 0:
    stdout.write(res.output)
  if res.exitCode != 0:
    raise newException(OSError, "command failed with exit " & $res.exitCode)

proc parseTarget(value: string): HarnessTarget =
  case value
  of "custom_crypto":
    result = targetCustomCrypto
  of "asymmetric_fast":
    result = targetAsymmetricFast
  of "asymmetric_full":
    result = targetAsymmetricFull
  else:
    raise newException(ValueError, "unknown harness target: " & value)

proc parseConfig(): BuildConfig =
  var
    i: int = 1
    arg: string = ""
  result.harnessTarget = targetCustomCrypto
  while i <= paramCount():
    arg = paramStr(i)
    if arg == "--":
      discard
    elif arg == "--release" or arg == "-d:release":
      result.release = true
    elif arg.startsWith("--harnessTarget:"):
      result.harnessTarget = parseTarget(arg.split(":", 1)[1])
    elif arg.startsWith("--harnessTarget="):
      result.harnessTarget = parseTarget(arg.split("=", 1)[1])
    elif arg == "--harnessTarget" and i < paramCount():
      i = i + 1
      result.harnessTarget = parseTarget(paramStr(i))
    else:
      raise newException(ValueError, "unknown argument: " & arg)
    i = i + 1

proc targetInfo(t: HarnessTarget): TargetInfo =
  case t
  of targetCustomCrypto:
    result.entryPoint = "tests/test_android_custom_crypto.nim"
    result.binaryBase = "test_android_custom_crypto"
    result.nimcacheBase = "custom"
  of targetAsymmetricFast:
    result.entryPoint = "tests/test_android_asymmetric_fast.nim"
    result.binaryBase = "test_android_asymmetric_fast"
    result.nimcacheBase = "asymmetric_fast"
  of targetAsymmetricFull:
    result.entryPoint = "tests/test_android_asymmetric_crypto.nim"
    result.binaryBase = "test_android_asymmetric_crypto"
    result.nimcacheBase = "asymmetric_full"

proc ensureZig(repoRoot: string) =
  var
    buildDir: string = joinPath(repoRoot, "build")
    zigExe: string = joinPath(buildDir, zigDirName, hostExeName("zig"))
    zipPath: string = joinPath(buildDir, zigArchive)
    client: HttpClient
  if fileExists(zigExe):
    return
  createDir(buildDir)
  if not fileExists(zipPath):
    echo "get  " & zigUrl
    client = newHttpClient()
    client.downloadFile(zigUrl, zipPath)
  runChecked("tar -xf " & quoteShell(zipPath) & " -C " & quoteShell(buildDir))

proc compileTool(repoRoot, toolName: string): string =
  var
    outPath: string = joinPath(repoRoot, "build", hostExeName(toolName))
    cachePath: string = joinPath(repoRoot, "build", "nimcache_" & toolName)
    sourcePath: string = joinPath(repoRoot, "tools", toolName & ".nim")
  createDir(parentDir(outPath))
  runChecked("nim c --nimcache:" & quoteShell(cachePath) &
    " --out:" & quoteShell(outPath) & " " & quoteShell(sourcePath))
  result = outPath

proc runNimHarnessBuild(repoRoot, cpu, compilerPath, nimcachePath,
    outputPath, nimsimdPath: string, info: TargetInfo, release: bool) =
  var
    args: seq[string] = @[
      "c",
      "--os:linux",
      "--cpu:" & cpu,
      "--cc:clang",
      "--clang.exe:" & compilerPath,
      "--clang.linkerexe:" & compilerPath,
      "--nimcache:" & nimcachePath,
      "--out:" & outputPath
    ]
  if nimsimdPath.len > 0:
    args.add("--path:" & nimsimdPath)
  if cpu == "arm64":
    args.add("-d:neon")
    args.add("--passC:-fPIE")
    args.add("--passL:-static")
  if release:
    args.add("-d:release")
  args.add(info.entryPoint)
  runChecked("nim " & quoteArgs(args))

proc firstExistingDir(candidates: openArray[string]): string =
  var i: int = 0
  while i < candidates.len:
    if candidates[i].len > 0 and dirExists(candidates[i]):
      return candidates[i]
    i = i + 1

proc defaultAndroidSdk(): string =
  when defined(windows):
    result = joinPath(getHomeDir(), "AppData", "Local", "Android", "Sdk")
  else:
    result = joinPath(getHomeDir(), "Android", "Sdk")

proc defaultJavaHome(): string =
  when defined(windows):
    result = firstExistingDir([
      joinPath(getEnv("ProgramFiles"), "Android", "Android Studio", "jbr"),
      joinPath(getEnv("ProgramFiles"), "Eclipse Adoptium")
    ])
  else:
    result = firstExistingDir([
      "/usr/lib/jvm/default",
      "/usr/lib/jvm/default-java"
    ])

proc findNimblePackage(prefix: string): string =
  var
    pkgsRoot: string = joinPath(getHomeDir(), ".nimble", "pkgs2")
    tail: string = ""
  if not dirExists(pkgsRoot):
    return ""
  for kind, path in walkDir(pkgsRoot):
    if kind == pcDir:
      tail = splitPath(path).tail
      if tail.startsWith(prefix & "-"):
        return path

when isMainModule:
  var
    repoRoot: string = parentDir(parentDir(currentSourcePath()))
    config: BuildConfig = parseConfig()
    info: TargetInfo = targetInfo(config.harnessTarget)
    harnessDir: string = joinPath(repoRoot, "tests", "android_harness")
    androidSdk: string = getEnv("ANDROID_SDK_ROOT")
    javaHome: string = getEnv("JAVA_HOME")
    nimsimdPath: string = getEnv("NIMSIMD_PATH")
    buildMode: string = "debug"
    armWrapper: string = ""
    x64Wrapper: string = ""
    arm64Out: string = ""
    x64Out: string = ""
  if androidSdk.len == 0:
    androidSdk = defaultAndroidSdk()
  if javaHome.len == 0:
    javaHome = defaultJavaHome()
  if nimsimdPath.len == 0:
    nimsimdPath = findNimblePackage("nimsimd")
  if config.release:
    buildMode = "release"

  ensureZig(repoRoot)
  armWrapper = compileTool(repoRoot, "zigcc_linux_aarch64")
  x64Wrapper = compileTool(repoRoot, "zigcc_linux_x86_64")

  arm64Out = joinPath(repoRoot, "build", info.binaryBase & "_arm64")
  x64Out = joinPath(repoRoot, "build", info.binaryBase & "_x86_64")
  runNimHarnessBuild(repoRoot, "arm64", armWrapper,
    joinPath(repoRoot, "build", "nimcache_linux_arm64_" & info.nimcacheBase & "_" & buildMode),
    arm64Out, nimsimdPath, info, config.release)
  runNimHarnessBuild(repoRoot, "amd64", x64Wrapper,
    joinPath(repoRoot, "build", "nimcache_linux_x64_" & info.nimcacheBase & "_" & buildMode),
    x64Out, nimsimdPath, info, config.release)

  createDir(joinPath(harnessDir, "app", "src", "main", "jniLibs", "arm64-v8a"))
  createDir(joinPath(harnessDir, "app", "src", "main", "jniLibs", "x86_64"))
  copyFile(arm64Out, joinPath(harnessDir, "app", "src", "main", "jniLibs", "arm64-v8a", "libtyrtests.so"))
  copyFile(x64Out, joinPath(harnessDir, "app", "src", "main", "jniLibs", "x86_64", "libtyrtests.so"))

  if javaHome.len > 0:
    putEnv("JAVA_HOME", javaHome)
  if androidSdk.len > 0:
    putEnv("ANDROID_HOME", androidSdk)
    putEnv("ANDROID_SDK_ROOT", androidSdk)
  putEnv("GRADLE_USER_HOME", joinPath(repoRoot, "build", "gradle-home"))
  createDir(getEnv("GRADLE_USER_HOME"))
  runChecked("nim r " & quoteShell(joinPath(harnessDir, "gradlew.nim")) & " -- assembleDebug")
