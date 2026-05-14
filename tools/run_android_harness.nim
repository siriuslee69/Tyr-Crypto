## ------------------------------------------------------------
## Android Harness Runner <- Nim replacement for PowerShell run
## ------------------------------------------------------------

import std/[os, osproc, strutils, times]

type
  RunConfig = object
    serial: string
    timeoutSeconds: int
    pollSeconds: int

proc quoteArgs(args: openArray[string]): string =
  var
    i: int = 0
  while i < args.len:
    if i > 0:
      result.add(" ")
    result.add(quoteShell(args[i]))
    i = i + 1

proc runChecked(args: openArray[string]) =
  var
    res: tuple[output: string, exitCode: int]
  res = execCmdEx(quoteArgs(args))
  if res.output.len > 0:
    stdout.write(res.output)
  if res.exitCode != 0:
    raise newException(OSError, "command failed: " & quoteArgs(args))

proc runCapture(args: openArray[string]): tuple[output: string, exitCode: int] =
  result = execCmdEx(quoteArgs(args))

proc parseConfig(): RunConfig =
  var
    i: int = 1
    arg: string = ""
  result.serial = "ZY22K9DZG9"
  result.timeoutSeconds = 900
  result.pollSeconds = 2
  while i <= paramCount():
    arg = paramStr(i)
    if arg == "--":
      discard
    elif arg.startsWith("--serial:"):
      result.serial = arg.split(":", 1)[1]
    elif arg.startsWith("--serial="):
      result.serial = arg.split("=", 1)[1]
    elif arg == "--serial" and i < paramCount():
      i = i + 1
      result.serial = paramStr(i)
    elif arg.startsWith("--timeoutSeconds:"):
      result.timeoutSeconds = parseInt(arg.split(":", 1)[1])
    elif arg.startsWith("--timeoutSeconds="):
      result.timeoutSeconds = parseInt(arg.split("=", 1)[1])
    elif arg == "--timeoutSeconds" and i < paramCount():
      i = i + 1
      result.timeoutSeconds = parseInt(paramStr(i))
    elif arg.startsWith("--pollSeconds:"):
      result.pollSeconds = parseInt(arg.split(":", 1)[1])
    elif arg.startsWith("--pollSeconds="):
      result.pollSeconds = parseInt(arg.split("=", 1)[1])
    elif arg == "--pollSeconds" and i < paramCount():
      i = i + 1
      result.pollSeconds = parseInt(paramStr(i))
    else:
      raise newException(ValueError, "unknown argument: " & arg)
    i = i + 1

proc readHarnessOutput(serial, packageName: string): string =
  var
    res: tuple[output: string, exitCode: int]
  res = runCapture(["adb", "-s", serial, "shell", "run-as", packageName,
    "cat", "files/last_test_output.txt"])
  if res.exitCode != 0:
    return ""
  result = res.output

when isMainModule:
  var
    config: RunConfig = parseConfig()
    repoRoot: string = parentDir(currentSourcePath())
    apkPath: string = joinPath(repoRoot, "tests", "android_harness", "app",
      "build", "outputs", "apk", "debug", "app-debug.apk")
    packageName: string = "org.tyrcrypto.harness"
    component: string = packageName & "/" & packageName & ".MainActivity"
    deadline: DateTime
    output: string = ""
  repoRoot = parentDir(repoRoot)
  apkPath = joinPath(repoRoot, "tests", "android_harness", "app", "build",
    "outputs", "apk", "debug", "app-debug.apk")
  if not fileExists(apkPath):
    raise newException(IOError, "Missing APK at " & apkPath &
      ". Run tools/build_android_harness.nim first.")
  if config.timeoutSeconds < 1:
    raise newException(ValueError, "timeoutSeconds must be >= 1")
  if config.pollSeconds < 1:
    raise newException(ValueError, "pollSeconds must be >= 1")

  runChecked(["adb", "-s", config.serial, "install", "-r", apkPath])
  discard runCapture(["adb", "-s", config.serial, "shell", "am", "force-stop", packageName])
  discard runCapture(["adb", "-s", config.serial, "shell", "run-as", packageName,
    "rm", "-f", "files/last_test_output.txt"])
  discard runCapture(["adb", "-s", config.serial, "shell", "run-as", packageName,
    "rm", "-f", "files/last_trace_output.txt"])
  discard runCapture(["adb", "-s", config.serial, "shell", "am", "start", "-n", component])

  deadline = now() + initDuration(seconds = config.timeoutSeconds)
  while now() < deadline:
    output = readHarnessOutput(config.serial, packageName)
    if output.startsWith("exit=") or output.startsWith("error="):
      stdout.write(output)
      quit 0
    sleep(config.pollSeconds * 1000)
  raise newException(IOError, "Timed out waiting for Android harness output after " &
    $config.timeoutSeconds & " seconds.")
