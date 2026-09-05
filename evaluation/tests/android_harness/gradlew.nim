## -------------------------------------------------
## Gradle Wrapper <- Nim replacement for gradlew.bat
## -------------------------------------------------

import std/[os, osproc, sequtils, strutils]

proc splitEnvArgs(value: string): seq[string] =
  if value.strip().len == 0:
    return @[]
  result = value.splitWhitespace()

proc javaExecutable(): string =
  var
    javaHome: string = getEnv("JAVA_HOME")
    candidate: string = ""
  if javaHome.len > 0:
    when defined(windows):
      candidate = joinPath(javaHome, "bin", "java.exe")
    else:
      candidate = joinPath(javaHome, "bin", "java")
    if fileExists(candidate):
      return candidate
    stderr.writeLine("ERROR: JAVA_HOME is set to an invalid directory: " & javaHome)
    quit 1
  result = "java"

when isMainModule:
  var
    appHome: string = parentDir(currentSourcePath())
    classpath: string = joinPath(appHome, "gradle", "wrapper", "gradle-wrapper.jar")
    args: seq[string] = @[]
    i: int = 1
    res: tuple[output: string, exitCode: int]
  if not fileExists(classpath):
    stderr.writeLine("Missing Gradle wrapper jar at " & classpath)
    quit 1
  args.add(splitEnvArgs(getEnv("JAVA_OPTS")))
  args.add(splitEnvArgs(getEnv("GRADLE_OPTS")))
  args.add("-Dorg.gradle.appname=gradlew")
  args.add("-classpath")
  args.add(classpath)
  args.add("org.gradle.wrapper.GradleWrapperMain")
  args.add("--project-dir")
  args.add(appHome)
  i = 1
  while i <= paramCount():
    if paramStr(i) != "--":
      args.add(paramStr(i))
    i = i + 1
  res = execCmdEx(quoteShell(javaExecutable()) & " " & args.mapIt(quoteShell(it)).join(" "))
  if res.output.len > 0:
    stdout.write(res.output)
  quit res.exitCode
