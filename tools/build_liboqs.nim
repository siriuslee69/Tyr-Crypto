import os
import osproc
import strutils

proc findCryptoRepoDir*(): string =
  ## Returns the crypto repo base directory based on this file's location.
  var
    sourceFile: string = currentSourcePath()
    sourceDir: string = ""
    baseDir: string = ""
  sourceDir = splitFile(sourceFile).dir
  baseDir = parentDir(sourceDir)
  result = baseDir

proc buildPaths*(a: string): tuple[repoDir: string, buildDir: string, buildSubDir: string,
    installDir: string, libDir: string, binDir: string] =
  ## a: crypto repo base directory
  ## Builds liboqs repo and build paths.
  var
    repoDir: string = if dirExists(joinPath(a, "submodules", "liboqs")):
        joinPath(a, "submodules", "liboqs")
      else:
        joinPath(parentDir(a), "liboqs")
    buildDir: string = joinPath(a, "build", "liboqs")
    buildSubDir: string = joinPath(buildDir, "build")
    installDir: string = joinPath(buildDir, "install")
    libDir: string = joinPath(installDir, "lib")
    binDir: string = joinPath(installDir, "bin")
  result = (repoDir: repoDir, buildDir: buildDir, buildSubDir: buildSubDir,
    installDir: installDir, libDir: libDir, binDir: binDir)

proc runCmd*(a: string): int =
  ## a: command line string
  ## Executes the command and returns the exit code.
  var
    res: tuple[output: string, exitCode: int] = execCmdEx(a)
  if res.output.len > 0:
    echo res.output
  result = res.exitCode

proc hasLib*(a: string): bool =
  ## a: install directory
  ## Returns true when a liboqs library file exists.
  var
    candidates: seq[string] = @[]
    i: int = 0
    l: int = 0
  when defined(windows):
    candidates = @[
      joinPath(a, "lib", "liboqs.dll.a"),
      joinPath(a, "lib", "liboqs.a")
    ]
  elif defined(macosx):
    candidates = @[
      joinPath(a, "lib", "liboqs.dylib"),
      joinPath(a, "lib", "liboqs.a")
    ]
  else:
    candidates = @[
      joinPath(a, "lib", "liboqs.so"),
      joinPath(a, "lib", "liboqs.a")
    ]
  l = candidates.len
  while i < l:
    if fileExists(candidates[i]):
      result = true
      return
    inc i
  result = false

proc isPositiveResponse*(a: string): bool =
  var
    t: string = a.strip().toLowerAscii()
  result = t in ["y", "yes", "1", "true"]

proc promptOverwrite*(a: string): bool =
  var
    overwriteEnv: string = getEnv("LIBOQS_OVERWRITE_BUILD")
    response: string = ""
  if isPositiveResponse(overwriteEnv):
    return true
  if overwriteEnv.strip().len > 0:
    return false
  stdout.write("Existing liboqs build found at " & a & ". Overwrite with a new build? [y/N]: ")
  stdout.flushFile()
  try:
    response = stdin.readLine()
  except EOFError:
    echo ""
    return false
  result = isPositiveResponse(response)

proc removeExistingBuild*(a: tuple[repoDir: string, buildDir: string, buildSubDir: string,
    installDir: string, libDir: string, binDir: string]) =
  if dirExists(a.buildSubDir):
    removeDir(a.buildSubDir)
  if dirExists(a.installDir):
    removeDir(a.installDir)

proc main*() =
  ## Builds liboqs using CMake and installs into the build folder.
  var
    baseDir: string = findCryptoRepoDir()
    paths: tuple[repoDir: string, buildDir: string, buildSubDir: string, installDir: string,
      libDir: string, binDir: string] = buildPaths(baseDir)
    configureCmd: string = ""
    buildCmd: string = ""
    code: int = 0
    generator: string = ""
    ninjaPath: string = ""
    cachePath: string = ""
    cacheText: string = ""
    jobs: string = ""
    jobsArg: string = ""
  if not dirExists(paths.repoDir):
    echo "Repo not found: " & paths.repoDir
    quit(1)
  if hasLib(paths.installDir):
    if not promptOverwrite(paths.installDir):
      echo "liboqs already built: " & paths.installDir
      return
    removeExistingBuild(paths)
  createDir(paths.buildDir)
  createDir(paths.buildSubDir)
  createDir(paths.installDir)
  ninjaPath = findExe("ninja")
  if ninjaPath.len > 0:
    generator = "Ninja"
  else:
    generator = "Unix Makefiles"
  cachePath = joinPath(paths.buildSubDir, "CMakeCache.txt")
  if fileExists(cachePath):
    cacheText = readFile(cachePath)
    if cacheText.find("CMAKE_GENERATOR:INTERNAL=" & generator) < 0 and
        cacheText.find("CMAKE_GENERATOR:UNINITIALIZED=" & generator) < 0:
      removeDir(paths.buildSubDir)
      createDir(paths.buildSubDir)
  configureCmd = "cmake -S " & quoteShell(paths.repoDir) & " -B " &
    quoteShell(paths.buildSubDir) & " -G " & quoteShell(generator) &
    " -DCMAKE_BUILD_TYPE=Release" &
    " -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=ON" &
    " -DCMAKE_INSTALL_PREFIX=" & quoteShell(paths.installDir)
  when defined(windows):
    configureCmd = configureCmd & " -DCMAKE_C_COMPILER=gcc"
  code = runCmd(configureCmd)
  if code != 0:
    quit(code)
  jobs = getEnv("OQS_BUILD_JOBS")
  if jobs.len > 0:
    jobsArg = " --parallel " & jobs
  else:
    jobsArg = " --parallel"
  buildCmd = "cmake --build " & quoteShell(paths.buildSubDir) &
    " --target install" & jobsArg
  code = runCmd(buildCmd)
  if code != 0:
    quit(code)

when isMainModule:
  main()
