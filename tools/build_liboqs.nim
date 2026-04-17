import os
import osproc
import strutils

proc envOrDefault*(a, b: string): string =
  ## a: environment variable name
  ## b: fallback value
  ## Returns the environment override when set, otherwise the fallback.
  var
    t: string = getEnv(a).strip()
  if t.len > 0:
    result = t
  else:
    result = b

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
    repoDirDefault: string = if dirExists(joinPath(a, "submodules", "liboqs")):
        joinPath(a, "submodules", "liboqs")
      else:
        joinPath(parentDir(a), "liboqs")
    repoDir: string = envOrDefault("LIBOQS_SOURCE", repoDirDefault)
    buildDir: string = envOrDefault("LIBOQS_BUILD_ROOT", joinPath(a, "build", "liboqs"))
    buildSubDir: string = joinPath(buildDir, "build")
    installDir: string = joinPath(buildDir, "install")
    libDir: string = joinPath(installDir, "lib")
    binDir: string = joinPath(installDir, "bin")
  result = (repoDir: repoDir, buildDir: buildDir, buildSubDir: buildSubDir,
    installDir: installDir, libDir: libDir, binDir: binDir)

proc cmakeBoolArg*(a: string): string =
  ## a: environment boolean-like string
  ## Converts typical env booleans into a CMake ON/OFF value.
  var
    t: string = a.strip().toLowerAscii()
  if t in ["1", "on", "yes", "true", "y"]:
    result = "ON"
  else:
    result = "OFF"

proc writeProfileMetadata*(a: tuple[repoDir: string, buildDir: string, buildSubDir: string,
    installDir: string, libDir: string, binDir: string]) =
  ## a: resolved liboqs build/install paths
  ## Writes a small metadata file so runtime benchmarks can report the exact liboqs profile used.
  var
    profileName: string = envOrDefault("LIBOQS_PROFILE_NAME", "default")
    useOpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_OPENSSL", "OFF"))
    useAesOpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_AES_OPENSSL", useOpenSsl))
    useSha2OpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_SHA2_OPENSSL", useOpenSsl))
    useSha3OpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_SHA3_OPENSSL", "OFF"))
    distBuild: string = cmakeBoolArg(envOrDefault("LIBOQS_DIST_BUILD", "ON"))
    optTarget: string = envOrDefault("LIBOQS_OPT_TARGET", "auto")
    minimalBuild: string = envOrDefault("LIBOQS_MINIMAL_BUILD", "")
    generator: string = envOrDefault("LIBOQS_CMAKE_GENERATOR", "")
    cCompiler: string = getEnv("LIBOQS_CMAKE_C_COMPILER").strip()
    cCompilerArg1: string = getEnv("LIBOQS_CMAKE_C_COMPILER_ARG1").strip()
    cxxCompiler: string = getEnv("LIBOQS_CMAKE_CXX_COMPILER").strip()
    cxxCompilerArg1: string = getEnv("LIBOQS_CMAKE_CXX_COMPILER_ARG1").strip()
    asmCompiler: string = getEnv("LIBOQS_CMAKE_ASM_COMPILER").strip()
    asmCompilerArg1: string = getEnv("LIBOQS_CMAKE_ASM_COMPILER_ARG1").strip()
    extraCmakeArgs: string = getEnv("LIBOQS_EXTRA_CMAKE_ARGS").strip()
    metadataPath: string = joinPath(a.installDir, "tyr_liboqs_profile.txt")
    lines: seq[string] = @[]
  lines.add("profile_name=" & profileName)
  lines.add("repo_dir=" & a.repoDir)
  lines.add("build_root=" & a.buildDir)
  lines.add("install_dir=" & a.installDir)
  lines.add("oqs_use_openssl=" & useOpenSsl)
  lines.add("oqs_use_aes_openssl=" & useAesOpenSsl)
  lines.add("oqs_use_sha2_openssl=" & useSha2OpenSsl)
  lines.add("oqs_use_sha3_openssl=" & useSha3OpenSsl)
  lines.add("oqs_dist_build=" & distBuild)
  lines.add("oqs_opt_target=" & optTarget)
  lines.add("oqs_minimal_build=" & minimalBuild)
  lines.add("cmake_generator=" & generator)
  lines.add("cmake_c_compiler=" & cCompiler)
  lines.add("cmake_c_compiler_arg1=" & cCompilerArg1)
  lines.add("cmake_cxx_compiler=" & cxxCompiler)
  lines.add("cmake_cxx_compiler_arg1=" & cxxCompilerArg1)
  lines.add("cmake_asm_compiler=" & asmCompiler)
  lines.add("cmake_asm_compiler_arg1=" & asmCompilerArg1)
  lines.add("cmake_extra_args=" & extraCmakeArgs)
  writeFile(metadataPath, lines.join("\n") & "\n")

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
    useOpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_OPENSSL", "OFF"))
    useAesOpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_AES_OPENSSL", useOpenSsl))
    useSha2OpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_SHA2_OPENSSL", useOpenSsl))
    useSha3OpenSsl: string = cmakeBoolArg(envOrDefault("LIBOQS_USE_SHA3_OPENSSL", "OFF"))
    distBuild: string = cmakeBoolArg(envOrDefault("LIBOQS_DIST_BUILD", "ON"))
    optTarget: string = envOrDefault("LIBOQS_OPT_TARGET", "auto")
    minimalBuild: string = envOrDefault("LIBOQS_MINIMAL_BUILD", "")
    opensslRoot: string = getEnv("OPENSSL_ROOT_DIR").strip()
    generatorOverride: string = getEnv("LIBOQS_CMAKE_GENERATOR").strip()
    cCompiler: string = getEnv("LIBOQS_CMAKE_C_COMPILER").strip()
    cCompilerArg1: string = getEnv("LIBOQS_CMAKE_C_COMPILER_ARG1").strip()
    cxxCompiler: string = getEnv("LIBOQS_CMAKE_CXX_COMPILER").strip()
    cxxCompilerArg1: string = getEnv("LIBOQS_CMAKE_CXX_COMPILER_ARG1").strip()
    asmCompiler: string = getEnv("LIBOQS_CMAKE_ASM_COMPILER").strip()
    asmCompilerArg1: string = getEnv("LIBOQS_CMAKE_ASM_COMPILER_ARG1").strip()
    extraCmakeArgs: string = getEnv("LIBOQS_EXTRA_CMAKE_ARGS").strip()
  if not dirExists(paths.repoDir):
    echo "Repo not found: " & paths.repoDir
    quit(1)
  if hasLib(paths.installDir):
    if not promptOverwrite(paths.installDir):
      echo "liboqs already built: " & paths.installDir
      return
    removeExistingBuild(paths)
  elif isPositiveResponse(getEnv("LIBOQS_OVERWRITE_BUILD")) and
      (dirExists(paths.buildSubDir) or dirExists(paths.installDir)):
    removeExistingBuild(paths)
  createDir(paths.buildDir)
  createDir(paths.buildSubDir)
  createDir(paths.installDir)
  if generatorOverride.len > 0:
    generator = generatorOverride
  else:
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
    " -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON" &
    " -DOQS_USE_OPENSSL=" & useOpenSsl &
    " -DOQS_USE_AES_OPENSSL=" & useAesOpenSsl &
    " -DOQS_USE_SHA2_OPENSSL=" & useSha2OpenSsl &
    " -DOQS_USE_SHA3_OPENSSL=" & useSha3OpenSsl &
    " -DOQS_DIST_BUILD=" & distBuild &
    " -DOQS_OPT_TARGET=" & quoteShell(optTarget) &
    " -DCMAKE_INSTALL_PREFIX=" & quoteShell(paths.installDir)
  if minimalBuild.len > 0:
    configureCmd = configureCmd & " -DOQS_MINIMAL_BUILD=" & quoteShell(minimalBuild)
  if opensslRoot.len > 0:
    configureCmd = configureCmd & " -DOPENSSL_ROOT_DIR=" & quoteShell(opensslRoot)
  if cCompiler.len > 0:
    configureCmd = configureCmd & " -DCMAKE_C_COMPILER=" & quoteShell(cCompiler)
  elif defined(windows):
    configureCmd = configureCmd & " -DCMAKE_C_COMPILER=gcc"
  if cCompilerArg1.len > 0:
    configureCmd = configureCmd & " -DCMAKE_C_COMPILER_ARG1=" & quoteShell(cCompilerArg1)
  if cxxCompiler.len > 0:
    configureCmd = configureCmd & " -DCMAKE_CXX_COMPILER=" & quoteShell(cxxCompiler)
  if cxxCompilerArg1.len > 0:
    configureCmd = configureCmd & " -DCMAKE_CXX_COMPILER_ARG1=" & quoteShell(cxxCompilerArg1)
  if asmCompiler.len > 0:
    configureCmd = configureCmd & " -DCMAKE_ASM_COMPILER=" & quoteShell(asmCompiler)
  if asmCompilerArg1.len > 0:
    configureCmd = configureCmd & " -DCMAKE_ASM_COMPILER_ARG1=" & quoteShell(asmCompilerArg1)
  if extraCmakeArgs.len > 0:
    configureCmd = configureCmd & " " & extraCmakeArgs
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
  writeProfileMetadata(paths)

when isMainModule:
  main()
