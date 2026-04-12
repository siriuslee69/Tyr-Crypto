when defined(hasLibsodium):
  import std/[os, osproc, strutils, terminal]
  when defined(windows):
    import ./libsodium_zigcc_windows

  const
    builderLibNames* = when defined(windows):
                         @["libsodium.dll"]
                       elif defined(macosx):
                         @["libsodium.dylib"]
                       else:
                         @["libsodium.so", "libsodium.so.23", "libsodium.so.24"]
    shellCmd = when defined(windows):
                 "sh"
               else:
                 "/bin/sh"
    moduleDir = splitFile(currentSourcePath()).dir

  proc repoRoot(): string =
    absolutePath(joinPath(moduleDir, "..", "..", ".."))

  proc defaultSourceDir(): string =
    let envSource = getEnv("LIBSODIUM_SOURCE").strip()
    if envSource.len > 0:
      return envSource
    let submoduleDir = joinPath(repoRoot(), "submodules", "libsodium")
    if dirExists(submoduleDir):
      return submoduleDir
    joinPath(parentDir(repoRoot()), "libsodium")

  proc defaultBuildRoot(): string =
    let envBuild = getEnv("LIBSODIUM_BUILD_ROOT").strip()
    if envBuild.len > 0:
      return envBuild
    joinPath(repoRoot(), "build", "libsodium")

  proc isPositiveResponse(s: string): bool =
    let trimmed = s.strip().toLowerAscii()
    result = trimmed in ["y", "yes", "1", "true"]

  proc toShellPath(p: string): string =
    when defined(windows):
      result = p.replace('\\', '/')
    else:
      result = p

  proc quoteShellCommand(cmd: string, args: openArray[string]): string =
    let command = quoteShell(cmd)
    result = command
    for arg in args:
      result.add(' ')
      result.add(quoteShell(arg))

  proc runCmd(cmd: string, args: openArray[string], workDir: string = ""): bool =
    let command = quoteShellCommand(cmd, args)
    echo "-> ", command
    let (output, code) =
      if workDir.len > 0:
        execCmdEx(command, options = {poUsePath, poStdErrToStdOut}, workingDir = workDir)
      else:
        execCmdEx(command, options = {poUsePath, poStdErrToStdOut})
    if output.len > 0:
      echo output
    if code != 0:
      echo "Command failed with exit code ", code
      return false
    true

  proc findBuiltLibrary*(installDir: string): string =
    for libDir in [joinPath(installDir, "lib"), joinPath(installDir, "bin")]:
      for name in builderLibNames:
        let libPath = joinPath(libDir, name)
        if fileExists(libPath) or symlinkExists(libPath):
          return libPath
    ""

  proc cloneLibsodiumRepo*(repoUrl: string, destDir: string): bool =
    if dirExists(destDir):
      return true
    echo "Cloning libsodium repository from ", repoUrl
    runCmd("git", ["clone", "--depth", "1", repoUrl, destDir])

  proc ensureSourceDir*(sourceDir: string): bool =
    let absSource = absolutePath(sourceDir)
    if dirExists(absSource):
      return true
    let defaultRepo = "https://github.com/jedisct1/libsodium.git"
    cloneLibsodiumRepo(defaultRepo, absSource)

  proc buildWithZig(absSource, installDir: string): bool =
    createDir(installDir)
    runCmd("zig", [
      "build",
      "--global-cache-dir", joinPath(parentDir(installDir), "zig-global-cache"),
      "--cache-dir", joinPath(parentDir(installDir), "zig-local-cache"),
      "-Dshared=true",
      "-Dstatic=false",
      "-Dtest=false",
      "-p", installDir
    ], absSource)

  proc buildWithCmake(absSource, buildDir, installDir: string): bool =
    createDir(buildDir)
    createDir(installDir)
    if not runCmd("cmake", [
      "-S", absSource,
      "-B", buildDir,
      "-DBUILD_SHARED_LIBS=ON",
      "-DSODIUM_STATIC=OFF",
      "-DCMAKE_BUILD_TYPE=Release",
      "-DCMAKE_INSTALL_PREFIX=" & installDir
    ]):
      return false
    if not runCmd("cmake", ["--build", buildDir, "--config", "Release"]):
      return false
    if not runCmd("cmake", ["--install", buildDir, "--config", "Release"]):
      return false
    true

  proc buildWithAutotools(absSource, installDir: string): bool =
    createDir(installDir)
    let shellSource = toShellPath(absSource)
    let shellInstall = toShellPath(installDir)
    if not fileExists(joinPath(absSource, "configure")):
      if findExe("autoreconf").len == 0:
        echo "autoreconf not found; install autotools to generate configure."
        return false
      let autogenCmd = "cd " & quoteShell(shellSource) & " && ./autogen.sh"
      if not runCmd(shellCmd, ["-c", autogenCmd]):
        return false
      if not fileExists(joinPath(absSource, "configure")):
        echo "configure script not generated after autogen.sh."
        return false
    let configureCmd = "cd " & quoteShell(shellSource) & " && ./configure --prefix=" & quoteShell(shellInstall) &
      " --enable-shared --disable-static"
    if not runCmd(shellCmd, ["-c", configureCmd]):
      return false
    let makeCmd = "cd " & quoteShell(shellSource) & " && make"
    if not runCmd(shellCmd, ["-c", makeCmd]):
      return false
    let installCmd = "cd " & quoteShell(shellSource) & " && make install"
    if not runCmd(shellCmd, ["-c", installCmd]):
      return false
    true

  proc buildLibsodium*(sourceDir: string, buildRoot: string = ""): string =
    let
      absSource = absolutePath(sourceDir)
      absBuildRoot = if buildRoot.len > 0: absolutePath(buildRoot) else: absolutePath(defaultBuildRoot())
      zigInstallDir = joinPath(absBuildRoot, "install")
      cmakeBuildDir = joinPath(absBuildRoot, "build")
      cmakeInstallDir = joinPath(absBuildRoot, "install")
      autotoolsInstallDir = joinPath(absBuildRoot, "install")
    if not ensureSourceDir(absSource):
      echo "libsodium source directory not available."
      return ""
    createDir(absBuildRoot)
    if findExe("zig").len > 0:
      if buildWithZig(absSource, zigInstallDir):
        let libPath = findBuiltLibrary(zigInstallDir)
        if libPath.len == 0:
          echo "libsodium build succeeded but no shared library was found in " & zigInstallDir
        else:
          echo "Built libsodium shared library at " & libPath
        return libPath
      echo "zig-based libsodium build failed; trying fallback builders."
      when defined(windows):
        let fallbackPath = buildLibsodiumSharedWithZigCc(absSource, absBuildRoot)
        if fallbackPath.len > 0:
          echo "Built libsodium shared library at " & fallbackPath
          return fallbackPath
        echo "zig cc fallback build failed; trying remaining fallback builders."
    if fileExists(joinPath(absSource, "CMakeLists.txt")):
      if not buildWithCmake(absSource, cmakeBuildDir, cmakeInstallDir):
        return ""
      let libPath = findBuiltLibrary(cmakeInstallDir)
      if libPath.len == 0:
        echo "libsodium build succeeded but no shared library was found in " & cmakeInstallDir
      else:
        echo "Built libsodium shared library at " & libPath
      return libPath
    if not buildWithAutotools(absSource, autotoolsInstallDir):
      return ""
    let libPath = findBuiltLibrary(autotoolsInstallDir)
    if libPath.len == 0:
      echo "libsodium build succeeded but no shared library was found in " & autotoolsInstallDir
    else:
      echo "Built libsodium shared library at " & libPath
    libPath

  proc autoBuildLibsodium*(extraCandidates: var seq[string], defaultSource: string,
      buildRoot: string = ""): bool =
    var src = defaultSource.strip()
    if src.len == 0:
      src = defaultSourceDir()
    let builtPath = buildLibsodium(src, buildRoot)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true

  proc promptAndBuildLibsodium*(extraCandidates: var seq[string], defaultSource: string,
      buildRoot: string = ""): bool =
    let autoBuild = isPositiveResponse(getEnv("LIBSODIUM_AUTO_BUILD")) or not isatty(stdin)
    if autoBuild:
      return autoBuildLibsodium(extraCandidates, defaultSource, buildRoot)
    echo "libsodium shared library not found."
    stdout.write("Attempt to build libsodium from source? [y/N]: ")
    stdout.flushFile()
    var response: string
    try:
      response = stdin.readLine()
    except EOFError:
      echo ""
      return false
    if not isPositiveResponse(response):
      return false
    stdout.write("Enter libsodium source directory (default: " & defaultSource & "): ")
    stdout.flushFile()
    var src: string
    try:
      src = stdin.readLine()
    except EOFError:
      echo ""
      return false
    src = src.strip()
    if src.len == 0:
      src = defaultSource
    let builtPath = buildLibsodium(src, buildRoot)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true
else:
  proc autoBuildLibsodium*(extraCandidates: var seq[string], defaultSource: string,
      buildRoot: string = ""): bool =
    discard extraCandidates
    discard defaultSource
    discard buildRoot
    false

  proc promptAndBuildLibsodium*(extraCandidates: var seq[string], defaultSource: string,
      buildRoot: string = ""): bool =
    discard extraCandidates
    discard defaultSource
    discard buildRoot
    false
