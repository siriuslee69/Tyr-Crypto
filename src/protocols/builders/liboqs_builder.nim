
when defined(hasLibOqs):
  import std/[os, osproc, strutils, terminal]
  const
    builderLibNames* = when defined(windows):
                         @["oqs.dll", "liboqs.dll"]
                       elif defined(macosx):
                         @["liboqs.dylib"]
                       else:
                         @["liboqs.so", "liboqs.so.4", "liboqs.so.5", "liboqs.so.9"]  
    moduleDir = splitFile(currentSourcePath()).dir

  proc repoRoot(): string =
    absolutePath(joinPath(moduleDir, "..", "..", ".."))

  proc defaultSourceDir(): string =
    let envSource = getEnv("LIBOQS_SOURCE").strip()
    if envSource.len > 0:
      return envSource
    let submoduleDir = joinPath(repoRoot(), "submodules", "liboqs")
    if dirExists(submoduleDir):
      return submoduleDir
    joinPath(parentDir(repoRoot()), "liboqs")

  proc defaultBuildRoot(): string =
    let envBuild = getEnv("LIBOQS_BUILD_ROOT").strip()
    if envBuild.len > 0:
      return envBuild
    joinPath(repoRoot(), "build", "liboqs")

  proc isPositiveResponse(s: string): bool =
    let trimmed = s.strip().toLowerAscii()
    result = trimmed in ["y", "yes", "1", "true"]

  proc quoteShellCommand(cmd: string, args: openArray[string]): string =
    result = quoteShell(cmd)
    for arg in args:
      result.add(' ')
      result.add(quoteShell(arg))

  proc runCmd(cmd: string, args: openArray[string]): bool =
    let command = quoteShellCommand(cmd, args)
    echo "-> ", command
    let (output, code) = execCmdEx(command, options = {poUsePath, poStdErrToStdOut})
    if output.len > 0:
      echo output
    if code != 0:
      echo "Command failed with exit code ", code
      return false
    true

  proc findBuiltLibrary*(buildRoot: string): string =
    for libDir in [
      joinPath(buildRoot, "install", "lib"),
      joinPath(buildRoot, "install", "bin"),
      joinPath(buildRoot, "lib"),
      joinPath(buildRoot, "bin")
    ]:
      for candidate in builderLibNames:
        let path = joinPath(libDir, candidate)
        if fileExists(path) or symlinkExists(path):
          return path
      for path in walkPattern(joinPath(libDir, "liboqs.so*")):
        return path
    ""

  proc removeExistingBuild*(buildRoot: string) =
    var
      buildDir: string = joinPath(buildRoot, "build")
      installDir: string = joinPath(buildRoot, "install")
      libDir: string = joinPath(buildRoot, "lib")
      binDir: string = joinPath(buildRoot, "bin")
    if dirExists(buildDir):
      removeDir(buildDir)
    if dirExists(installDir):
      removeDir(installDir)
    if dirExists(libDir):
      removeDir(libDir)
    if dirExists(binDir):
      removeDir(binDir)

  proc shouldOverwriteExistingBuild*(buildRoot: string, libPath: string,
      explicitPrompt: bool = false): bool =
    var
      overwriteEnv: string = getEnv("LIBOQS_OVERWRITE_BUILD").strip()
      autoBuild: bool = isPositiveResponse(getEnv("LIBOQS_AUTO_BUILD")) or not isatty(stdin)
      response: string = ""
    if isPositiveResponse(overwriteEnv):
      return true
    if overwriteEnv.len > 0:
      return false
    if explicitPrompt and not isatty(stdin):
      echo "Existing liboqs build found at ", libPath
      echo "Noninteractive run cannot ask for overwrite. Reusing existing liboqs build."
      echo "Set LIBOQS_OVERWRITE_BUILD=yes to force a rebuild."
      return false
    if autoBuild:
      echo "Existing liboqs build found at ", libPath
      echo "Reusing existing liboqs build. Set LIBOQS_OVERWRITE_BUILD=yes to rebuild."
      return false
    echo "Existing liboqs build found at ", libPath
    stdout.write("Overwrite existing liboqs build with a new one? [y/N]: ")
    stdout.flushFile()
    try:
      response = stdin.readLine()
    except EOFError:
      echo ""
      return false
    result = isPositiveResponse(response)

  proc cloneLibOqsRepo*(repoUrl: string, destDir: string): bool =
    if dirExists(destDir):
      return true
    echo "Cloning liboqs repository from ", repoUrl
    if not runCmd("git", ["clone", "--depth", "1", repoUrl, destDir]):
      return false
    true

  proc ensureSourceDir*(sourceDir: string): bool =
    let absSource = absolutePath(sourceDir)
    if dirExists(absSource):
      return true
    let defaultRepo = "https://github.com/open-quantum-safe/liboqs.git"
    let autoClone = isPositiveResponse(getEnv("LIBOQS_AUTO_BUILD")) or not isatty(stdin)
    if autoClone:
      return cloneLibOqsRepo(defaultRepo, absSource)
    stdout.write("liboqs source directory not found. Clone from " & defaultRepo & "? [y/N]: ")
    stdout.flushFile()
    var response: string
    try:
      response = stdin.readLine()
    except EOFError:
      echo ""
      return false
    if not isPositiveResponse(response):
      return false
    cloneLibOqsRepo(defaultRepo, absSource)

  proc buildLibOqs*(sourceDir: string, buildRoot: string = ""): string

  proc buildLibOqs*(sourceDir: string, buildRoot: string = ""): string =
    let absSource = absolutePath(sourceDir)
    let absBuildRoot =
      if buildRoot.len > 0: absolutePath(buildRoot)
      else: absolutePath(defaultBuildRoot())
    var
      existingLib: string = ""
    if not ensureSourceDir(absSource):
      echo "liboqs source directory not available."
      return ""
    existingLib = findBuiltLibrary(absBuildRoot)
    if existingLib.len > 0:
      if not shouldOverwriteExistingBuild(absBuildRoot, existingLib):
        return existingLib
      removeExistingBuild(absBuildRoot)
    let buildDir = joinPath(absBuildRoot, "build")
    let installDir = joinPath(absBuildRoot, "install")
    createDir(absBuildRoot)
    createDir(buildDir)
    createDir(installDir)
    if not runCmd("cmake", [
      "-S", absSource,
      "-B", buildDir,
      "-DBUILD_SHARED_LIBS=ON",
      "-DOQS_BUILD_ONLY_LIB=ON",
      "-DOQS_ENABLE_TESTS=OFF",
      "-DOQS_USE_OPENSSL=OFF",
      "-DCMAKE_BUILD_TYPE=Release",
      "-DCMAKE_INSTALL_PREFIX=" & installDir
    ]):
      return ""
    if not runCmd("cmake", ["--build", buildDir, "--target", "install", "--config", "Release"]):
      return ""
    let libPath = findBuiltLibrary(absBuildRoot)
    if libPath.len == 0:
      echo "liboqs build succeeded but no shared library was found in ", absBuildRoot
    else:
      echo "Built liboqs shared library at ", libPath
    libPath

  proc promptReuseOrRebuildLibOqs*(sourceDir: string, buildRoot: string): string =
    var
      absBuildRoot: string = absolutePath(buildRoot)
      existingLib: string = findBuiltLibrary(absBuildRoot)
    if existingLib.len == 0:
      return ""
    if not shouldOverwriteExistingBuild(absBuildRoot, existingLib, true):
      return existingLib
    removeExistingBuild(absBuildRoot)
    result = buildLibOqs(sourceDir, absBuildRoot)

  proc autoBuildLibOqs*(extraCandidates: var seq[string], defaultSource: string,
      buildRoot: string = ""): bool =
    var src = defaultSource.strip()
    if src.len == 0:
      src = defaultSourceDir()
    let builtPath = buildLibOqs(src, buildRoot)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true

  proc promptAndBuildLibOqs*(extraCandidates: var seq[string], defaultSource: string,
      buildRoot: string = ""): bool =
    let autoBuild = isPositiveResponse(getEnv("LIBOQS_AUTO_BUILD")) or not isatty(stdin)
    if autoBuild:
      return autoBuildLibOqs(extraCandidates, defaultSource, buildRoot)
    echo "liboqs shared library not found."
    stdout.write("Attempt to build liboqs from source? [y/N]: ")
    stdout.flushFile()
    var response: string
    try:
      response = stdin.readLine()
    except EOFError:
      echo ""
      return false
    if not isPositiveResponse(response):
      return false
    stdout.write("Enter liboqs source directory (default: " & defaultSource & "): ")
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
    let builtPath = buildLibOqs(src, buildRoot)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true
else:
  proc promptReuseOrRebuildLibOqs*(sourceDir: string, buildRoot: string): string =
    discard sourceDir
    discard buildRoot
    ""

  proc promptAndBuildLibOqs*(extraCandidates: var seq[string], defaultSource: string): bool =
    discard extraCandidates
    discard defaultSource
    false
