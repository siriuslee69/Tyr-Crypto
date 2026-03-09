
when defined(hasLibOqs):
  import std/[os, osproc, strutils, terminal], ../helper
  const
    builderLibNames* = when defined(windows):
                         @["oqs.dll", "liboqs.dll"]
                       elif defined(macosx):
                         @["liboqs.dylib"]
                       else:
                         @["liboqs.so", "liboqs.so.4", "liboqs.so.5", "liboqs.so.9"]  

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

  proc findBuiltLibrary(buildDir: string): string =
    for libDir in [joinPath(buildDir, "lib"), joinPath(buildDir, "bin")]:
      for candidate in builderLibNames:
        let path = joinPath(libDir, candidate)
        if fileExists(path) or symlinkExists(path):
          return path
      for path in walkPattern(joinPath(libDir, "liboqs.so*")):
        return path
    ""

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
    let autoClone = getEnv("LIBOQS_AUTO_BUILD").strip().isPositive() or not isatty(stdin)
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
    if not response.isPositive():
      return false
    cloneLibOqsRepo(defaultRepo, absSource)

  proc buildLibOqs*(sourceDir: string): string =
    let absSource = absolutePath(sourceDir)
    if not ensureSourceDir(absSource):
      echo "liboqs source directory not available."
      return ""
    let buildDir = joinPath(absSource, "build")
    createDir(buildDir)
    if not runCmd("cmake", [
      "-S", absSource,
      "-B", buildDir,
      "-DBUILD_SHARED_LIBS=ON",
      "-DOQS_BUILD_ONLY_LIB=ON",
      "-DOQS_ENABLE_TESTS=OFF",
      "-DOQS_USE_OPENSSL=OFF",
      "-DCMAKE_BUILD_TYPE=Release"
    ]):
      return ""
    if not runCmd("cmake", ["--build", buildDir, "--target", "oqs", "--config", "Release"]):
      return ""
    let libPath = findBuiltLibrary(buildDir)
    if libPath.len == 0:
      echo "liboqs build succeeded but no shared library was found in ", buildDir
    else:
      echo "Built liboqs shared library at ", libPath
    libPath

  proc autoBuildLibOqs*(extraCandidates: var seq[string], defaultSource: string): bool =
    var src = defaultSource.strip()
    if src.len == 0:
      src = joinPath(getCurrentDir(), "..", "liboqs")
    let builtPath = buildLibOqs(src)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true

  proc promptAndBuildLibOqs*(extraCandidates: var seq[string], defaultSource: string): bool =
    let autoBuild = getEnv("LIBOQS_AUTO_BUILD").strip().isPositive() or not isatty(stdin)
    if autoBuild:
      return autoBuildLibOqs(extraCandidates, defaultSource)
    echo "liboqs shared library not found."
    stdout.write("Attempt to build liboqs from source? [y/N]: ")
    stdout.flushFile()
    var response: string
    try:
      response = stdin.readLine()
    except EOFError:
      echo ""
      return false
    if not response.isPositive():
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
    let builtPath = buildLibOqs(src)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true
else:
  proc promptAndBuildLibOqs*(extraCandidates: var seq[string], defaultSource: string): bool =
    discard extraCandidates
    discard defaultSource
    false
