when defined(hasOpenSSL3):
  import std/[os, osproc, strutils, terminal], ../helper

  const
    builderLibNames* = when defined(windows):
                         @["libcrypto-3-x64.dll"]
                       elif defined(macosx):
                         @["libcrypto.3.dylib", "libcrypto.dylib"]
                       else:
                         @["libcrypto.so.3", "libcrypto.so"]

  proc quoteShellCommand(cmd: string, args: openArray[string]): string =
    let command = quoteShell(cmd)
    result = command
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

  proc findBuiltLibrary*(installDir: string): string =
    for name in builderLibNames:
      let libPath = joinPath(installDir, "lib", name)
      if fileExists(libPath) or symlinkExists(libPath):
        return libPath
    ""

  proc cloneOpenSslRepo*(repoUrl: string, destDir: string): bool =
    if dirExists(destDir):
      return true
    echo "Cloning OpenSSL repository from ", repoUrl
    runCmd("git", ["clone", "--depth", "1", repoUrl, destDir])

  proc promptClone(defaultRepo, destDir: string): bool =
    stdout.write("OpenSSL source directory not found. Clone from " & defaultRepo & "? [y/N]: ")
    stdout.flushFile()
    var response: string
    try:
      response = stdin.readLine()
    except EOFError:
      echo ""
      return false
    if not response.isPositive():
      return false
    cloneOpenSslRepo(defaultRepo, destDir)

  proc ensureSourceDir*(sourceDir: string): bool =
    let absSource = absolutePath(sourceDir)
    if dirExists(absSource):
      return true
    let defaultRepo = "https://github.com/openssl/openssl.git"
    promptClone(defaultRepo, absSource)

  proc configureOpenSsl(absSource, installDir: string): bool =
    createDir(installDir)
    runCmd("perl", [
      joinPath(absSource, "Configure"),
      "--prefix=" & installDir,
      "--libdir=lib",
      "shared",
      "no-tests"
    ])

  proc compileOpenSsl(absSource: string): bool =
    runCmd("make", ["-C", absSource])

  proc installOpenSsl(absSource: string): bool =
    runCmd("make", ["-C", absSource, "install_sw"])

  proc buildOpenSsl*(sourceDir: string): string =
    let
      absSource = absolutePath(sourceDir)
      installDir = joinPath(absSource, "build", "install")
    if not ensureSourceDir(absSource):
      echo "OpenSSL source directory not available."
      return ""
    if not configureOpenSsl(absSource, installDir):
      return ""
    if not compileOpenSsl(absSource):
      return ""
    if not installOpenSsl(absSource):
      return ""
    let libPath = findBuiltLibrary(installDir)
    if libPath.len == 0:
      echo "OpenSSL build succeeded but no shared library was found in ", installDir
    else:
      echo "Built OpenSSL shared library at ", libPath
    libPath

  proc promptAndBuildOpenSsl*(extraCandidates: var seq[string], defaultSource: string): bool =
    if not isatty(stdin):
      echo "OpenSSL shared library unavailable and interactive prompt is disabled."
      return false
    echo "OpenSSL shared library not found."
    stdout.write("Attempt to build OpenSSL from source? [y/N]: ")
    stdout.flushFile()
    var response: string
    try:
      response = stdin.readLine()
    except EOFError:
      echo ""
      return false
    if not response.isPositive():
      return false
    stdout.write("Enter OpenSSL source directory (default: " & defaultSource & "): ")
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
    let builtPath = buildOpenSsl(src)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true
else:
  proc promptAndBuildOpenSsl*(extraCandidates: var seq[string], defaultSource: string): bool =
    discard extraCandidates
    discard defaultSource
    false
