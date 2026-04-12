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

proc buildPaths*(a: string): tuple[repoDir: string, buildDir: string, sourceDir: string,
    installDir: string, libDir: string, binDir: string] =
  ## a: crypto repo base directory
  ## Builds OpenSSL repo and build paths.
  var
    repoDir: string = if dirExists(joinPath(a, "submodules", "openssl")):
        joinPath(a, "submodules", "openssl")
      else:
        joinPath(parentDir(a), "openssl")
    buildDir: string = joinPath(a, "build", "openssl")
    sourceDir: string = joinPath(buildDir, "src")
    installDir: string = joinPath(buildDir, "install")
    libDir: string = joinPath(installDir, "lib")
    binDir: string = joinPath(installDir, "bin")
  result = (repoDir: repoDir, buildDir: buildDir, sourceDir: sourceDir,
    installDir: installDir, libDir: libDir, binDir: binDir)

proc runCmd*(a: string): int =
  ## a: command line string
  ## Executes the command and returns the exit code.
  var
    res: tuple[output: string, exitCode: int] = execCmdEx(a)
  if res.output.len > 0:
    echo res.output
  result = res.exitCode

proc runCmdInDir*(a: string, b: string): int =
  ## a: command line string
  ## b: working directory
  ## Runs a command in a specific working directory.
  var
    oldDir: string = getCurrentDir()
    code: int = 0
  setCurrentDir(b)
  code = runCmd(a)
  setCurrentDir(oldDir)
  result = code

proc hasLib*(a: string): bool =
  ## a: install directory
  ## Returns true when a libcrypto library file exists.
  var
    candidates: seq[string] = @[]
    i: int = 0
    l: int = 0
  when defined(windows):
    candidates = @[
      joinPath(a, "lib", "libcrypto.dll.a"),
      joinPath(a, "lib", "libcrypto.a"),
      joinPath(a, "lib64", "libcrypto.dll.a"),
      joinPath(a, "lib64", "libcrypto.a")
    ]
  elif defined(macosx):
    candidates = @[
      joinPath(a, "lib", "libcrypto.dylib"),
      joinPath(a, "lib", "libcrypto.a"),
      joinPath(a, "lib64", "libcrypto.dylib"),
      joinPath(a, "lib64", "libcrypto.a")
    ]
  else:
    candidates = @[
      joinPath(a, "lib", "libcrypto.so"),
      joinPath(a, "lib", "libcrypto.a"),
      joinPath(a, "lib64", "libcrypto.so"),
      joinPath(a, "lib64", "libcrypto.a")
    ]
  l = candidates.len
  while i < l:
    if fileExists(candidates[i]):
      result = true
      return
    inc i
  result = false

proc ensureSourceCopy*(a: string, b: string) =
  ## a: OpenSSL repo directory
  ## b: build source directory
  ## Copies the OpenSSL repo into the build folder when missing.
  var
    configPath: string = joinPath(b, "Configure")
  if dirExists(b) and fileExists(configPath):
    return
  if dirExists(b):
    echo "OpenSSL source exists but is incomplete: " & b
    echo "Remove the folder manually if you want a fresh copy."
    quit(1)
  copyDir(a, b)

proc ensureExecutable*(a: string) =
  ## a: file path
  ## Ensures the file is marked as executable on Unix.
  when not defined(windows):
    var
      perms: set[FilePermission] = {}
    if not fileExists(a):
      return
    perms = getFilePermissions(a)
    if fpUserExec notin perms:
      perms.incl(fpUserExec)
      perms.incl(fpGroupExec)
      perms.incl(fpOthersExec)
      setFilePermissions(a, perms)

proc patchUnixChecker*(a: string) =
  ## a: unix-checker.pm path
  ## Skips the Unix path check when using MSWin32 perl.
  var
    text: string = ""
    oldLine: string = "if (rel2abs('.') !~ m|/|) {"
    newLine: string = "if (rel2abs('.') !~ m|/| && $^O ne 'MSWin32') {"
  if not fileExists(a):
    return
  text = readFile(a)
  if text.contains(newLine):
    return
  if text.contains(oldLine):
    text = text.replace(oldLine, newLine)
    writeFile(a, text)

proc patchMakefileForWindows*(a: string) =
  ## a: Makefile path
  ## Rewrites CC="$(CC)" perl invocations for cmd.exe compatibility.
  var
    text: string = ""
    oldToken: string = "CC=\"$(CC)\" $(PERL)"
    newToken: string = "set CC=$(CC) && $(PERL)"
    rmToken: string = "rm -f "
    delToken: string = "del /f /q "
  if not fileExists(a):
    return
  text = readFile(a)
  text = text.replace(oldToken, newToken)
  text = text.replace(rmToken, delToken)
  writeFile(a, text)

proc toForwardSlashes*(a: string): string =
  ## a: input path
  ## Converts Windows backslashes to forward slashes.
  result = a.replace("\\", "/")

proc buildConfigureCmd*(a: string): string =
  ## a: install directory
  ## Builds the OpenSSL Configure or config command.
  var
    sslDir: string = joinPath(a, "ssl")
    cmd: string = ""
    prefixPath: string = ""
    sslPath: string = ""
  when defined(windows):
    prefixPath = toForwardSlashes(a)
    sslPath = toForwardSlashes(sslDir)
    cmd = "perl Configure mingw64 no-shared no-tests --prefix=" & quoteShell(prefixPath) &
      " --openssldir=" & quoteShell(sslPath)
  else:
    cmd = "./config no-shared no-tests --prefix=" & quoteShell(a) &
      " --openssldir=" & quoteShell(sslDir)
  result = cmd

proc buildMakeCmd*(): string =
  ## Returns the make command for the current platform.
  var
    cmd: string = ""
  when defined(windows):
    cmd = "mingw32-make RM=" & quoteShell("del /f /q")
  else:
    cmd = "make"
  result = cmd

proc main*() =
  ## Builds OpenSSL and installs it into the build folder.
  var
    baseDir: string = findCryptoRepoDir()
    paths: tuple[repoDir: string, buildDir: string, sourceDir: string, installDir: string,
      libDir: string, binDir: string] = buildPaths(baseDir)
    configureCmd: string = ""
    makeCmd: string = ""
    installCmd: string = ""
    checkerPath: string = ""
    code: int = 0
  if not dirExists(paths.repoDir):
    echo "Repo not found: " & paths.repoDir
    quit(1)
  if hasLib(paths.installDir):
    echo "OpenSSL already built: " & paths.installDir
    return
  createDir(paths.buildDir)
  createDir(paths.installDir)
  ensureSourceCopy(paths.repoDir, paths.sourceDir)
  ensureExecutable(joinPath(paths.sourceDir, "config"))
  ensureExecutable(joinPath(paths.sourceDir, "Configure"))
  when defined(windows):
    checkerPath = joinPath(paths.sourceDir, "Configurations", "unix-checker.pm")
    patchUnixChecker(checkerPath)
  configureCmd = buildConfigureCmd(paths.installDir)
  code = runCmdInDir(configureCmd, paths.sourceDir)
  if code != 0:
    quit(code)
  when defined(windows):
    patchMakefileForWindows(joinPath(paths.sourceDir, "Makefile"))
  makeCmd = buildMakeCmd()
  code = runCmdInDir(makeCmd, paths.sourceDir)
  if code != 0:
    quit(code)
  installCmd = makeCmd & " install_sw"
  code = runCmdInDir(installCmd, paths.sourceDir)
  if code != 0:
    quit(code)

when isMainModule:
  main()
