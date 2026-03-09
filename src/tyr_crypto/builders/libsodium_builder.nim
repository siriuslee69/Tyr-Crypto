when defined(hasLibsodium):
  import std/[os, osproc, strutils]

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
    let shellSource = toShellPath(absSource)
    let shellInstall = toShellPath(installDir)
    let cmd = "cd " & quoteShell(shellSource) &
      " && zig build -Dshared=true -Dstatic=false -Dtest=false -p " & quoteShell(shellInstall)
    runCmd(shellCmd, ["-c", cmd])

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

  proc buildLibsodium*(sourceDir: string): string =
    let
      absSource = absolutePath(sourceDir)
      zigInstallDir = joinPath(absSource, "zig-out")
      cmakeBuildDir = joinPath(absSource, "build")
      cmakeInstallDir = joinPath(absSource, "build", "install")
      autotoolsInstallDir = joinPath(absSource, "build", "install")
    if not ensureSourceDir(absSource):
      echo "libsodium source directory not available."
      return ""
    if findExe("zig").len > 0:
      if not buildWithZig(absSource, zigInstallDir):
        return ""
      let libPath = findBuiltLibrary(zigInstallDir)
      if libPath.len == 0:
        echo "libsodium build succeeded but no shared library was found in " & zigInstallDir
      else:
        echo "Built libsodium shared library at " & libPath
      return libPath
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

  proc autoBuildLibsodium*(extraCandidates: var seq[string], defaultSource: string): bool =
    var src = defaultSource.strip()
    if src.len == 0:
      src = joinPath(getCurrentDir(), "..", "libsodium")
    let builtPath = buildLibsodium(src)
    if builtPath.len == 0:
      return false
    extraCandidates.insert(builtPath, 0)
    true
else:
  proc autoBuildLibsodium*(extraCandidates: var seq[string], defaultSource: string): bool =
    discard extraCandidates
    discard defaultSource
    false
