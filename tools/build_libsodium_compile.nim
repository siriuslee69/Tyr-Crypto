proc compileSource*(a: string, b: string, c: string) =
  ## a: source file path
  ## b: output object path
  ## c: compiler flags
  var
    cmd: string = ""
    code: int = 0
  cmd = "gcc -c " & c & " -o " & quoteShell(b) & " " & quoteShell(a)
  code = runCmd(cmd)
  if code != 0:
    quit(code)

proc compileSources*(a: seq[tuple[path: string, flags: string]], b: string,
    c: string): seq[string] =
  ## a: sources with flags
  ## b: repo directory
  ## c: object directory
  ## Compiles sources and returns object file paths.
  var
    objList: seq[string] = @[]
    i: int = 0
    l: int = a.len
    objPath: string = ""
  while i < l:
    objPath = objectPathFromSource(a[i].path, b, c)
    objList.add objPath
    compileSource(a[i].path, objPath, a[i].flags)
    inc i
  result = objList

proc buildStaticLib*(a: seq[tuple[path: string, flags: string]], b: string, c: string,
    d: string, e: string) =
  ## a: sources with flags
  ## b: repo directory
  ## c: object directory
  ## d: lib directory
  ## e: stamp file path
  ## Compiles sources into a static libsodium library and writes a build stamp.
  var
    objs: seq[string] = @[]
    objArgs: string = ""
    i: int = 0
    l: int = 0
    libPath: string = joinPath(d, "libsodium.a")
    arCmd: string = ""
    code: int = 0
  createDir(c)
  createDir(d)
  objs = compileSources(a, b, c)
  l = objs.len
  while i < l:
    if i > 0:
      objArgs.add " "
    objArgs.add quoteShell(objs[i])
    inc i
  arCmd = "ar rcs " & quoteShell(libPath) & " " & objArgs
  code = runCmd(arCmd)
  if code != 0:
    quit(code)
  writeFile(e, libsodiumBuildStamp)

proc main*() =
  ## Builds an expanded libsodium static library for AEAD, hashing, and public-key primitives.
  var
    baseDir: string = findCryptoRepoDir()
    paths: tuple[repoDir: string, buildDir: string, installDir: string, libDir: string,
      binDir: string, objDir: string, memzeroShim: string, coreShim: string,
      stampPath: string] = buildPaths(baseDir)
    flags: tuple[base: string, sse: string, sse41: string, avx2: string, aes: string] =
      buildFlags(paths.repoDir)
    sources: seq[tuple[path: string, flags: string]] = @[]
  if not dirExists(paths.repoDir):
    echo "Repo not found: " & paths.repoDir
    quit(1)
  if hasLib(paths.installDir, paths.stampPath):
    echo "libsodium already built: " & paths.installDir
    return
  createDir(paths.buildDir)
  createDir(paths.installDir)
  ensureMemzeroShim(paths.memzeroShim)
  ensureCoreShim(paths.coreShim)
  sources = collectSources(paths.repoDir, flags, paths.memzeroShim, paths.coreShim)
  buildStaticLib(sources, paths.repoDir, paths.objDir, paths.libDir, paths.stampPath)
