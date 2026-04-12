import os
import osproc
import strutils

const
  libsodiumBuildStamp = "libsodium-extended-v2"

proc findCryptoRepoDir*(): string =
  ## Returns the crypto repo base directory based on this file's location.
  var
    sourceFile: string = currentSourcePath()
    sourceDir: string = ""
    baseDir: string = ""
  sourceDir = splitFile(sourceFile).dir
  baseDir = parentDir(sourceDir)
  result = baseDir

proc buildPaths*(a: string): tuple[repoDir: string, buildDir: string, installDir: string,
    libDir: string, binDir: string, objDir: string, memzeroShim: string, coreShim: string,
    stampPath: string] =
  ## a: crypto repo base directory
  ## Builds libsodium repo and build paths.
  var
    repoDir: string = if dirExists(joinPath(a, "submodules", "libsodium")):
        joinPath(a, "submodules", "libsodium")
      else:
        joinPath(parentDir(a), "libsodium")
    buildDir: string = joinPath(a, "build", "libsodium")
    installDir: string = joinPath(buildDir, "install")
    libDir: string = joinPath(installDir, "lib")
    binDir: string = joinPath(installDir, "bin")
    objDir: string = joinPath(buildDir, "obj")
    memzeroShim: string = joinPath(buildDir, "sodium_memzero_shim.c")
    coreShim: string = joinPath(buildDir, "sodium_core_shim.c")
    stampPath: string = joinPath(buildDir, "libsodium_build.stamp")
  result = (repoDir: repoDir, buildDir: buildDir, installDir: installDir, libDir: libDir,
    binDir: binDir, objDir: objDir, memzeroShim: memzeroShim, coreShim: coreShim,
    stampPath: stampPath)

proc runCmd*(a: string): int =
  ## a: command line string
  ## Executes the command and returns the exit code.
  var
    res: tuple[output: string, exitCode: int] = execCmdEx(a)
  if res.output.len > 0:
    echo res.output
  result = res.exitCode

proc hasLib*(a: string, b: string): bool =
  ## a: install directory
  ## b: stamp file path
  ## Returns true when a libsodium library file exists and the build stamp matches.
  var
    candidates: seq[string] = @[]
    i: int = 0
    l: int = 0
    stampText: string = ""
  if not fileExists(b):
    result = false
    return
  stampText = readFile(b).strip()
  if stampText != libsodiumBuildStamp:
    result = false
    return
  when defined(windows):
    candidates = @[
      joinPath(a, "lib", "libsodium.dll.a"),
      joinPath(a, "lib", "libsodium.a")
    ]
  elif defined(macosx):
    candidates = @[
      joinPath(a, "lib", "libsodium.dylib"),
      joinPath(a, "lib", "libsodium.a")
    ]
  else:
    candidates = @[
      joinPath(a, "lib", "libsodium.so"),
      joinPath(a, "lib", "libsodium.a")
    ]
  l = candidates.len
  while i < l:
    if fileExists(candidates[i]):
      result = true
      return
    inc i
  result = false

proc ensureMemzeroShim*(a: string) =
  ## a: shim C file path
  ## Writes a minimal sodium_memzero implementation when missing.
  var
    text: string = ""
  if fileExists(a):
    return
  text = "/* Minimal libsodium shim for sodium_memzero. */\n" &
    "#include <stddef.h>\n" &
    "#include <stdint.h>\n" &
    "#include \"sodium/utils.h\"\n\n" &
    "void sodium_memzero(void * const pnt, const size_t len) {\n" &
    "    volatile unsigned char *volatile p = (volatile unsigned char *volatile) pnt;\n" &
    "    size_t i = 0;\n" &
    "    while (i < len) {\n" &
    "        p[i] = 0;\n" &
    "        i++;\n" &
    "    }\n" &
    "}\n"
  writeFile(a, text)

proc ensureCoreShim*(a: string) =
  ## a: shim C file path
  ## Writes a minimal sodium_init/sodium_misuse implementation when missing.
  var
    text: string = ""
  if fileExists(a):
    return
  text = "/* Minimal libsodium core shim. */\n" &
    "#include <stdlib.h>\n" &
    "#include \"sodium/core.h\"\n\n" &
    "int sodium_init(void) {\n" &
    "    return 0;\n" &
    "}\n\n" &
    "void sodium_misuse(void) {\n" &
    "    abort();\n" &
    "}\n"
  writeFile(a, text)

proc buildFlags*(a: string): tuple[base: string, sse: string, sse41: string, avx2: string,
    aes: string] =
  ## a: libsodium repo directory
  ## Returns common and CPU-specific compiler flags for the build.
  var
    includeDir: string = joinPath(a, "src", "libsodium", "include")
    includeSodium: string = joinPath(includeDir, "sodium")
    srcDir: string = joinPath(a, "src", "libsodium")
    baseFlags: string = ""
    cpuDefines: string = ""
    base: string = ""
    sse: string = ""
    sse41: string = ""
    avx2: string = ""
    aes: string = ""
  baseFlags = "-O2 -DSODIUM_STATIC -DNATIVE_LITTLE_ENDIAN -DCONFIGURED=1" &
    " -I" & quoteShell(includeDir) & " -I" & quoteShell(includeSodium) &
    " -I" & quoteShell(srcDir)
  cpuDefines = " -DHAVE_EMMINTRIN_H -DHAVE_TMMINTRIN_H -DHAVE_SMMINTRIN_H" &
    " -DHAVE_AVX2INTRIN_H -DHAVE_WMMINTRIN_H"
  base = baseFlags & cpuDefines
  sse = base & " -msse2 -mssse3"
  sse41 = base & " -msse2 -mssse3 -msse4.1"
  avx2 = base & " -msse2 -mssse3 -mavx2"
  aes = base & " -msse2 -mssse3 -mavx -mpclmul -maes"
  result = (base: base, sse: sse, sse41: sse41, avx2: avx2, aes: aes)

proc addSource*(s: var seq[tuple[path: string, flags: string]], a: string, b: string) =
  ## s: source list
  ## a: source file path
  ## b: compile flags
  var
    item: tuple[path: string, flags: string]
  item.path = a
  item.flags = b
  s.add item

proc collectSources*(a: string, b: tuple[base: string, sse: string, sse41: string, avx2: string,
    aes: string], c: string, d: string): seq[tuple[path: string, flags: string]] =
  ## a: libsodium repo directory
  ## b: compiler flags tuple
  ## c: memzero shim path
  ## d: core shim path
  ## Returns the list of sources with per-file compiler flags.
  var
    sources: seq[tuple[path: string, flags: string]] = @[]
    kdfPath: string = ""
  addSource(sources, c, b.base)
  addSource(sources, d, b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "randombytes", "randombytes.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "randombytes", "sysrandom",
    "randombytes_sysrandom.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "sodium", "runtime.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_hash", "sha256",
    "hash_sha256.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_hash", "sha256", "cp",
    "hash_sha256_cp.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_hash", "sha512",
    "hash_sha512.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_hash", "sha512", "cp",
    "hash_sha512_cp.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash",
    "crypto_generichash.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash", "blake2b",
    "generichash_blake2.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
    "generichash_blake2b.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
    "blake2b-ref.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
    "blake2b-compress-ref.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
    "blake2b-compress-ssse3.c"), b.sse)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
    "blake2b-compress-sse41.c"), b.sse41)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
    "blake2b-compress-avx2.c"), b.avx2)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_core", "hchacha20",
    "core_hchacha20.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_stream", "chacha20",
    "stream_chacha20.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_stream", "chacha20", "ref",
    "chacha20_ref.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_stream", "chacha20",
    "dolbeau", "chacha20_dolbeau-ssse3.c"), b.sse)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_stream", "chacha20",
    "dolbeau", "chacha20_dolbeau-avx2.c"), b.avx2)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_stream", "xchacha20",
    "stream_xchacha20.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_aead", "chacha20poly1305",
    "aead_chacha20poly1305.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_aead", "xchacha20poly1305",
    "aead_xchacha20poly1305.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_aead", "aes256gcm",
    "aead_aes256gcm.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_aead", "aes256gcm", "aesni",
    "aead_aes256gcm_aesni.c"), b.aes)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_onetimeauth",
    "crypto_onetimeauth.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_onetimeauth", "poly1305",
    "onetimeauth_poly1305.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_onetimeauth", "poly1305",
    "donna", "poly1305_donna.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_secretbox",
    "crypto_secretbox.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_secretbox",
    "crypto_secretbox_easy.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_secretbox",
    "xchacha20poly1305", "secretbox_xchacha20poly1305.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_scalarmult",
    "crypto_scalarmult.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_scalarmult", "curve25519",
    "scalarmult_curve25519.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_scalarmult", "curve25519",
    "ref10", "x25519_ref10.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_sign",
    "crypto_sign.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_sign", "ed25519",
    "sign_ed25519.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_sign", "ed25519", "ref10",
    "keypair.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_sign", "ed25519", "ref10",
    "open.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_sign", "ed25519", "ref10",
    "sign.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_core", "ed25519",
    "core_ed25519.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_core", "ed25519", "ref10",
    "ed25519_ref10.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_kdf",
    "crypto_kdf.c"), b.base)
  kdfPath = joinPath(a, "src", "libsodium", "crypto_kdf", "blake2b",
    "crypto_kdf_blake2b.c")
  if not fileExists(kdfPath):
    kdfPath = joinPath(a, "src", "libsodium", "crypto_kdf", "blake2b",
      "kdf_blake2b.c")
  addSource(sources, kdfPath, b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_kx",
    "crypto_kx.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash",
    "crypto_pwhash.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash", "argon2",
    "argon2.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash", "argon2",
    "argon2-core.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash", "argon2",
    "argon2-encoding.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash", "argon2",
    "argon2-fill-block-ref.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash", "argon2",
    "blake2b-long.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash", "argon2",
    "pwhash_argon2i.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_pwhash", "argon2",
    "pwhash_argon2id.c"), b.base)
  addSource(sources, joinPath(a, "src", "libsodium", "crypto_verify",
    "verify.c"), b.base)
  result = sources

proc objectPathFromSource*(a: string, b: string, c: string): string =
  ## a: source file path
  ## b: repo directory
  ## c: object directory
  ## Returns a stable object file path derived from the source path.
  var
    relPath: string = relativePath(a, b)
    name: string = ""
  name = relPath.replace("\\", "_").replace("/", "_").replace(":", "_")
  name = changeFileExt(name, ".o")
  result = joinPath(c, name)

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

when isMainModule:
  main()
