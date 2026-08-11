## libsodium_zigcc_windows.nim
## -> Windows fallback builder for libsodium
## Compiles libsodium sources with `zig cc` and links a shared DLL with MinGW GCC.

when defined(windows):
  import std/[os, osproc, strutils]

  type
    BuildFlags* = tuple[base: string, sse: string, sse41: string, avx2: string, aes: string]
    SourceSpec* = tuple[path: string, flags: string]

  proc runCmd(cmd: string): bool =
    var
      res: tuple[output: string, exitCode: int] = execCmdEx(cmd)
    if res.output.len > 0:
      echo res.output
    if res.exitCode != 0:
      echo "Command failed with exit code ", res.exitCode
      result = false
      return
    result = true

  proc runCmdWithZigCache(cmd: string, cacheDir: string, globalCacheDir: string): bool =
    var
      oldLocal: string = getEnv("ZIG_LOCAL_CACHE_DIR")
      oldGlobal: string = getEnv("ZIG_GLOBAL_CACHE_DIR")
      hadLocal: bool = existsEnv("ZIG_LOCAL_CACHE_DIR")
      hadGlobal: bool = existsEnv("ZIG_GLOBAL_CACHE_DIR")
    putEnv("ZIG_LOCAL_CACHE_DIR", cacheDir)
    putEnv("ZIG_GLOBAL_CACHE_DIR", globalCacheDir)
    result = runCmd(cmd)
    if hadLocal:
      putEnv("ZIG_LOCAL_CACHE_DIR", oldLocal)
    else:
      delEnv("ZIG_LOCAL_CACHE_DIR")
    if hadGlobal:
      putEnv("ZIG_GLOBAL_CACHE_DIR", oldGlobal)
    else:
      delEnv("ZIG_GLOBAL_CACHE_DIR")

  proc ensureVersionHeader(repoDir: string) =
    var
      targetPath: string = joinPath(repoDir, "src", "libsodium", "include", "sodium", "version.h")
      sourcePath: string = joinPath(repoDir, "builds", "msvc", "version.h")
    if fileExists(targetPath):
      return
    createDir(parentDir(targetPath))
    copyFile(sourcePath, targetPath)

  proc ensureMemzeroShim(path: string) =
    var
      text: string = ""
    if fileExists(path):
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
    writeFile(path, text)

  proc ensureCoreShim(path: string) =
    var
      text: string = ""
    if fileExists(path):
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
    writeFile(path, text)

  proc buildFlags(repoDir: string): BuildFlags =
    var
      includeDir: string = joinPath(repoDir, "src", "libsodium", "include")
      includeSodium: string = joinPath(includeDir, "sodium")
      srcDir: string = joinPath(repoDir, "src", "libsodium")
      baseFlags: string = ""
      cpuDefines: string = ""
    baseFlags = "-O2 -DNATIVE_LITTLE_ENDIAN -DCONFIGURED=1" &
      " -I" & quoteShell(includeDir) & " -I" & quoteShell(includeSodium) &
      " -I" & quoteShell(srcDir)
    cpuDefines = " -DHAVE_EMMINTRIN_H -DHAVE_TMMINTRIN_H -DHAVE_SMMINTRIN_H" &
      " -DHAVE_AVX2INTRIN_H -DHAVE_WMMINTRIN_H"
    result.base = baseFlags & cpuDefines
    result.sse = result.base & " -msse2 -mssse3"
    result.sse41 = result.base & " -msse2 -mssse3 -msse4.1"
    result.avx2 = result.base & " -msse2 -mssse3 -mavx2"
    result.aes = result.base & " -msse2 -mssse3 -mavx -mpclmul -maes"

  proc addSource(S: var seq[SourceSpec], path: string, flags: string) =
    S.add((path: path, flags: flags))

  proc collectSources(repoDir: string, flags: BuildFlags, memzeroShim: string,
      coreShim: string): seq[SourceSpec] =
    var
      kdfPath: string = ""
    discard memzeroShim
    addSource(result, coreShim, flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "randombytes", "randombytes.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "randombytes", "sysrandom",
      "randombytes_sysrandom.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "sodium", "runtime.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "sodium", "utils.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "sodium", "codecs.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "sodium", "version.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_hash", "sha256",
      "hash_sha256.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_hash", "sha256", "cp",
      "hash_sha256_cp.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_hash", "sha512",
      "hash_sha512.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_hash", "sha512", "cp",
      "hash_sha512_cp.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash",
      "crypto_generichash.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash", "blake2b",
      "generichash_blake2.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
      "generichash_blake2b.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
      "blake2b-ref.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
      "blake2b-compress-ref.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
      "blake2b-compress-ssse3.c"), flags.sse)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
      "blake2b-compress-sse41.c"), flags.sse41)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_generichash", "blake2b", "ref",
      "blake2b-compress-avx2.c"), flags.avx2)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_core", "hchacha20",
      "core_hchacha20.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_core", "salsa", "ref",
      "core_salsa_ref.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "chacha20",
      "stream_chacha20.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "chacha20", "ref",
      "chacha20_ref.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "chacha20",
      "dolbeau", "chacha20_dolbeau-ssse3.c"), flags.sse)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "chacha20",
      "dolbeau", "chacha20_dolbeau-avx2.c"), flags.avx2)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "salsa20",
      "stream_salsa20.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "salsa20", "ref",
      "salsa20_ref.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "salsa20", "xmm6",
      "salsa20_xmm6.c"), flags.sse)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "salsa20", "xmm6int",
      "salsa20_xmm6int-sse2.c"), flags.sse)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "salsa20", "xmm6int",
      "salsa20_xmm6int-avx2.c"), flags.avx2)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "xchacha20",
      "stream_xchacha20.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_stream", "xsalsa20",
      "stream_xsalsa20.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_aead", "chacha20poly1305",
      "aead_chacha20poly1305.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_aead", "xchacha20poly1305",
      "aead_xchacha20poly1305.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_aead", "aes256gcm",
      "aead_aes256gcm.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_aead", "aes256gcm", "aesni",
      "aead_aes256gcm_aesni.c"), flags.aes)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_onetimeauth",
      "crypto_onetimeauth.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_onetimeauth", "poly1305",
      "onetimeauth_poly1305.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_onetimeauth", "poly1305",
      "donna", "poly1305_donna.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_secretbox",
      "crypto_secretbox.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_secretbox",
      "crypto_secretbox_easy.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_secretbox",
      "xchacha20poly1305", "secretbox_xchacha20poly1305.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_secretbox",
      "xsalsa20poly1305", "secretbox_xsalsa20poly1305.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_scalarmult",
      "crypto_scalarmult.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_scalarmult", "curve25519",
      "scalarmult_curve25519.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_scalarmult", "curve25519",
      "ref10", "x25519_ref10.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_sign",
      "crypto_sign.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_sign", "ed25519",
      "sign_ed25519.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_sign", "ed25519", "ref10",
      "keypair.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_sign", "ed25519", "ref10",
      "open.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_sign", "ed25519", "ref10",
      "sign.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_core", "ed25519",
      "core_ed25519.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_core", "ed25519",
      "core_h2c.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_core", "ed25519", "ref10",
      "ed25519_ref10.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_core", "hsalsa20",
      "core_hsalsa20.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_core", "hsalsa20", "ref2",
      "core_hsalsa20_ref2.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_kdf",
      "crypto_kdf.c"), flags.base)
    kdfPath = joinPath(repoDir, "src", "libsodium", "crypto_kdf", "blake2b",
      "crypto_kdf_blake2b.c")
    if not fileExists(kdfPath):
      kdfPath = joinPath(repoDir, "src", "libsodium", "crypto_kdf", "blake2b",
        "kdf_blake2b.c")
    addSource(result, kdfPath, flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_kx",
      "crypto_kx.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash",
      "crypto_pwhash.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "argon2.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "argon2-core.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "argon2-encoding.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "argon2-fill-block-avx2.c"), flags.avx2)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "argon2-fill-block-ref.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "argon2-fill-block-ssse3.c"), flags.sse)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "blake2b-long.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "pwhash_argon2i.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_pwhash", "argon2",
      "pwhash_argon2id.c"), flags.base)
    addSource(result, joinPath(repoDir, "src", "libsodium", "crypto_verify",
      "verify.c"), flags.base)

  proc objectPathFromSource(sourcePath: string, repoDir: string, objDir: string): string =
    var
      relPath: string = relativePath(sourcePath, repoDir)
      name: string = ""
    name = relPath.replace("\\", "_").replace("/", "_").replace(":", "_")
    name = changeFileExt(name, ".o")
    result = joinPath(objDir, name)

  proc zigCompiler(): string =
    result = findExe("zig")
    if result.len == 0:
      result = "zig"

  proc zigCompile(sourcePath: string, objPath: string, flags: string, cacheDir: string,
      globalCacheDir: string): bool =
    var
      cmd: string = ""
    cmd = quoteShell(zigCompiler()) &
      " cc" &
      " -target x86_64-windows-gnu -c " & flags &
      " -o " & quoteShell(objPath) & " " & quoteShell(sourcePath)
    result = runCmdWithZigCache(cmd, cacheDir, globalCacheDir)

  proc compileSourcesZig(sources: seq[SourceSpec], repoDir: string, objDir: string,
      cacheDir: string, globalCacheDir: string): seq[string] =
    var
      i: int = 0
      l: int = sources.len
      objPath: string = ""
    while i < l:
      objPath = objectPathFromSource(sources[i].path, repoDir, objDir)
      if not zigCompile(sources[i].path, objPath, sources[i].flags, cacheDir, globalCacheDir):
        return @[]
      result.add(objPath)
      inc i

  proc gccLinker(): string =
    result = findExe("x86_64-w64-mingw32-gcc")
    if result.len > 0:
      return
    result = findExe("gcc")
    if result.len == 0:
      result = "gcc"

  proc linkSharedLibrary(objects: seq[string], dllPath: string, implibPath: string): bool =
    var
      cmd: string = ""
      i: int = 0
      l: int = objects.len
    cmd = quoteShell(gccLinker()) & " -shared -o " & quoteShell(dllPath)
    while i < l:
      cmd.add(" ")
      cmd.add(quoteShell(objects[i]))
      inc i
    cmd.add(" -Wl,--out-implib,")
    cmd.add(quoteShell(implibPath))
    cmd.add(" -ladvapi32")
    result = runCmd(cmd)

  proc installHeaders(repoDir: string, includeInstallDir: string) =
    var
      sodiumHeaderDir: string = joinPath(includeInstallDir, "sodium")
    createDir(includeInstallDir)
    if dirExists(sodiumHeaderDir):
      removeDir(sodiumHeaderDir)
    copyFile(joinPath(repoDir, "src", "libsodium", "include", "sodium.h"),
      joinPath(includeInstallDir, "sodium.h"))
    copyDir(joinPath(repoDir, "src", "libsodium", "include", "sodium"), sodiumHeaderDir)

  proc buildLibsodiumSharedWithZigCc*(repoDir: string, buildRoot: string): string =
    var
      installDir: string = joinPath(buildRoot, "install")
      libDir: string = joinPath(installDir, "lib")
      binDir: string = joinPath(installDir, "bin")
      includeDir: string = joinPath(installDir, "include")
      objDir: string = joinPath(buildRoot, "zigcc-obj")
      cacheDir: string = joinPath(buildRoot, "zig-local-cache")
      globalCacheDir: string = joinPath(buildRoot, "zig-global-cache")
      memzeroShim: string = joinPath(buildRoot, "sodium_memzero_shim.c")
      coreShim: string = joinPath(buildRoot, "sodium_core_shim.c")
      dllPath: string = joinPath(binDir, "libsodium.dll")
      implibPath: string = joinPath(libDir, "libsodium.dll.a")
      flags: BuildFlags
      sources: seq[SourceSpec] = @[]
      objects: seq[string] = @[]
    ensureVersionHeader(repoDir)
    createDir(buildRoot)
    createDir(installDir)
    createDir(libDir)
    createDir(binDir)
    createDir(includeDir)
    createDir(objDir)
    createDir(cacheDir)
    createDir(globalCacheDir)
    ensureMemzeroShim(memzeroShim)
    ensureCoreShim(coreShim)
    flags = buildFlags(repoDir)
    sources = collectSources(repoDir, flags, memzeroShim, coreShim)
    objects = compileSourcesZig(sources, repoDir, objDir, cacheDir, globalCacheDir)
    if objects.len == 0:
      return ""
    if not linkSharedLibrary(objects, dllPath, implibPath):
      return ""
    installHeaders(repoDir, includeDir)
    result = dllPath
