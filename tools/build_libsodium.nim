## Build the pinned libsodium sources for Tyr.

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

include ./build_libsodium_sources
when isMainModule:
  main()
