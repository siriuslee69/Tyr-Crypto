import algorithm
import os
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

proc buildPaths*(a: string): tuple[repoDir: string, buildDir: string, opsPath: string,
    shaPath: string, shaOutPath: string, includeDir: string, fullOutPath: string] =
  ## a: crypto repo base directory
  ## Builds liboqs repo, build, and header paths for combined headers.
  var
    repoDir: string = joinPath(a, "liboqs")
    buildDir: string = joinPath(a, "build", "liboqs")
    opsPath: string = joinPath(repoDir, "src", "common", "sha2", "sha2_ops.h")
    shaPath: string = joinPath(repoDir, "src", "common", "sha2", "sha2.h")
    shaOutPath: string = joinPath(buildDir, "oqs_sha2_combined.h")
    includeDir: string = joinPath(buildDir, "install", "include", "oqs")
    fullOutPath: string = joinPath(buildDir, "oqs_full_combined.h")
  result = (repoDir: repoDir, buildDir: buildDir, opsPath: opsPath, shaPath: shaPath,
    shaOutPath: shaOutPath, includeDir: includeDir, fullOutPath: fullOutPath)

proc headerName*(a: string): string =
  ## a: header file path
  ## Returns the lowercase filename with extension.
  var
    dir: string = ""
    name: string = ""
    ext: string = ""
  (dir, name, ext) = splitFile(a)
  result = (name & ext).toLowerAscii()

proc collectHeaders*(a: string): seq[string] =
  ## a: include directory
  ## Collects header paths from the include directory.
  var
    files: seq[string] = @[]
    entry: string = ""
    name: string = ""
  for kind, path in walkDir(a):
    if kind == pcFile:
      entry = path
      name = headerName(entry)
      if name.endsWith(".h"):
        files.add entry
  result = files

proc orderHeaders*(a: seq[string]): seq[string] =
  ## a: header paths
  ## Orders headers so shared config and core types appear first.
  var
    preferred: seq[string] = @[
      "oqsconfig.h",
      "common.h",
      "rand.h",
      "kem.h",
      "sig.h",
      "sig_stfl.h",
      "aes_ops.h",
      "sha2_ops.h",
      "sha3_ops.h",
      "sha3x4_ops.h"
    ]
    remaining: seq[string] = @[]
    ordered: seq[string] = @[]
    i: int = 0
    l: int = 0
    j: int = 0
    name: string = ""
    found: bool = false
  remaining = a
  l = preferred.len
  while i < l:
    j = 0
    found = false
    while j < remaining.len:
      name = headerName(remaining[j])
      if name == preferred[i]:
        ordered.add remaining[j]
        remaining.delete(j)
        found = true
        break
      inc j
    if not found:
      discard
    inc i
  remaining.sort(system.cmp[string])
  for item in remaining:
    ordered.add item
  result = ordered

proc ensureSha2CombinedHeader*(a: string) =
  ## a: crypto repo base directory
  ## Writes a combined header with sha2_ops.h and sha2.h for wrapper input.
  var
    paths: tuple[repoDir: string, buildDir: string, opsPath: string, shaPath: string,
      shaOutPath: string, includeDir: string, fullOutPath: string] = buildPaths(a)
    opsText: string = ""
    shaText: string = ""
    outText: string = ""
  if not fileExists(paths.opsPath):
    echo "Missing liboqs header: " & paths.opsPath
    quit(1)
  if not fileExists(paths.shaPath):
    echo "Missing liboqs header: " & paths.shaPath
    quit(1)
  createDir(paths.buildDir)
  opsText = readFile(paths.opsPath)
  shaText = readFile(paths.shaPath)
  outText = "/* Auto-generated combined header for cNimWrapper. */" & "\n" &
    "#ifndef OQS_SHA2_COMBINED_H" & "\n" &
    "#define OQS_SHA2_COMBINED_H" & "\n\n" &
    opsText & "\n\n" &
    shaText & "\n\n" &
    "#endif" & "\n"
  writeFile(paths.shaOutPath, outText)

proc ensureFullCombinedHeader*(a: string) =
  ## a: crypto repo base directory
  ## Writes a combined header containing all installed liboqs headers.
  var
    paths: tuple[repoDir: string, buildDir: string, opsPath: string, shaPath: string,
      shaOutPath: string, includeDir: string, fullOutPath: string] = buildPaths(a)
    headers: seq[string] = @[]
    ordered: seq[string] = @[]
    i: int = 0
    l: int = 0
    body: string = ""
    text: string = ""
  if not dirExists(paths.includeDir):
    echo "Missing liboqs include dir: " & paths.includeDir
    quit(1)
  createDir(paths.buildDir)
  headers = collectHeaders(paths.includeDir)
  ordered = orderHeaders(headers)
  l = ordered.len
  while i < l:
    body = readFile(ordered[i])
    text.add body & "\n\n"
    inc i
  text = "/* Auto-generated combined header for cNimWrapper. */" & "\n" &
    "#ifndef OQS_FULL_COMBINED_H" & "\n" &
    "#define OQS_FULL_COMBINED_H" & "\n\n" &
    text &
    "#endif" & "\n"
  writeFile(paths.fullOutPath, text)

proc main*() =
  ## Generates the combined liboqs headers.
  var
    baseDir: string = findCryptoRepoDir()
  ensureSha2CombinedHeader(baseDir)
  ensureFullCombinedHeader(baseDir)

when isMainModule:
  main()

