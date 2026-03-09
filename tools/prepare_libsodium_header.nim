import os

proc findCryptoRepoDir*(): string =
  ## Returns the crypto repo base directory based on this file's location.
  var
    sourceFile: string = currentSourcePath()
    sourceDir: string = ""
    baseDir: string = ""
  sourceDir = splitFile(sourceFile).dir
  baseDir = parentDir(sourceDir)
  result = baseDir

proc buildPaths*(a: string): tuple[repoDir: string, buildDir: string, outPath: string] =
  ## a: crypto repo base directory
  ## Builds libsodium repo and combined header paths.
  var
    repoDir: string = joinPath(a, "libsodium")
    buildDir: string = joinPath(a, "build", "libsodium")
    outPath: string = joinPath(buildDir, "sodium_combined.h")
  result = (repoDir: repoDir, buildDir: buildDir, outPath: outPath)

proc collectHeaders*(a: string): seq[string] =
  ## a: libsodium repo directory
  ## Returns ordered header paths for the combined wrapper input.
  var
    headers: seq[string] = @[]
    baseDir: string = joinPath(a, "src", "libsodium", "include", "sodium")
  headers.add joinPath(baseDir, "export.h")
  headers.add joinPath(baseDir, "core.h")
  headers.add joinPath(baseDir, "crypto_hash.h")
  headers.add joinPath(baseDir, "crypto_hash_sha256.h")
  headers.add joinPath(baseDir, "crypto_hash_sha512.h")
  headers.add joinPath(baseDir, "crypto_generichash.h")
  headers.add joinPath(baseDir, "crypto_generichash_blake2b.h")
  headers.add joinPath(baseDir, "crypto_kdf.h")
  headers.add joinPath(baseDir, "crypto_kdf_blake2b.h")
  headers.add joinPath(baseDir, "crypto_stream.h")
  headers.add joinPath(baseDir, "crypto_stream_chacha20.h")
  headers.add joinPath(baseDir, "crypto_stream_xchacha20.h")
  headers.add joinPath(baseDir, "crypto_aead_chacha20poly1305.h")
  headers.add joinPath(baseDir, "crypto_aead_xchacha20poly1305.h")
  headers.add joinPath(baseDir, "crypto_aead_aes256gcm.h")
  headers.add joinPath(baseDir, "crypto_onetimeauth.h")
  headers.add joinPath(baseDir, "crypto_onetimeauth_poly1305.h")
  headers.add joinPath(baseDir, "crypto_secretbox_xchacha20poly1305.h")
  headers.add joinPath(baseDir, "crypto_pwhash.h")
  headers.add joinPath(baseDir, "crypto_pwhash_argon2i.h")
  headers.add joinPath(baseDir, "crypto_pwhash_argon2id.h")
  headers.add joinPath(baseDir, "crypto_scalarmult.h")
  headers.add joinPath(baseDir, "crypto_scalarmult_curve25519.h")
  headers.add joinPath(baseDir, "crypto_sign.h")
  headers.add joinPath(baseDir, "crypto_sign_ed25519.h")
  headers.add joinPath(baseDir, "crypto_kx.h")
  result = headers

proc readHeader*(a: string): string =
  ## a: header file path
  ## Returns the file contents or aborts if the file is missing.
  if not fileExists(a):
    echo "Header not found: " & a
    quit(1)
  result = readFile(a)

proc writeCombined*(a: seq[string], b: string) =
  ## a: ordered header paths
  ## b: output header path
  ## Writes a combined header file for libsodium wrappers.
  var
    i: int = 0
    l: int = a.len
    combined: string = ""
    headerText: string = ""
    headerPath: string = ""
  while i < l:
    headerPath = a[i]
    headerText = readHeader(headerPath)
    combined.add "/* --- " & headerPath & " --- */\n"
    combined.add headerText
    if headerText.len == 0 or headerText[^1] != '\n':
      combined.add "\n"
    combined.add "\n"
    inc i
  writeFile(b, combined)

proc main*() =
  ## Builds a combined libsodium header with the required crypto APIs.
  var
    baseDir: string = findCryptoRepoDir()
    paths: tuple[repoDir: string, buildDir: string, outPath: string] = buildPaths(baseDir)
    headers: seq[string] = @[]
  if not dirExists(paths.repoDir):
    echo "Repo not found: " & paths.repoDir
    quit(1)
  createDir(paths.buildDir)
  headers = collectHeaders(paths.repoDir)
  writeCombined(headers, paths.outPath)
  echo "wrote: " & paths.outPath

when isMainModule:
  main()

