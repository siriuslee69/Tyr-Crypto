import std/[os, unittest]
import ../src/protocols/wrapper/algorithms
import ../src/protocols/wrapper/suite_api
import ../src/protocols/common
import ../src/protocols/bindings/libsodium
import ../src/protocols/bindings/liboqs
import ../src/protocols/builders/liboqs_builder
import ./helpers
import ./crypto_vectors

let
  wrapperRepoRoot = parentDir(splitFile(currentSourcePath()).dir)
  wrapperLiboqsSource = joinPath(wrapperRepoRoot, "submodules", "liboqs")
  wrapperLibsodiumSource = joinPath(wrapperRepoRoot, "submodules", "libsodium")
  wrapperLiboqsBuild = joinPath(wrapperRepoRoot, "build", "liboqs")
  wrapperLibsodiumBuild = joinPath(wrapperRepoRoot, "build", "libsodium")

putEnv("LIBOQS_SOURCE", wrapperLiboqsSource)
putEnv("LIBSODIUM_SOURCE", wrapperLibsodiumSource)
putEnv("LIBOQS_BUILD_ROOT", wrapperLiboqsBuild)
putEnv("LIBSODIUM_BUILD_ROOT", wrapperLibsodiumBuild)
putEnv("LIBOQS_LIB_DIRS",
  joinPath(wrapperLiboqsBuild, "install", "lib") & ";" &
  joinPath(wrapperLiboqsBuild, "install", "bin"))
putEnv("LIBSODIUM_LIB_DIRS",
  joinPath(wrapperLibsodiumBuild, "install", "lib") & ";" &
  joinPath(wrapperLibsodiumBuild, "install", "bin"))

proc bytesToString(data: openArray[uint8]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc ensureWrapperLibsodiumAvailable(): bool =
  try:
    if not ensureLibSodiumLoaded():
      echo "libsodium unavailable at runtime after local build attempt; wrapper sodium tests will skip."
      return false
    return true
  except LibraryUnavailableError, OSError, IOError:
    echo "libsodium unavailable at runtime after local build attempt; wrapper sodium tests will skip."
    return false

proc ensureWrapperLiboqsAvailable(): bool =
  when defined(hasLibOqs):
    try:
      discard promptReuseOrRebuildLibOqs(wrapperLiboqsSource, wrapperLiboqsBuild)
      if not ensureLibOqsLoaded():
        echo "liboqs unavailable at runtime after local build attempt; wrapper PQ tests will skip."
        return false
      return true
    except LibraryUnavailableError, OSError, IOError:
      echo "liboqs unavailable at runtime after local build attempt; wrapper PQ tests will skip."
      return false
  else:
    echo "liboqs unavailable at compile time; wrapper PQ tests will skip."
    return false

suite "wrapper crypto":
  when defined(hasLibsodium):
    test "wrapper can load or build libsodium from local submodule":
      discard ensureWrapperLibsodiumAvailable()

  when defined(hasLibOqs):
    test "wrapper can load or build liboqs from local submodule":
      discard ensureWrapperLiboqsAvailable()

  test "XChaCha20 wrapper matches vector":
    let vec = wrapperXChaChaVector
    let key = hexToBytes(vec.keyHex)
    let nonce = hexToBytes(vec.nonceHex)
    let plaintext = hexToBytes(vec.plaintextHex)
    let expectedCipher = hexToBytes(vec.cipherHex)
    let expectedTag = hexToBytes(vec.tagHex)

    let state = initSymAuthState(csXChaCha20Blake3, @[key], nonce)
    let cipher = symAuthEnc(plaintext, state)
    check cipher.authType == atBlake3
    check cipher.ciphertext == expectedCipher
    check cipher.auth == expectedTag

  test "XChaCha20 encrypt/decrypt roundtrip":
    const nonceLen = 24
    var key = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(i)
    var nonce = newSeq[uint8](nonceLen)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(100 + i)
    var msg = toBytes("wrapper xchacha20 roundtrip")
    msg.add(0'u8)
    msg.add(255'u8)
    let state = initSymAuthState(csXChaCha20Blake3, @[key], nonce)
    let cipher = symAuthEnc(msg, state)
    check cipher.authType == atBlake3
    let plain = symAuthDec(cipher, state)
    check plain == msg

  test "XChaCha20 tag mismatch rejects":
    var key = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(i)
    var nonce = newSeq[uint8](24)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(100 + i)
    let state = initSymAuthState(csXChaCha20Blake3, @[key], nonce)
    var cipher = symAuthEnc(toBytes("wrapper tag mismatch"), state)
    cipher.auth[0] = cipher.auth[0] xor 0x01'u8
    expect ValueError:
      discard symAuthDec(cipher, state)

  test "XChaCha20 decrypt/write/read roundtrip":
    const nonceLen = 24
    var key = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(200 - i)
    var nonce = newSeq[uint8](nonceLen)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(i xor 0x5a)
    var msg = toBytes("file roundtrip check for xchacha20")
    msg.add(0'u8)
    msg.add(1'u8)
    msg.add(2'u8)
    let state = initSymAuthState(csXChaCha20Blake3, @[key], nonce)
    let cipher = symAuthEnc(msg, state)
    let plain = symAuthDec(cipher, state)

    let path = getTempDir() / "crypto_wrapper_xchacha20.bin"
    defer:
      if fileExists(path):
        removeFile(path)
    writeFile(path, bytesToString(plain))
    let readBack = toBytes(readFile(path))
    check readBack == msg

  when defined(hasLibsodium):
    test "XChaCha20-Poly1305 encrypt/decrypt roundtrip":
      if ensureWrapperLibsodiumAvailable():
        var key = newSeq[uint8](32)
        for i in 0 ..< key.len:
          key[i] = uint8((i * 7) mod 256)
        var nonce = newSeq[uint8](24)
        for i in 0 ..< nonce.len:
          nonce[i] = uint8(150 - i)
        let msg = toBytes("wrapper xchacha20poly1305 roundtrip")
        let state = initSymAuthState(csXChaCha20Poly1305, @[key], nonce)
        let cipher = symAuthEnc(msg, state)
        check cipher.authType == atAeadTag
        check cipher.auth.len == 16
        let plain = symAuthDec(cipher, state)
        check plain == msg
  else:
    test "XChaCha20-Poly1305 unavailable raises descriptive error":
      let state = initSymAuthState(csXChaCha20Poly1305, @[newSeq[uint8](32)],
        newSeq[uint8](24))
      expect LibraryUnavailableError:
        discard symAuthEnc(toBytes("poly1305"), state)

  when defined(hasNimcrypto):
    test "AES-256-GCM encrypt/decrypt roundtrip":
      var key = newSeq[uint8](32)
      for i in 0 ..< key.len:
        key[i] = uint8(i + 10)
      var nonce = newSeq[uint8](12)
      for i in 0 ..< nonce.len:
        nonce[i] = uint8(255 - i)
      let msg = toBytes("wrapper aes gcm roundtrip")
      let state = initSymAuthState(csAes256Gcm, @[key], nonce)
      let cipher = symAuthEnc(msg, state)
      check cipher.authType == atAeadTag
      let plain = symAuthDec(cipher, state)
      check plain == msg
  else:
    test "AES-256-GCM unavailable raises descriptive error":
      var key = newSeq[uint8](32)
      var nonce = newSeq[uint8](12)
      let msg = toBytes("aes")
      let state = initSymAuthState(csAes256Gcm, @[key], nonce)
      expect LibraryUnavailableError:
        discard symAuthEnc(msg, state)

  when defined(hasNimcrypto):
    test "AES-256-GCM decrypt/write/read roundtrip":
      var key = newSeq[uint8](32)
      for i in 0 ..< key.len:
        key[i] = uint8(31 - i)
      var nonce = newSeq[uint8](12)
      for i in 0 ..< nonce.len:
        nonce[i] = uint8(i * 3 mod 256)
      var msg = toBytes("file roundtrip check for aes gcm")
      msg.add(9'u8)
      msg.add(8'u8)
      let state = initSymAuthState(csAes256Gcm, @[key], nonce)
      let cipher = symAuthEnc(msg, state)
      let plain = symAuthDec(cipher, state)

      let path = getTempDir() / "crypto_wrapper_aes.bin"
      defer:
        if fileExists(path):
          removeFile(path)
      writeFile(path, bytesToString(plain))
      let readBack = toBytes(readFile(path))
      check readBack == msg

    test "AES-256-GCM tag mismatch rejects":
      var key = newSeq[uint8](32)
      for i in 0 ..< key.len:
        key[i] = uint8(i + 1)
      var nonce = newSeq[uint8](12)
      for i in 0 ..< nonce.len:
        nonce[i] = uint8(200 - i)
      let state = initSymAuthState(csAes256Gcm, @[key], nonce)
      var cipher = symAuthEnc(toBytes("aes gcm tamper"), state)
      cipher.auth[0] = cipher.auth[0] xor 0x80'u8
      expect ValueError:
        discard symAuthDec(cipher, state)
