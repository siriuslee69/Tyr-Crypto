## otter:vectors - the fixed keys and hex below are published test vectors.

import std/[os, sequtils, unittest]
import ../paths
import ../../src/tyr/helpers/tiers
import ../../src/tyr/aeads
import ../../src/tyr/helpers/errors
import ../../src/tyr/bindings/libsodium
import ../../src/tyr/bindings/liboqs
import ../../tools/builders/liboqs_builder
import ../../src/tyr/hashes/blake3
import ./helpers
import ./crypto_vectors

let
  wrapperRepoRoot = repoRootFrom(currentSourcePath())
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
    let authKey = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let plaintext = hexToBytes(vec.plaintextHex)
    let expectedCipher = hexToBytes(vec.cipherHex)
    let expectedTag = hexToBytes(vec.tagHex)

    let state = initAeadState(csXChaCha20Blake3, @[key, authKey], nonce)
    let cipher = seal(plaintext, state)
    check cipher.authType == atBlake3
    check cipher.ciphertext == expectedCipher
    check cipher.auth == expectedTag

  test "XChaCha20 encrypt/decrypt roundtrip":
    const nonceLen = 24
    var key = newSeq[uint8](32)
    var authKey = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(i)
      authKey[i] = uint8(255 - i)
    var nonce = newSeq[uint8](nonceLen)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(100 + i)
    var msg = toBytes("wrapper xchacha20 roundtrip")
    msg.add(0'u8)
    msg.add(255'u8)
    let state = initAeadState(csXChaCha20Blake3, @[key, authKey], nonce)
    let cipher = seal(msg, state)
    check cipher.authType == atBlake3
    let plain = open(cipher, state)
    check plain == msg

  test "XChaCha20 tag mismatch rejects":
    var key = newSeq[uint8](32)
    var authKey = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(i)
      authKey[i] = uint8(255 - i)
    var nonce = newSeq[uint8](24)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(100 + i)
    let state = initAeadState(csXChaCha20Blake3, @[key, authKey], nonce)
    var cipher = seal(toBytes("wrapper tag mismatch"), state)
    cipher.auth[0] = cipher.auth[0] xor 0x01'u8
    expect ValueError:
      discard open(cipher, state)

  test "XChaCha20 decrypt/write/read roundtrip":
    const nonceLen = 24
    var key = newSeq[uint8](32)
    var authKey = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(200 - i)
      authKey[i] = uint8(i xor 0xa5)
    var nonce = newSeq[uint8](nonceLen)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(i xor 0x5a)
    var msg = toBytes("file roundtrip check for xchacha20")
    msg.add(0'u8)
    msg.add(1'u8)
    msg.add(2'u8)
    let state = initAeadState(csXChaCha20Blake3, @[key, authKey], nonce)
    let cipher = seal(msg, state)
    let plain = open(cipher, state)

    let path = getTempDir() / "crypto_wrapper_xchacha20.bin"
    defer:
      if fileExists(path):
        removeFile(path)
    writeFile(path, bytesToString(plain))
    let readBack = toBytes(readFile(path))
    check readBack == msg

  test "keyed BLAKE3 suite rejects attacker-recomputed unkeyed tag":
    let key = newSeq[uint8](32)
    let authKey = newSeqWith(32, 0x5a'u8)
    let nonce = newSeq[uint8](24)
    let state = initAeadState(csXChaCha20Blake3, @[key, authKey], nonce)
    var cipher = seal(@[0x41'u8], state)
    cipher.ciphertext[0] = cipher.ciphertext[0] xor 1'u8
    cipher.auth = blake3Hash(cipher.ciphertext, cipher.auth.len)
    expect ValueError:
      discard open(cipher, state)

  test "suite state rejects a second encryption with the same nonce":
    let key = newSeq[uint8](32)
    let authKey = newSeqWith(32, 0x5a'u8)
    let nonce = newSeq[uint8](24)
    let state = initAeadState(csXChaCha20Blake3, @[key, authKey], nonce)
    let stateAlias = state
    discard seal(@[0x00'u8], state)
    expect ValueError:
      discard seal(@[0xff'u8], stateAlias)

  test "suite tag boundaries are enforced per algorithm":
    let key = newSeq[uint8](32)
    let authKey = newSeqWith(32, 0x5a'u8)
    let nonce = newSeq[uint8](24)
    let gcmNonce = newSeq[uint8](12)
    check initAeadState(csXChaCha20Blake3, @[key, authKey], nonce).tagBytes == 32
    expect ValueError:
      discard initAeadState(csXChaCha20Blake3, @[key, authKey], nonce, 15)
    expect ValueError:
      discard initAeadState(csXChaCha20Blake3, @[key, authKey], nonce, 33)
    expect ValueError:
      discard initAeadState(csXChaCha20Blake3, @[key], nonce)
    check initAeadState(csAes256Gcm, @[key], gcmNonce).tagBytes == 16
    for size in [1'u16, 15'u16, 17'u16, 32'u16]:
      expect ValueError:
        discard initAeadState(csAes256Gcm, @[key], gcmNonce, size)

  when defined(hasNimcrypto):
    test "AES-256-GCM encrypt/decrypt roundtrip":
      var key = newSeq[uint8](32)
      for i in 0 ..< key.len:
        key[i] = uint8(i + 10)
      var nonce = newSeq[uint8](12)
      for i in 0 ..< nonce.len:
        nonce[i] = uint8(255 - i)
      let msg = toBytes("wrapper aes gcm roundtrip")
      let state = initAeadState(csAes256Gcm, @[key], nonce)
      let cipher = seal(msg, state)
      check cipher.authType == atAeadTag
      let plain = open(cipher, state)
      check plain == msg
  else:
    test "AES-256-GCM unavailable raises descriptive error":
      var key = newSeq[uint8](32)
      var nonce = newSeq[uint8](12)
      let msg = toBytes("aes")
      let state = initAeadState(csAes256Gcm, @[key], nonce)
      expect LibraryUnavailableError:
        discard seal(msg, state)

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
      let state = initAeadState(csAes256Gcm, @[key], nonce)
      let cipher = seal(msg, state)
      let plain = open(cipher, state)

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
      let state = initAeadState(csAes256Gcm, @[key], nonce)
      var cipher = seal(toBytes("aes gcm tamper"), state)
      cipher.auth[0] = cipher.auth[0] xor 0x80'u8
      expect ValueError:
        discard open(cipher, state)
      cipher.auth.setLen(15)
      expect ValueError:
        discard open(cipher, state)
      cipher.auth = newSeq[uint8](16)
      cipher.authType = atBlake3
      expect ValueError:
        discard open(cipher, state)
