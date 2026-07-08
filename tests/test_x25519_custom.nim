import std/unittest

import ../src/protocols/custom_crypto/x25519 as customX25519
import ../src/protocols/custom_crypto/asymmetric/none_pq/x25519_common
import ../src/protocols/bindings/libsodium
import ./[crypto_vectors, helpers]

proc sodiumAvailable(): bool =
  try:
    if not ensureLibSodiumLoaded():
      return false
    ensureSodiumInitialised()
    result = true
  except CatchableError:
    result = false

proc sodiumPublicKey(secretKey: openArray[byte]): seq[byte] =
  var outBuf = newSeq[byte](32)
  if crypto_scalarmult_curve25519_base(
      addr outBuf[0],
      if secretKey.len > 0: unsafeAddr secretKey[0] else: nil) != 0:
    raise newException(ValueError, "crypto_scalarmult_curve25519_base failed")
  result = outBuf

proc sodiumShared(secretKey, publicKey: openArray[byte]): seq[byte] =
  var outBuf = newSeq[byte](32)
  if crypto_scalarmult_curve25519(
      addr outBuf[0],
      if secretKey.len > 0: unsafeAddr secretKey[0] else: nil,
      if publicKey.len > 0: unsafeAddr publicKey[0] else: nil) != 0:
    raise newException(ValueError, "crypto_scalarmult_curve25519 failed")
  result = outBuf

suite "custom x25519":
  test "impl matches the RFC-style known vector":
    let
      sk = hexToBytes(curve25519Vector.skHex)
      pk = hexToBytes(curve25519Vector.pkHex)
      shared = hexToBytes(curve25519Vector.sharedHex)
    check customX25519.x25519TyrShared(sk, pk) == shared

  when defined(hasLibsodium):
    test "impl matches libsodium basepoint derivation":
      let sk = hexToBytes(curve25519Vector.skHex)
      if not sodiumAvailable():
        skip()
      let pk = sodiumPublicKey(sk)
      check customX25519.x25519TyrPublicKey(sk) == pk

  test "seeded keypairs stay deterministic":
    let seed = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let kpA = customX25519.x25519TyrKeypairFromSeed(seed)
    let kpB = customX25519.x25519TyrKeypairFromSeed(seed)
    check kpA.publicKey == kpB.publicKey
    check kpA.secretKey == kpB.secretKey

  test "all small-order peers are detected and rejected":
    let secretKey = hexToBytes(curve25519Vector.skHex)
    for peer in smallOrderBlocklist:
      check hasSmallOrder(peer)
      var peerHighBit = peer
      peerHighBit[31] = peerHighBit[31] or 0x80'u8
      check hasSmallOrder(peerHighBit)
      expect(ValueError):
        discard customX25519.x25519TyrShared(secretKey, toSeqBytes(peer))
      expect(ValueError):
        discard customX25519.x25519TyrShared(secretKey, toSeqBytes(peerHighBit))

  when defined(hasLibsodium):
    test "impl matches libsodium on a deterministic corpus":
      if not sodiumAvailable():
        skip()
      for i in 0 ..< 6:
        var seedA = newSeq[byte](32)
        var seedB = newSeq[byte](32)
        for j in 0 ..< 32:
          seedA[j] = byte((17 * i + j) and 0xff)
          seedB[j] = byte((91 + 13 * i + 3 * j) and 0xff)
        let
          kpA = customX25519.x25519TyrKeypairFromSeed(seedA)
          kpB = customX25519.x25519TyrKeypairFromSeed(seedB)
          sodiumPkA = sodiumPublicKey(kpA.secretKey)
          sodiumPkB = sodiumPublicKey(kpB.secretKey)
          sodiumSharedA = sodiumShared(kpA.secretKey, kpB.publicKey)
          sodiumSharedB = sodiumShared(kpB.secretKey, kpA.publicKey)
        check kpA.publicKey == sodiumPkA
        check kpB.publicKey == sodiumPkB
        check customX25519.x25519TyrShared(kpA.secretKey, kpB.publicKey) == sodiumSharedA
        check sodiumSharedA == sodiumSharedB
