## ---------------------------------------------------------------------
## | AEAD Runtime Tests <- the one-shot tier must match the state tier   |
## ---------------------------------------------------------------------

import std/unittest

import ../src/tyr/aeads
import ../src/tyr/aeads/dynamic

proc keysFor(a: CipherSuite): seq[seq[uint8]] =
  var
    i: int = 0
    j: int = 0
    k: seq[uint8] = @[]
  result = @[]
  while i < keyCount(a):
    k = newSeq[uint8](suiteKeyBytes)
    j = 0
    while j < suiteKeyBytes:
      k[j] = uint8((i * 41 + j * 7 + 3) and 0xff)
      j = j + 1
    result.add(k)
    i = i + 1

proc nonceFor(a: CipherSuite): seq[uint8] =
  var i: int = 0
  result = newSeq[uint8](nonceBytes(a))
  while i < result.len:
    result[i] = uint8(255 - i)
    i = i + 1

## The composites are what this build can always run. AES-256-GCM needs
## -d:hasNimcrypto, and is covered by test_wrapper where that applies.
const composites = [csXChaCha20Blake3, csXChaCha20Gimli, csAesGimli,
  csXChaCha20AesGimli, csXChaCha20AesGimliPoly1305]

suite "aead runtime selection":

  test "every composite suite round-trips through the one-shot tier":
    var
      msg: seq[uint8] = @[]
      i: int = 0
    while i < 200:
      msg.add uint8(i)
      i = i + 1
    for a in composites:
      var c = sealOf(a, keysFor(a), nonceFor(a), msg)
      check c.ciphertext.len == msg.len
      check c.ciphertext != msg
      check openOf(a, keysFor(a), nonceFor(a), c) == msg

  test "one-shot result equals building the state by hand":
    var msg: seq[uint8] = @[9'u8, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    for a in composites:
      var viaState = seal(msg, initAeadState(a, keysFor(a), nonceFor(a)))
      var viaOneShot = sealOf(a, keysFor(a), nonceFor(a), msg)
      check viaState.ciphertext == viaOneShot.ciphertext
      check viaState.auth == viaOneShot.auth
      check viaState.authType == viaOneShot.authType

  test "a flipped ciphertext byte is refused, never decrypted":
    var msg: seq[uint8] = @[1'u8, 2, 3, 4, 5, 6, 7, 8]
    for a in composites:
      var c = sealOf(a, keysFor(a), nonceFor(a), msg)
      c.ciphertext[0] = c.ciphertext[0] xor 0x01'u8
      expect ValueError:
        discard openOf(a, keysFor(a), nonceFor(a), c)

  test "a flipped tag byte is refused":
    var msg: seq[uint8] = @[1'u8, 2, 3, 4]
    for a in composites:
      var c = sealOf(a, keysFor(a), nonceFor(a), msg)
      c.auth[0] = c.auth[0] xor 0x80'u8
      expect ValueError:
        discard openOf(a, keysFor(a), nonceFor(a), c)

  test "names survive a write-then-read trip":
    for a in CipherSuite:
      check parseCipherSuite(suiteName(a)) == a
    expect ValueError:
      discard parseCipherSuite("no-such-suite")

  test "declared key counts and nonce sizes are what init accepts":
    for a in composites:
      check nonceBytes(a) == 24
      discard initAeadState(a, keysFor(a), nonceFor(a))
      expect ValueError:
        discard initAeadState(a, keysFor(a)[0 ..< keyCount(a) - 1], nonceFor(a))
      expect ValueError:
        discard initAeadState(a, keysFor(a), nonceFor(a)[0 ..< 23])
    check nonceBytes(csAes256Gcm) == 12
    check keyCount(csAes256Gcm) == 1

  test "tag length requests outside 16..32 are refused":
    check initAeadState(csXChaCha20Blake3, keysFor(csXChaCha20Blake3),
      nonceFor(csXChaCha20Blake3)).tagBytes == defaultTagBytes
    expect ValueError:
      discard resolveTagBytes(csXChaCha20Blake3, 15'u16)
    expect ValueError:
      discard resolveTagBytes(csXChaCha20Blake3, 33'u16)
    check resolveTagBytes(csAes256Gcm, 0'u16) == gcmTagBytes
    expect ValueError:
      discard resolveTagBytes(csAes256Gcm, 32'u16)

  test "a state refuses to seal twice on one nonce":
    var st = initAeadState(csXChaCha20Gimli, keysFor(csXChaCha20Gimli),
      nonceFor(csXChaCha20Gimli))
    discard seal(@[0x00'u8], st)
    expect ValueError:
      discard seal(@[0xff'u8], st)

  test "opening stays allowed as often as you like":
    var st = initAeadState(csXChaCha20Gimli, keysFor(csXChaCha20Gimli),
      nonceFor(csXChaCha20Gimli))
    var c = seal(@[0x11'u8, 0x22], st)
    check open(c, st) == @[0x11'u8, 0x22]
    check open(c, st) == @[0x11'u8, 0x22]

  test "only AES-256-GCM reports as a single primitive":
    for a in composites:
      check not isSinglePrimitive(a)
    check isSinglePrimitive(csAes256Gcm)
