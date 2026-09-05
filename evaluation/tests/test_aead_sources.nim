## ---------------------------------------------------------------------
## | AEAD Source Tests <- the suites must honour the derivation choice   |
## | and the default must stay the standard construction                 |
## ---------------------------------------------------------------------
##
## The composites perform two steps with a second algorithm: XChaCha20's
## subkey and Poly1305's one-time key. Both are selectable per state.
## These tests check the wiring actually reaches the cipher rather than
## being accepted and ignored, which is the failure mode that would look
## fine from the outside.

import std/unittest

import ../../src/tyr/aeads
import ../../src/tyr/aeads/dynamic
import ../../src/tyr/ciphers/xchacha20
import ../../src/tyr/macs/poly1305

proc fill(n: int, seed: int): seq[uint8] =
  var i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = uint8((i * 29 + seed * 13 + 7) and 0xff)
    i = i + 1

proc keysFor(a: CipherSuite): seq[seq[uint8]] =
  var i: int = 0
  result = @[]
  while i < keyCount(a):
    result.add(fill(suiteKeyBytes, i + 1))
    i = i + 1

let
  nonce = fill(24, 9)
  msg = fill(180, 4)

## Suites whose cipher layers include XChaCha20, so cipherSource reaches them.
const xchachaSuites = [csXChaCha20Blake3, csXChaCha20Gimli,
  csXChaCha20AesGimli, csXChaCha20AesGimliPoly1305]
## The only suite that uses Poly1305, so macSource reaches it.
const polySuite = csXChaCha20AesGimliPoly1305
## Everything this build can always run.
const composites = [csXChaCha20Blake3, csXChaCha20Gimli, csAesGimli,
  csXChaCha20AesGimli, csXChaCha20AesGimliPoly1305]

suite "aead derivation sources":

  test "the default state uses the standard constructions":
    var st = initAeadState(csXChaCha20Blake3, keysFor(csXChaCha20Blake3), nonce)
    check st.cipherSource == sksHChaCha20
    check st.macSource == pksXChaCha20

  test "a default-built ciphertext matches an explicitly standard one":
    ## Guards the wiring: adding the fields must not have changed what a
    ## caller who never mentions them gets.
    for a in composites:
      var plain = initAeadState(a, keysFor(a), nonce)
      var named = initAeadState(a, keysFor(a), nonce, 0'u16,
        sksHChaCha20, pksXChaCha20)
      var c1 = seal(msg, plain)
      var c2 = seal(msg, named)
      check c1.ciphertext == c2.ciphertext
      check c1.auth == c2.auth

  test "every source combination round-trips":
    for a in composites:
      for cs in SubkeySource:
        for ms in Poly1305KeySource:
          var c = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16, cs, ms))
          check c.ciphertext.len == msg.len
          check open(c, initAeadState(a, keysFor(a), nonce, 0'u16, cs, ms)) == msg

  test "cipherSource actually changes the ciphertext":
    ## If the field were accepted and ignored, these would be equal.
    for a in xchachaSuites:
      var hc = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16, sksHChaCha20))
      var b3 = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16, sksBlake3))
      var gi = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16, sksGimli))
      check hc.ciphertext != b3.ciphertext
      check hc.ciphertext != gi.ciphertext
      check b3.ciphertext != gi.ciphertext

  test "cipherSource is ignored by a suite with no XChaCha20 layer":
    ## csAesGimli is AES-CTR plus Gimli, so there is no subkey to derive.
    var hc = seal(msg, initAeadState(csAesGimli, keysFor(csAesGimli), nonce,
      0'u16, sksHChaCha20))
    var b3 = seal(msg, initAeadState(csAesGimli, keysFor(csAesGimli), nonce,
      0'u16, sksBlake3))
    check hc.ciphertext == b3.ciphertext

  test "macSource actually changes the tag":
    var
      xc = seal(msg, initAeadState(polySuite, keysFor(polySuite), nonce,
        0'u16, sksHChaCha20, pksXChaCha20))
      b3 = seal(msg, initAeadState(polySuite, keysFor(polySuite), nonce,
        0'u16, sksHChaCha20, pksBlake3))
      gi = seal(msg, initAeadState(polySuite, keysFor(polySuite), nonce,
        0'u16, sksHChaCha20, pksGimli))
    ## The ciphertext is untouched by the MAC choice.
    check xc.ciphertext == b3.ciphertext
    check xc.ciphertext == gi.ciphertext
    ## The tag is not.
    check xc.auth != b3.auth
    check xc.auth != gi.auth
    check b3.auth != gi.auth

  test "both sources are bound into every suite's tag":
    ## Even where a source does not affect the ciphertext, it goes into
    ## authFrame, so a peer configured differently fails the tag check
    ## instead of silently decrypting to garbage.
    for a in composites:
      var base = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16,
        sksHChaCha20, pksXChaCha20))
      var otherMac = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16,
        sksHChaCha20, pksGimli))
      var otherCipher = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16,
        sksGimli, pksXChaCha20))
      check base.auth != otherMac.auth
      check base.auth != otherCipher.auth

  test "the suite id is bound too, so tags do not cross suites":
    ## Two suites with the same key count and the same nonce must not
    ## produce interchangeable tags.
    var
      g1 = initAeadState(csXChaCha20Gimli, keysFor(csXChaCha20Gimli), nonce)
      g2 = initAeadState(csAesGimli, keysFor(csAesGimli), nonce)
    check authFrame(msg, g1) != authFrame(msg, g2)

  test "a mismatched source cannot open the message":
    for a in xchachaSuites:
      var c = seal(msg, initAeadState(a, keysFor(a), nonce, 0'u16, sksBlake3))
      expect ValueError:
        discard open(c, initAeadState(a, keysFor(a), nonce, 0'u16, sksHChaCha20))
      expect ValueError:
        discard open(c, initAeadState(a, keysFor(a), nonce, 0'u16, sksGimli))

  test "a mismatched MAC source is refused":
    var c = seal(msg, initAeadState(polySuite, keysFor(polySuite), nonce,
      0'u16, sksHChaCha20, pksBlake3))
    expect ValueError:
      discard open(c, initAeadState(polySuite, keysFor(polySuite), nonce,
        0'u16, sksHChaCha20, pksXChaCha20))

  test "the Poly1305 half of the tag is the derived construction":
    ## The suite appends a 16-byte Poly1305 tag after the Gimli tag, and it
    ## must be the nonce-derived one - never a raw key handed to Poly1305.
    var
      st = initAeadState(polySuite, keysFor(polySuite), nonce)
      c = seal(msg, st)
      gimliLen = int(st.tagBytes)
      polyPart = c.auth[gimliLen ..< c.auth.len]
    check c.auth.len == gimliLen + 16
    check polyPart == poly1305DerivedTag(keysFor(polySuite)[3], nonce,
      authFrame(c.ciphertext, st), pksXChaCha20)
    ## And explicitly NOT the raw one-time form under the same key.
    check polyPart != poly1305Tag(keysFor(polySuite)[3],
      authFrame(c.ciphertext, st))

  test "tampering is still caught under every source combination":
    for cs in SubkeySource:
      for ms in Poly1305KeySource:
        var c = seal(msg, initAeadState(polySuite, keysFor(polySuite), nonce,
          0'u16, cs, ms))
        c.ciphertext[3] = c.ciphertext[3] xor 0x01'u8
        expect ValueError:
          discard open(c, initAeadState(polySuite, keysFor(polySuite), nonce,
            0'u16, cs, ms))

suite "aead sources on the one-shot tier":
  ## `sealOf`/`openOf` used to build their state with the tagBytes argument
  ## and nothing after it, so the sources silently took their defaults and
  ## a caller on this tier had no way to express the choice at all. These
  ## checks are what would have caught that.

  test "the one-shot tier still defaults to the standard route":
    for a in composites:
      check sealOf(a, keysFor(a), nonce, msg).ciphertext ==
        seal(msg, initAeadState(a, keysFor(a), nonce)).ciphertext

  test "a named source reaches the cipher through the one-shot tier":
    for a in xchachaSuites:
      var viaOneShot = sealOf(a, keysFor(a), nonce, msg, 0'u16, sksBlake3)
      check viaOneShot.ciphertext !=
        sealOf(a, keysFor(a), nonce, msg).ciphertext
      check viaOneShot.ciphertext == seal(msg, initAeadState(a, keysFor(a),
        nonce, 0'u16, sksBlake3)).ciphertext

  test "a named MAC source reaches the tag through the one-shot tier":
    var viaOneShot = sealOf(polySuite, keysFor(polySuite), nonce, msg, 0'u16,
      sksHChaCha20, pksGimli)
    check viaOneShot.auth !=
      sealOf(polySuite, keysFor(polySuite), nonce, msg).auth
    check viaOneShot.auth == seal(msg, initAeadState(polySuite,
      keysFor(polySuite), nonce, 0'u16, sksHChaCha20, pksGimli)).auth

  test "every source combination round-trips one-shot":
    for cs in SubkeySource:
      for ms in Poly1305KeySource:
        var c = sealOf(polySuite, keysFor(polySuite), nonce, msg, 0'u16, cs, ms)
        check openOf(polySuite, keysFor(polySuite), nonce, c, 0'u16, cs, ms) ==
          msg

  test "the two tiers interoperate in both directions":
    ## A message sealed one-shot must open through a hand-built state and
    ## the other way round, or the sources mean different things per tier.
    var
      st = initAeadState(polySuite, keysFor(polySuite), nonce, 0'u16,
        sksGimli, pksBlake3)
      oneShot = sealOf(polySuite, keysFor(polySuite), nonce, msg, 0'u16,
        sksGimli, pksBlake3)
    check open(oneShot, initAeadState(polySuite, keysFor(polySuite), nonce,
      0'u16, sksGimli, pksBlake3)) == msg
    check openOf(polySuite, keysFor(polySuite), nonce, seal(msg, st), 0'u16,
      sksGimli, pksBlake3) == msg

  test "a mismatched source is refused on the one-shot tier too":
    var c = sealOf(polySuite, keysFor(polySuite), nonce, msg, 0'u16, sksBlake3)
    expect ValueError:
      discard openOf(polySuite, keysFor(polySuite), nonce, c, 0'u16, sksGimli)
