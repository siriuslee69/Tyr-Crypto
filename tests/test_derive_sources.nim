## ---------------------------------------------------------------------
## | Derive Source Tests <- swappable key/subkey derivation             |
## | the default must stay bit-identical to the standard construction   |
## ---------------------------------------------------------------------

import std/unittest

import ../src/tyr/ciphers/xchacha20
import ../src/tyr/macs/poly1305

proc fill(n: int, seed: int): seq[byte] =
  var i: int = 0
  result = newSeq[byte](n)
  while i < n:
    result[i] = byte((i * 31 + seed * 17 + 5) and 0xff)
    i = i + 1

let
  key   = fill(32, 1)
  nonce = fill(24, 2)
  msg   = fill(200, 3)

suite "xchacha20 subkey sources":

  test "the default is bit-identical to plain XChaCha20":
    ## If this ever fails, the variant path has drifted from the standard
    ## one and every xchacha20b3/gi claim below is suspect too.
    check xchacha20VariantXor(key, nonce, msg) == xchacha20Xor(key, nonce, msg)
    check xchacha20VariantXor(key, nonce, msg, sksHChaCha20) ==
      xchacha20Xor(key, nonce, msg)
    check xchacha20VariantStream(key, nonce, 128) ==
      xchacha20Stream(key, nonce, 128)

  test "the default subkey is exactly HChaCha20's":
    var head = fill(24, 2)[0 ..< 16]
    check @(xchacha20Subkey(sksHChaCha20, key, nonce)) == @(hchacha20(key, head))

  test "every source round-trips":
    for s in SubkeySource:
      var ct = xchacha20VariantXor(key, nonce, msg, s)
      check ct.len == msg.len
      check ct != msg
      check xchacha20VariantXor(key, nonce, ct, s) == msg
    check xchacha20b3Xor(key, nonce, xchacha20b3Xor(key, nonce, msg)) == msg
    check xchacha20giXor(key, nonce, xchacha20giXor(key, nonce, msg)) == msg

  test "the three sources disagree with each other":
    var
      hc = xchacha20VariantXor(key, nonce, msg, sksHChaCha20)
      b3 = xchacha20b3Xor(key, nonce, msg)
      gi = xchacha20giXor(key, nonce, msg)
    check hc != b3
    check hc != gi
    check b3 != gi
    check @(xchacha20Subkey(sksHChaCha20, key, nonce)) !=
      @(xchacha20Subkey(sksBlake3, key, nonce))
    check @(xchacha20Subkey(sksBlake3, key, nonce)) !=
      @(xchacha20Subkey(sksGimli, key, nonce))

  test "a variant cannot open what another variant sealed":
    var b3 = xchacha20b3Xor(key, nonce, msg)
    check xchacha20giXor(key, nonce, b3) != msg
    check xchacha20Xor(key, nonce, b3) != msg

  test "the subkey changes with the nonce, for every source":
    var other = fill(24, 99)
    for s in SubkeySource:
      check @(xchacha20Subkey(s, key, nonce)) != @(xchacha20Subkey(s, key, other))

  test "names survive a write-then-read trip":
    for s in SubkeySource:
      check parseSubkeySource(sourceName(s)) == s
    check sourceName(sksHChaCha20) == "hc"
    check sourceName(sksBlake3) == "b3"
    check sourceName(sksGimli) == "gi"
    expect ValueError:
      discard parseSubkeySource("zz")

  test "wrong key or nonce size is refused by every source":
    for s in SubkeySource:
      expect ValueError:
        discard xchacha20Subkey(s, fill(31, 1), nonce)
      expect ValueError:
        discard xchacha20Subkey(s, key, fill(23, 2))

suite "poly1305 one-time key sources":

  test "the default is the standard XChaCha20 keystream route":
    check poly1305DeriveKey(pksXChaCha20, key, nonce) ==
      xchacha20Stream(key, nonce, 32, 0'u32)
    check poly1305DerivedTag(key, nonce, msg) ==
      poly1305xcTag(key, nonce, msg)

  test "every source produces a verifiable tag":
    for s in Poly1305KeySource:
      var tag = poly1305DerivedTag(key, nonce, msg, s)
      check tag.len == 16
      check poly1305DerivedVerify(key, nonce, msg, tag, s)
    check poly1305xcVerify(key, nonce, msg, poly1305xcTag(key, nonce, msg))
    check poly1305b3Verify(key, nonce, msg, poly1305b3Tag(key, nonce, msg))
    check poly1305giVerify(key, nonce, msg, poly1305giTag(key, nonce, msg))

  test "the three sources disagree with each other":
    var
      xc = poly1305xcTag(key, nonce, msg)
      b3 = poly1305b3Tag(key, nonce, msg)
      gi = poly1305giTag(key, nonce, msg)
    check xc != b3
    check xc != gi
    check b3 != gi
    check poly1305DeriveKey(pksXChaCha20, key, nonce) !=
      poly1305DeriveKey(pksBlake3, key, nonce)
    check poly1305DeriveKey(pksBlake3, key, nonce) !=
      poly1305DeriveKey(pksGimli, key, nonce)

  test "a tag from one source does not verify under another":
    var b3 = poly1305b3Tag(key, nonce, msg)
    check not poly1305xcVerify(key, nonce, msg, b3)
    check not poly1305giVerify(key, nonce, msg, b3)

  test "an altered message is refused by every source":
    var altered = fill(200, 3)
    altered[7] = altered[7] xor 0x01'u8
    for s in Poly1305KeySource:
      var tag = poly1305DerivedTag(key, nonce, msg, s)
      check not poly1305DerivedVerify(key, nonce, altered, tag, s)

  test "the one-time key changes with the nonce, for every source":
    ## This is the property the whole construction rests on: a fresh
    ## nonce must give a fresh (r, s), or Poly1305's key is recoverable.
    var other = fill(24, 77)
    for s in Poly1305KeySource:
      check poly1305DeriveKey(s, key, nonce) != poly1305DeriveKey(s, key, other)
      check poly1305DerivedTag(key, nonce, msg, s) !=
        poly1305DerivedTag(key, other, msg, s)

  test "names survive a write-then-read trip":
    for s in Poly1305KeySource:
      check parsePoly1305KeySource(sourceName(s)) == s
    check sourceName(pksXChaCha20) == "xc"
    check sourceName(pksBlake3) == "b3"
    check sourceName(pksGimli) == "gi"
    expect ValueError:
      discard parsePoly1305KeySource("zz")

  test "wrong master key or nonce size is refused by every source":
    for s in Poly1305KeySource:
      expect ValueError:
        discard poly1305DeriveKey(s, fill(31, 1), nonce)
      expect ValueError:
        discard poly1305DeriveKey(s, key, fill(12, 2))
