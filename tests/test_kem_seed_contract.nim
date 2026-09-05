## ==============================================================
## | KEM Seed Contract                                          |
## | -> a seed either reproduces a key pair, or it is refused   |
## ==============================================================
##
## Two arguments of `genKeypair` and `encaps` look alike:
##
##   seed          "give me THIS key pair again"  -> must reproduce
##   extraEntropy  "stir this in as well"         -> must NOT reproduce
##
## The danger is a tier that accepts a `seed`, cannot honour it, and
## hands back a different key every call anyway. A caller would only
## notice when it tried to rebuild a key it no longer had. These tests
## hold both halves of the contract in place.

import std/unittest
import metaPragmas

import ../src/tyr

proc patternSeed(n, base: int): seq[uint8] {.role: {helper}.} =
  ## n: how many bytes are wanted.
  ## base: first byte value of the repeating pattern.
  result = newSeq[uint8](n)
  var i: int = 0
  while i < n:
    result[i] = uint8((base + i) and 0xff)
    i = i + 1

const
  libraryTiers: array[13, KemAlgorithm] = [
    kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
    kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake,
    kaFrodo2Aes, kaFrodo2Shake, kaNtruPrime0, kaBike0
  ]
    ## Every tier whose randomness comes from liboqs.

suite "kem seed contract":
  # {.testKind: tkUnit, covers: "genKeypair".}
  test "a seed reproduces the key pair on the tier that supports it":
    var
      S = patternSeed(32, 11)
      a = genKeypair(kaX25519, S)
      b = genKeypair(kaX25519, S)
    check a.publicKey == b.publicKey
    check a.secretKey == b.secretKey

  # {.testKind: tkRegression, covers: "genKeypair", pins: "seed silently ignored by library-backed KEM tiers".}
  test "a seed is refused by every library-backed tier":
    var
      S = patternSeed(32, 23)
      i: int = 0
    while i < libraryTiers.len:
      expect ValueError:
        discard genKeypair(libraryTiers[i], S)
      i = i + 1

  # {.testKind: tkRegression, covers: "encaps", pins: "seed silently ignored by library-backed KEM tiers".}
  test "encapsulation refuses a seed on a library-backed tier":
    ## The refusal happens before the library is reached, so a public key
    ## the right size is enough - no liboqs build is needed here.
    var
      S = patternSeed(32, 37)
      pk = newSeq[uint8](1184)
    expect ValueError:
      discard encaps(kaKyber0, pk, seed = S)

  when defined(hasLibOqs):
    # {.testKind: tkUnit, covers: "genKeypair, encaps".}
    test "extra entropy is accepted and stays unpredictable":
      var
        E = patternSeed(48, 53)
        a = genKeypair(kaKyber0, extraEntropy = E)
        b = genKeypair(kaKyber0, extraEntropy = E)
        c0 = encaps(kaKyber0, a.publicKey, extraEntropy = E)
        c1 = encaps(kaKyber0, a.publicKey, extraEntropy = E)
      check a.publicKey != b.publicKey
      check c0.envelope.ciphertext != c1.envelope.ciphertext
      # Both envelopes must still open to their own secret.
      check decaps(kaKyber0, a.secretKey, c0.envelope) == c0.sharedSecret
      check decaps(kaKyber0, a.secretKey, c1.envelope) == c1.sharedSecret

    # {.testKind: tkEdgeCase, covers: "genKeypair".}
    test "an empty seed is not a seed":
      var
        empty: seq[uint8] = @[]
        kp = genKeypair(kaKyber0, empty)
      check kp.publicKey.len > 0
      check kp.secretKey.len > 0
