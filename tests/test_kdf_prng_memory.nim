## ---------------------------------------------------------------------
## | KDF, PRNG and Zeroization Tests <- the plumbing nothing else covers |
## ---------------------------------------------------------------------
##
## Three areas with no direct coverage before this file:
##
##   the custom memory-hard KDF and the BLAKE3+Gimli staged KDF
##   the CSPRNG, including its entropy-mixing mode
##   secure_memory, which is what actually erases key material
##
## These are not algorithms with published test vectors, so the checks
## here are structural: determinism where it is promised, separation where
## it is required, and non-determinism where the whole point is entropy.

import std/[sets, unittest]

import ../src/tyr/kdfs
import ../src/tyr/kdfs/kdf
import ../src/tyr/kdfs/blake3_gimli_kdf
import ../src/tyr/helpers/random
import ../src/tyr/helpers/tiers
import ../src/tyr/helpers/secure_memory

proc fill(n: int, seed: int): seq[byte] =
  var i: int = 0
  result = newSeq[byte](n)
  while i < n:
    result[i] = byte((i * 23 + seed * 19 + 11) and 0xff)
    i = i + 1

proc allZero(b: openArray[byte]): bool =
  result = true
  for x in b:
    if x != 0'u8:
      return false

let
  secret = fill(32, 1)
  salt = fill(16, 2)

suite "custom memory-hard KDF":

  test "output is deterministic for one input":
    var a = deriveCustomKdf(secret, ckaBlake3, 2, 4096, 1, 64)
    check a == deriveCustomKdf(secret, ckaBlake3, 2, 4096, 1, 64)
    check a.len > 0

  test "a changed secret changes the output":
    var other = fill(32, 42)
    check deriveCustomKdf(secret, ckaBlake3, 2, 4096, 1, 64) !=
      deriveCustomKdf(other, ckaBlake3, 2, 4096, 1, 64)

  test "each generator gives a different result":
    ## The generator choice must actually reach the mixing loop.
    var seen = initHashSet[seq[byte]]()
    for g in CustomKdfAlgorithm:
      seen.incl(deriveCustomKdf(secret, g, 2, 4096, 1, 64))
    check seen.len == ord(high(CustomKdfAlgorithm)) + 1

  test "more passes or more memory changes the output":
    var base = deriveCustomKdf(secret, ckaBlake3, 2, 4096, 1, 64)
    check base != deriveCustomKdf(secret, ckaBlake3, 3, 4096, 1, 64)
    check base != deriveCustomKdf(secret, ckaBlake3, 2, 8192, 1, 64)

suite "BLAKE3 + Gimli staged KDF":

  test "stages are separated":
    ## Two stages of one derivation must not produce the same key, or the
    ## staging buys nothing.
    var
      cfg = initBlake3GimliKdfConfig(keyBytes = 32)
      s1 = deriveBlake3GimliStageKey(secret, salt, 1, cfg = cfg)
      s2 = deriveBlake3GimliStageKey(secret, salt, 2, cfg = cfg)
    check s1.len == 32
    check s1 != s2

  test "stage 0 and below are refused":
    var cfg = initBlake3GimliKdfConfig(keyBytes = 32)
    expect ValueError:
      discard deriveBlake3GimliStageKey(secret, salt, 0, cfg = cfg)

  test "the salt separates derivations":
    var
      cfg = initBlake3GimliKdfConfig(keyBytes = 32)
      other = fill(16, 88)
    check deriveBlake3GimliStageKey(secret, salt, 1, cfg = cfg) !=
      deriveBlake3GimliStageKey(secret, other, 1, cfg = cfg)

  test "the kdfs umbrella reaches a working stage":
    ## Regression: `deriveKey(kdfBlake3Gimli, ...)` used to pass stage 0
    ## and raise "invalid stage" on every call.
    check deriveKey(kdfBlake3Gimli, secret, salt, 32).len == 32

suite "CSPRNG":

  test "requested lengths are honoured, including zero":
    for n in [0, 1, 16, 32, 200]:
      check cryptoRandomBytes(n).len == n

  test "successive draws differ":
    ## A generator that repeats is the failure this catches; 8 identical
    ## 32-byte draws is not something a working CSPRNG produces.
    var seen = initHashSet[seq[uint8]]()
    for i in 0 ..< 8:
      seen.incl(cryptoRandomBytes(32))
    check seen.len == 8

  test "output is not left zeroed":
    var anyNonZero = false
    for i in 0 ..< 4:
      if not allZero(cryptoRandomBytes(32)):
        anyNonZero = true
    check anyNonZero

  test "entropy mixing still returns fresh bytes":
    var extra = fill(32, 5)
    var seen = initHashSet[seq[uint8]]()
    for i in 0 ..< 8:
      seen.incl(cryptoRandomBytes(32, extra))
    check seen.len == 8

  test "both randomness tiers work and stay distinct":
    check cryptoRand(raSystem, 32).len == 32
    check cryptoRand(raSystemMixed, 32, fill(16, 6)).len == 32
    var seen = initHashSet[seq[uint8]]()
    for i in 0 ..< 4:
      seen.incl(cryptoRand(raSystem, 32))
      seen.incl(cryptoRand(raSystemMixed, 32, fill(16, 6)))
    check seen.len == 8

suite "secure memory":

  test "secureClearBytes erases a seq":
    var b = fill(64, 7)
    check not allZero(b)
    secureClearBytes(b)
    check allZero(b)

  test "clearing an empty seq is safe":
    var b: seq[byte] = @[]
    secureClearBytes(b)
    check b.len == 0

  test "secureClearPod erases a fixed array":
    var a: array[32, byte]
    for i in 0 ..< a.len:
      a[i] = byte(i + 1)
    check not allZero(a)
    secureClearPod(a)
    check allZero(a)

  test "erasing a derived key leaves nothing behind":
    ## The realistic shape: derive, use, wipe.
    var k = deriveKey(kdfArgon2id, secret, salt, 32, 1, 64, 1)
    check not allZero(k)
    secureClearBytes(k)
    check allZero(k)
