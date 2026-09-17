## ---------------------------------------------------------------------
## | HQC Tyr <- the pure-Nim HQC backend, checked from the inside out   |
## ---------------------------------------------------------------------
##
## Four layers, checked bottom first, so a failure names the layer that
## broke rather than only the end result:
##
##   GF(2^8)          one byte times one byte
##   Reed-Solomon     bytes repaired, up to delta of them
##   Reed-Muller      one byte out of a very noisy block
##   polynomial       two long bit strings multiplied
##   key exchange     the whole thing, including rejection behaviour
##
## Reference: [HQC-20250822] HQC specification of 2025-08-22.

{.define: tyrCryptoTestHooks.}

import std/[bitops, random, unittest]

import runePragmas
import ../../src/tyr/kems/hqc as custom_hqc
import ../../src/tyr/kems/hqc/gf as hqc_gf
import ../../src/tyr/kems/hqc/gf2x as hqc_gf2x
import ../../src/tyr/kems/hqc/reed_muller as hqc_rm
import ../../src/tyr/kems/hqc/reed_solomon as hqc_rs
import ../../src/tyr/kems/hqc/symmetric as hqc_sym
import ../../src/tyr/kems/hqc/types as hqc_types
import ../../src/tyr/kems/hqc/util as hqc_util
import ../../src/tyr/kems/hqc/vector as hqc_vector
import ../../src/tyr/kems

const
  hqcAllVariants = [custom_hqc.hqc1, custom_hqc.hqc3, custom_hqc.hqc5]

## Reference: [HQC-20250822] test support; deterministic filler for `fillHqcPattern`; pitfall: the pattern only has to be fixed, not random.
proc fillHqcPattern(A: var seq[byte], base: int) {.role: {helper}.} =
  ## A/base: the buffer to fill and where the pattern starts.
  var
    i: int = 0
  while i < A.len:
    A[i] = byte((base + i * 7) mod 256)
    i = i + 1

## Reference: [HQC-20250822] test support; weight measurement for `hqcBitWeight`; pitfall: counts every word, so the caller must pass a vector with clean padding.
proc hqcBitWeight(V: hqc_types.HqcVec): int {.role: {math}.} =
  ## V: the bit string to weigh.
  var
    i: int = 0
  while i < V.len:
    result = result + countSetBits(V[i])
    i = i + 1

## Reference: [HQC-20250822] test support; independent product for `hqcNaiveMul`; pitfall: this is the slow definition of the product, kept deliberately unlike the fast one.
proc hqcNaiveMul(A, B: hqc_types.HqcVec, p: HqcParams): hqc_types.HqcVec
    {.role: {math}.} =
  ## A/B/p: the two bit strings and the parameter set.
  ## Multiply modulo x^n - 1 the obvious way: for every pair of set bits,
  ## flip the bit at the sum of their positions.
  var
    i: int = 0
    j: int = 0
    k: int = 0
  result = hqc_util.newHqcVec(p.vecNWords)
  while i < p.n:
    if ((A[i shr 6] shr (i and 63)) and 1'u64) == 1'u64:
      j = 0
      while j < p.n:
        if ((B[j shr 6] shr (j and 63)) and 1'u64) == 1'u64:
          k = (i + j) mod p.n
          result[k shr 6] = result[k shr 6] xor (1'u64 shl (k and 63))
        j = j + 1
    i = i + 1

suite "hqc tyr":
  # {.testKind: tkUnit.}
  test "GF(2^8) multiplication agrees with the logarithm tables":
    var
      mismatches: int = 0
      want: uint16 = 0
      a: int = 0
      b: int = 0
    while a < 256:
      b = 0
      while b < 256:
        want = 0
        if a != 0 and b != 0:
          want = hqc_gf.gfExp[(int(hqc_gf.gfLog[a]) + int(hqc_gf.gfLog[b])) mod 255]
        if hqc_gf.gfMul(uint16(a), uint16(b)) != want:
          mismatches = mismatches + 1
        b = b + 1
      a = a + 1
    check mismatches == 0

  # {.testKind: tkUnit.}
  test "GF(2^8) inversion undoes multiplication":
    var
      mismatches: int = 0
      a: int = 1
    while a < 256:
      if hqc_gf.gfMul(uint16(a), hqc_gf.gfInverse(uint16(a))) != 1'u16:
        mismatches = mismatches + 1
      a = a + 1
    check mismatches == 0

  # {.testKind: tkUnit.}
  test "Reed-Solomon repairs exactly delta damaged bytes":
    for v in hqcAllVariants:
      var
        p = params(v)
        G = genPoly(v)
        msg: seq[byte] = @[]
        cdw: seq[byte] = @[]
        damaged: seq[byte] = @[]
        back: seq[byte] = @[]
        i: int = 0
      msg = newSeq[byte](p.messageBytes)
      fillHqcPattern(msg, 3)
      cdw = newSeq[byte](p.n1)
      back = newSeq[byte](p.messageBytes)
      hqc_rs.reedSolomonEncode(cdw, msg, p, G)
      hqc_rs.reedSolomonDecode(back, cdw, p)
      check back == msg
      damaged = cdw
      i = 0
      while i < p.delta:
        damaged[i * 2] = damaged[i * 2] xor byte(0x5a + i)
        i = i + 1
      hqc_rs.reedSolomonDecode(back, damaged, p)
      check back == msg

  # {.testKind: tkEdgeCase.}
  test "Reed-Muller survives a third of its bits being flipped":
    var
      r = initRand(20250822)
    for v in hqcAllVariants:
      var
        p = params(v)
        msg: seq[byte] = @[]
        back: seq[byte] = @[]
        cdw: hqc_types.HqcVec = @[]
        wrong: int = 0
        flips: int = 0
        bit: int = 0
        i: int = 0
      msg = newSeq[byte](p.n1)
      back = newSeq[byte](p.n1)
      i = 0
      while i < p.n1:
        msg[i] = byte(r.rand(255))
        i = i + 1
      cdw = hqc_util.newHqcVec(p.vecNWords)
      hqc_rm.reedMullerEncode(cdw, msg, p)
      flips = p.n1n2 div 3
      i = 0
      while i < flips:
        bit = r.rand(p.n1n2 - 1)
        cdw[bit shr 6] = cdw[bit shr 6] xor (1'u64 shl (bit and 63))
        i = i + 1
      hqc_rm.reedMullerDecode(back, cdw, p)
      wrong = 0
      i = 0
      while i < p.n1:
        if back[i] != msg[i]:
          wrong = wrong + 1
        i = i + 1
      check wrong == 0

  # {.testKind: tkProperty.}
  test "Karatsuba multiplication agrees with the slow definition":
    for v in hqcAllVariants:
      var
        p = params(v)
        W: seq[uint64] = @[]
        X = default(hqc_sym.HqcXof)
        seed: seq[byte] = @[]
        a: hqc_types.HqcVec = @[]
        b: hqc_types.HqcVec = @[]
        got: hqc_types.HqcVec = @[]
        one: hqc_types.HqcVec = @[]
        identity: hqc_types.HqcVec = @[]
      seed = newSeq[byte](32)
      fillHqcPattern(seed, ord(v) * 11 + 5)
      W = hqc_gf2x.newHqcMulScratch(p)
      a = hqc_util.newHqcVec(p.vecNWords)
      b = hqc_util.newHqcVec(p.vecNWords)
      got = hqc_util.newHqcVec(p.vecNWords)
      one = hqc_util.newHqcVec(p.vecNWords)
      identity = hqc_util.newHqcVec(p.vecNWords)
      hqc_sym.xofInit(X, seed)
      hqc_vector.sampleFixedWeightKey(a, X, p.omega, p)
      hqc_vector.sampleFixedWeightEnc(b, X, p.omegaR, p)
      check hqcBitWeight(a) == p.omega
      check hqcBitWeight(b) == p.omegaR
      hqc_gf2x.vecMul(got, a, b, p, W)
      check got == hqcNaiveMul(a, b, p)
      one[0] = 1'u64
      hqc_gf2x.vecMul(identity, b, one, p, W)
      check identity == b

  # {.testKind: tkUnit.}
  test "pure-nim HQC roundtrip matches shared secret and published sizes":
    for v in hqcAllVariants:
      var
        p = params(v)
        keypairRandom: seq[byte] = @[]
        encapsRandom: seq[byte] = @[]
      keypairRandom = newSeq[byte](p.keypairRandomBytes)
      encapsRandom = newSeq[byte](p.encapsRandomBytes)
      fillHqcPattern(keypairRandom, 17)
      fillHqcPattern(encapsRandom, 91)
      var
        kp = custom_hqc.hqcTyrKeypairDerand(v, keypairRandom)
        env = custom_hqc.hqcTyrEncapsDerand(v, kp.publicKey, encapsRandom)
        shared = custom_hqc.hqcTyrDecaps(v, kp.secretKey, env.ciphertext)
      check shared == env.sharedSecret
      check kp.publicKey.len == p.publicKeyBytes
      check kp.secretKey.len == p.secretKeyBytes
      check env.ciphertext.len == p.ciphertextBytes
      check env.sharedSecret.len == 32

  # {.testKind: tkRegression.}
  test "published byte lengths are what the specification prints":
    check params(custom_hqc.hqc1).publicKeyBytes == 2241
    check params(custom_hqc.hqc1).secretKeyBytes == 2321
    check params(custom_hqc.hqc1).ciphertextBytes == 4433
    check params(custom_hqc.hqc3).publicKeyBytes == 4514
    check params(custom_hqc.hqc3).secretKeyBytes == 4602
    check params(custom_hqc.hqc3).ciphertextBytes == 8978
    check params(custom_hqc.hqc5).publicKeyBytes == 7237
    check params(custom_hqc.hqc5).secretKeyBytes == 7333
    check params(custom_hqc.hqc5).ciphertextBytes == 14421

  # {.testKind: tkRegression.}
  test "the same seed always gives the same keypair and ciphertext":
    var
      p = params(custom_hqc.hqc1)
      keypairRandom: seq[byte] = @[]
      encapsRandom: seq[byte] = @[]
    keypairRandom = newSeq[byte](p.keypairRandomBytes)
    encapsRandom = newSeq[byte](p.encapsRandomBytes)
    fillHqcPattern(keypairRandom, 41)
    fillHqcPattern(encapsRandom, 67)
    var
      first = custom_hqc.hqcTyrKeypairDerand(custom_hqc.hqc1, keypairRandom)
      second = custom_hqc.hqcTyrKeypairDerand(custom_hqc.hqc1, keypairRandom)
    check first.publicKey == second.publicKey
    check first.secretKey == second.secretKey
    var
      envA = custom_hqc.hqcTyrEncapsDerand(custom_hqc.hqc1, first.publicKey, encapsRandom)
      envB = custom_hqc.hqcTyrEncapsDerand(custom_hqc.hqc1, first.publicKey, encapsRandom)
    check envA.ciphertext == envB.ciphertext
    check envA.sharedSecret == envB.sharedSecret

  # {.testKind: tkEdgeCase.}
  test "the public key carries its own seed, so it regrows h":
    var
      p = params(custom_hqc.hqc1)
      keypairRandom: seq[byte] = @[]
    keypairRandom = newSeq[byte](p.keypairRandomBytes)
    fillHqcPattern(keypairRandom, 23)
    var kp = custom_hqc.hqcTyrKeypairDerand(custom_hqc.hqc1, keypairRandom)
    ## The secret key begins with a verbatim copy of the public key, which
    ## is what lets decapsulation re-encrypt without being handed one.
    check kp.secretKey[0 ..< p.publicKeyBytes] == kp.publicKey

  # {.testKind: tkEdgeCase.}
  test "a tampered HQC ciphertext is rejected without saying so":
    ## Two ways to damage a ciphertext, and neither may be reported.
    ## `hqcTyrTryDecaps` only exists under `-d:tyrCryptoTestHooks`; without
    ## it the same behaviour is checked from the outside, which is all a
    ## real caller can see anyway.
    var
      p = params(custom_hqc.hqc1)
      keypairRandom: seq[byte] = @[]
      encapsRandom: seq[byte] = @[]
      damaged: seq[byte] = @[]
      damagedSalt: seq[byte] = @[]
    keypairRandom = newSeq[byte](p.keypairRandomBytes)
    encapsRandom = newSeq[byte](p.encapsRandomBytes)
    fillHqcPattern(keypairRandom, 53)
    fillHqcPattern(encapsRandom, 149)
    var
      kp = custom_hqc.hqcTyrKeypairDerand(custom_hqc.hqc1, keypairRandom)
      env = custom_hqc.hqcTyrEncapsDerand(custom_hqc.hqc1, kp.publicKey, encapsRandom)
    damaged = env.ciphertext
    damaged[0] = damaged[0] xor 1'u8
    ## Damaging the salt alone must be rejected too, because the salt is
    ## hashed into both the shared secret and the encryption randomness.
    damagedSalt = env.ciphertext
    damagedSalt[p.ciphertextBytes - 1] = damagedSalt[p.ciphertextBytes - 1] xor 0x80'u8
    check custom_hqc.hqcTyrDecaps(custom_hqc.hqc1, kp.secretKey, env.ciphertext) ==
      env.sharedSecret
    ## A rejected answer is still a normal-looking 32-byte secret.
    var rejected = custom_hqc.hqcTyrDecaps(custom_hqc.hqc1, kp.secretKey, damaged)
    check rejected.len == 32
    check rejected != env.sharedSecret
    rejected = custom_hqc.hqcTyrDecaps(custom_hqc.hqc1, kp.secretKey, damagedSalt)
    check rejected.len == 32
    check rejected != env.sharedSecret
    when declared(hqcTyrTryDecaps):
      ## With the test hook compiled in, check the diagnostic flag agrees.
      var
        good = custom_hqc.hqcTyrTryDecaps(custom_hqc.hqc1, kp.secretKey, env.ciphertext)
        bad = custom_hqc.hqcTyrTryDecaps(custom_hqc.hqc1, kp.secretKey, damaged)
        badSalt = custom_hqc.hqcTyrTryDecaps(custom_hqc.hqc1, kp.secretKey, damagedSalt)
      check good.ok
      check good.sharedSecret == env.sharedSecret
      check not bad.ok
      check not badSalt.ok

  # {.testKind: tkEdgeCase.}
  test "wrong-length inputs are refused rather than guessed at":
    var
      p = params(custom_hqc.hqc1)
      keypairRandom: seq[byte] = @[]
      encapsRandom: seq[byte] = @[]
    keypairRandom = newSeq[byte](p.keypairRandomBytes)
    encapsRandom = newSeq[byte](p.encapsRandomBytes)
    fillHqcPattern(keypairRandom, 71)
    fillHqcPattern(encapsRandom, 13)
    var
      kp = custom_hqc.hqcTyrKeypairDerand(custom_hqc.hqc1, keypairRandom)
      env = custom_hqc.hqcTyrEncapsDerand(custom_hqc.hqc1, kp.publicKey, encapsRandom)
    expect ValueError:
      discard custom_hqc.hqcTyrKeypairDerand(custom_hqc.hqc1, newSeq[byte](31))
    expect ValueError:
      discard custom_hqc.hqcTyrEncapsDerand(custom_hqc.hqc1, kp.publicKey,
        newSeq[byte](p.encapsRandomBytes - 1))
    expect ValueError:
      discard custom_hqc.hqcTyrEncapsDerand(custom_hqc.hqc1,
        kp.publicKey[0 ..< p.publicKeyBytes - 1], encapsRandom)
    expect ValueError:
      discard custom_hqc.hqcTyrDecaps(custom_hqc.hqc1,
        kp.secretKey[0 ..< p.secretKeyBytes - 1], env.ciphertext)
    expect ValueError:
      discard custom_hqc.hqcTyrDecaps(custom_hqc.hqc1, kp.secretKey,
        env.ciphertext[0 ..< p.ciphertextBytes - 1])

  # {.testKind: tkIntegration.}
  test "HQC reaches the default and dynamic KEM tiers":
    var
      p = params(custom_hqc.hqc1)
      keypairRandom: seq[byte] = @[]
      encapsRandom: seq[byte] = @[]
    keypairRandom = newSeq[byte](p.keypairRandomBytes)
    encapsRandom = newSeq[byte](p.encapsRandomBytes)
    fillHqcPattern(keypairRandom, 101)
    fillHqcPattern(encapsRandom, 199)
    var kp = keypair(custom_hqc.hqc1, keypairRandom)
    check kp.family == kfHqc
    var env = encaps(custom_hqc.hqc1, kp.public, encapsRandom)
    check env.family == kfHqc
    check decaps(custom_hqc.hqc1, kp.secret, env.ciphertext) == env.shared
    check familyName(kfHqc) == "hqc"
    check parseKemFamily("hqc") == kfHqc

  # {.testKind: tkSmoke.}
  test "unseeded HQC keypairs differ from each other":
    var
      first = custom_hqc.hqcTyrKeypair(custom_hqc.hqc1)
      second = custom_hqc.hqcTyrKeypair(custom_hqc.hqc1)
    check first.publicKey != second.publicKey
    var env = custom_hqc.hqcTyrEncaps(custom_hqc.hqc1, first.publicKey)
    check custom_hqc.hqcTyrDecaps(custom_hqc.hqc1, first.secretKey, env.ciphertext) ==
      env.sharedSecret

  # {.testKind: tkUnit.}
  test "variant names survive a round trip through text":
    for v in hqcAllVariants:
      check parseHqcVariant(variantName(v)) == v
    expect ValueError:
      discard parseHqcVariant("hqc-2")


