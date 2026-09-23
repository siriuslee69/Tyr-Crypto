## ---------------------------------------------------------------------
## | HQC PKE <- the encryption underneath the key exchange              |
## ---------------------------------------------------------------------
##
## The one-line idea
## -----------------
## Pick a random long bit string `h`. The secret is two sparse strings
## `x` and `y` - sparse meaning almost all zeros. Publish
##
##   s = x + y*h
##
## Anyone can compute with `h` and `s`, but recovering `x` and `y` from
## them means finding a sparse solution to a huge linear system, which is
## the problem nobody knows how to solve, quantum computer or not.
##
## Encrypting
## ----------
## Draw three more sparse strings r1, r2 and e, then send
##
##   u = r1 + r2*h
##   v = codeword(m) + Truncate(r2*s + e)
##
## Decrypting
## ----------
## Compute v - Truncate(u*y). Substituting the definitions above, almost
## everything cancels:
##
##   v - u*y = codeword(m) + (x*r2 - r1*y + e)
##                            \______________/
##                             all sparse, so this is just NOISE
##
## The leftover is a sparse string, which is exactly the kind of damage
## the concatenated code was built to repair. Strip it off and the
## message comes back.
##
## What "truncate" is doing
## ------------------------
## The codeword is n1n2 bits, which is a little shorter than the n bits
## everything else uses. Truncating throws the surplus away so the two
## line up.
##
## Reference: [HQC-20250822] HQC public-key encryption; ported from the
## reference implementation's `hqc.c` and `parsing.c`.

import runePragmas
import ./params
import ./types
import ./code
import ./gf2x
import ./symmetric
import ./util
import ./vector

include "pke_parse.nim"

## Reference: [HQC-20250822] HQC.PKE key generation; keypair derivation for `pkeKeygen`; pitfall: `y` is sampled before `x` from the decryption stream, and reversing them breaks every stored key.
proc pkeKeygen*(ek: var openArray[byte], dk: var openArray[byte],
    seed: openArray[byte], p: HqcParams, W: var seq[uint64])
    {.role: {orchestrator}, raises: [ValueError].} =
  ## ek/dk/seed/p/W: the public key bytes, the 32-byte secret seed, the
  ## 32-byte input seed, the parameter set, and multiplication scratch.
  ##
  ## Everything below grows from `seed`, so the whole secret key is those
  ## 32 bytes and nothing else.
  var
    keypairSeed = default(array[2 * hqcSeedBytes, byte])
    dkXof = default(HqcXof)
    ekXof = default(HqcXof)
    x: HqcVec = @[]
    y: HqcVec = @[]
    h: HqcVec = @[]
    s: HqcVec = @[]
    sBytes: seq[byte] = @[]
    i: int = 0
  x = newHqcVec(p.vecNWords)
  y = newHqcVec(p.vecNWords)
  h = newHqcVec(p.vecNWords)
  s = newHqcVec(p.vecNWords)
  ## One seed in, two seeds out: one for the secret, one for the public part.
  hashI(keypairSeed, seed)
  xofInit(dkXof, keypairSeed.toOpenArray(0, hqcSeedBytes - 1))
  sampleFixedWeightKey(y, dkXof, p.omega, p)
  sampleFixedWeightKey(x, dkXof, p.omega, p)
  xofClear(dkXof)
  xofInit(ekXof, keypairSeed.toOpenArray(hqcSeedBytes, 2 * hqcSeedBytes - 1))
  vecSetRandom(h, ekXof, p)
  xofClear(ekXof)
  ## s = x + y*h. This is the whole public key, bar the seed for h.
  vecMul(s, y, h, p, W)
  hqcVecAdd(s, x, s, p.vecNWords)
  i = 0
  while i < hqcSeedBytes:
    ek[i] = keypairSeed[hqcSeedBytes + i]
    dk[i] = keypairSeed[i]
    i = i + 1
  sBytes = hqcVecToByteSeq(s, p.vecNBytes)
  i = 0
  while i < p.vecNBytes:
    ek[hqcSeedBytes + i] = sBytes[i]
    i = i + 1
  hqcWipeBytes(keypairSeed)
  hqcWipeBytes(sBytes)
  hqcWipeWords(x)
  hqcWipeWords(y)

## Reference: [HQC-20250822] HQC.PKE encryption; ciphertext construction for `pkeEncrypt`; pitfall: r2, e and r1 come off the stream in that order, and swapping any two changes every ciphertext.
include "pke_encdec.nim"
