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

## Reference: [HQC-20250822] encryption key parsing; public-key expansion for `ekFromString`; pitfall: `h` is never stored, only the 32-byte seed it grows from.
proc ekFromString(h, s: var HqcVec, ek: openArray[byte], p: HqcParams)
    {.role: {parser}, raises: [ValueError].} =
  ## h/s/ek/p: the two halves of the public key, its bytes, the parameters.
  ##
  ## Only `s` travels as data. `h` is regrown from the 32-byte seed that
  ## sits in front of it, which is why the public key is barely longer
  ## than one bit string instead of two.
  var
    X = default(HqcXof)
    i: int = 0
  xofInit(X, ek.toOpenArray(0, hqcSeedBytes - 1))
  vecSetRandom(h, X, p)
  xofClear(X)
  i = 0
  while i < p.vecNWords:
    s[i] = 0'u64
    i = i + 1
  hqcBytesToWords(s, ek, hqcSeedBytes, p.vecNBytes)

## Reference: [HQC-20250822] decryption key parsing; secret expansion for `dkFromString`; pitfall: this must draw the SAME first fixed-weight vector that key generation drew, so the sampler and its order cannot change.
proc dkFromString(y: var HqcVec, dk: openArray[byte], p: HqcParams)
    {.role: {parser}, raises: [ValueError].} =
  ## y/dk/p: the recovered secret vector, its 32-byte seed, the parameters.
  ## Regrow the secret `y` from the seed key generation kept.
  var
    X = default(HqcXof)
    i: int = 0
  i = 0
  while i < p.vecNWords:
    y[i] = 0'u64
    i = i + 1
  xofInit(X, dk.toOpenArray(0, hqcSeedBytes - 1))
  sampleFixedWeightKey(y, X, p.omega, p)
  xofClear(X)

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
proc pkeEncrypt*(c: var HqcPkeCipher, ek: openArray[byte], m: openArray[byte],
    theta: openArray[byte], p: HqcParams, G: openArray[uint16],
    W: var seq[uint64]) {.role: {encryptor}, raises: [ValueError].} =
  ## c/ek/m/theta/p/G/W: the ciphertext, the public key, the message
  ## bytes, the 32-byte encryption seed, the parameter set, the
  ## Reed-Solomon generator, and multiplication scratch.
  ##
  ## `theta` fixes every random choice here, so the same inputs always
  ## give the same ciphertext. Decapsulation relies on that to check a
  ## ciphertext by rebuilding it.
  var
    X = default(HqcXof)
    h: HqcVec = @[]
    s: HqcVec = @[]
    r1: HqcVec = @[]
    r2: HqcVec = @[]
    e: HqcVec = @[]
    tmp: HqcVec = @[]
  h = newHqcVec(p.vecNWords)
  s = newHqcVec(p.vecNWords)
  r1 = newHqcVec(p.vecNWords)
  r2 = newHqcVec(p.vecNWords)
  e = newHqcVec(p.vecNWords)
  tmp = newHqcVec(p.vecNWords)
  xofInit(X, theta)
  ekFromString(h, s, ek, p)
  sampleFixedWeightEnc(r2, X, p.omegaR, p)
  sampleFixedWeightEnc(e, X, p.omegaE, p)
  sampleFixedWeightEnc(r1, X, p.omegaR, p)
  xofClear(X)
  ## u = r1 + r2*h
  vecMul(c.u, r2, h, p, W)
  hqcVecAdd(c.u, r1, c.u, p.vecNWords)
  ## v = codeword(m) + Truncate(r2*s + e)
  codeEncode(c.v, m, p, G)
  vecMul(tmp, r2, s, p, W)
  hqcVecAdd(tmp, e, tmp, p.vecNWords)
  hqcVecTruncate(tmp, p)
  hqcVecAdd(c.v, c.v, tmp, p.vecN1n2Words)
  hqcWipeWords(r1)
  hqcWipeWords(r2)
  hqcWipeWords(e)
  hqcWipeWords(tmp)

## Reference: [HQC-20250822] HQC.PKE decryption; message recovery for `pkeDecrypt`; pitfall: decoding never reports failure, so the caller must decide validity by re-encrypting.
proc pkeDecrypt*(m: var openArray[byte], dk: openArray[byte],
    c: HqcPkeCipher, p: HqcParams, W: var seq[uint64])
    {.role: {decryptor}, raises: [ValueError].} =
  ## m/dk/c/p/W: the recovered message bytes, the 32-byte secret seed, the
  ## ciphertext, the parameter set, and multiplication scratch.
  ##
  ## v - Truncate(u*y) is the codeword plus sparse noise. The concatenated
  ## code strips the noise. If there was too much noise the result is
  ## simply the wrong message - it is the KEM layer above that notices.
  var
    y: HqcVec = @[]
    tmp1: HqcVec = @[]
    tmp2: HqcVec = @[]
  y = newHqcVec(p.vecNWords)
  tmp1 = newHqcVec(p.vecNWords)
  tmp2 = newHqcVec(p.vecNWords)
  dkFromString(y, dk, p)
  vecMul(tmp1, y, c.u, p, W)
  hqcVecTruncate(tmp1, p)
  hqcVecAdd(tmp2, c.v, tmp1, p.vecN1n2Words)
  codeDecode(m, tmp2, p)
  hqcWipeWords(y)
  hqcWipeWords(tmp1)
  hqcWipeWords(tmp2)

