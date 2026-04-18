## --------------------------------------------------------------------
## Dilithium Operations <- pure-Nim ML-DSA keypair/sign/verify backend
## --------------------------------------------------------------------

import ./params
import ./poly
import ../../../sha3
import ../../../random
import ../../../../helpers/otter_support

type
  ## Public/secret keypair emitted by the pure-Nim ML-DSA backend.
  DilithiumTyrKeypair* = object
    variant*: DilithiumVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

{.push boundChecks: off, overflowChecks: off.}
proc variantFromParams(p: DilithiumParams): DilithiumVariant {.inline.} =
  if p.k == 4:
    result = dilithium44
    return
  if p.k == 6:
    result = dilithium65
    return
  result = dilithium87

proc writePre(ctx: openArray[byte], pre: var array[257, byte]): int {.inline.} =
  var
    i: int = 0
  if ctx.len > 255:
    raise newException(ValueError, "Dilithium context too long")
  pre[0] = 0'u8
  pre[1] = byte(ctx.len)
  i = 0
  while i < ctx.len:
    pre[2 + i] = ctx[i]
    i = i + 1
  result = ctx.len + 2

proc messageDigestInto(tr, pre, msg: openArray[byte],
    dst: var array[dilithiumCrhBytes, byte]) {.inline.} =
  shake256Into(dst, tr, pre, msg)

proc sampleSecretVectorsEta(p: DilithiumParams, s1: var DilithiumPolyVecL,
    s2: var DilithiumPolyVecK, seed: array[dilithiumCrhBytes, byte]) {.inline, otterBench.} =
  ## Secret eta sampling now uses the fixed-work sampler, so keygen can batch
  ## the SHAKE/eta path again without the old secret-dependent lane divergence.
  polyveclUniformEta(p, s1, seed, 0'u16)
  polyveckUniformEta(p, s2, seed, uint16(p.l))

proc expandPointwiseRow(p: DilithiumParams, t: var DilithiumPoly, row: var DilithiumPolyVecL,
    rho: array[dilithiumSeedBytes, byte], rowIndex: int, v: DilithiumPolyVecL) {.inline, raises: [].} =
  polyvecMatrixExpandRowInto(p, row, rho, rowIndex)
  polyveclPointwiseAccMontgomery(t, row, v)

proc matrixVectorPointwiseByRowsKeypair(p: DilithiumParams, t: var DilithiumPolyVecK,
    rho: array[dilithiumSeedBytes, byte], v: DilithiumPolyVecL) {.inline, otterBench.} =
  var
    row: DilithiumPolyVecL
    i: int = 0
  if p.k == 4:
    expandPointwiseRow(p, t.vec[0], row, rho, 0, v)
    expandPointwiseRow(p, t.vec[1], row, rho, 1, v)
    expandPointwiseRow(p, t.vec[2], row, rho, 2, v)
    expandPointwiseRow(p, t.vec[3], row, rho, 3, v)
    return
  if p.k == 6:
    expandPointwiseRow(p, t.vec[0], row, rho, 0, v)
    expandPointwiseRow(p, t.vec[1], row, rho, 1, v)
    expandPointwiseRow(p, t.vec[2], row, rho, 2, v)
    expandPointwiseRow(p, t.vec[3], row, rho, 3, v)
    expandPointwiseRow(p, t.vec[4], row, rho, 4, v)
    expandPointwiseRow(p, t.vec[5], row, rho, 5, v)
    return
  if p.k == 8:
    expandPointwiseRow(p, t.vec[0], row, rho, 0, v)
    expandPointwiseRow(p, t.vec[1], row, rho, 1, v)
    expandPointwiseRow(p, t.vec[2], row, rho, 2, v)
    expandPointwiseRow(p, t.vec[3], row, rho, 3, v)
    expandPointwiseRow(p, t.vec[4], row, rho, 4, v)
    expandPointwiseRow(p, t.vec[5], row, rho, 5, v)
    expandPointwiseRow(p, t.vec[6], row, rho, 6, v)
    expandPointwiseRow(p, t.vec[7], row, rho, 7, v)
    return
  i = 0
  while i < p.k:
    expandPointwiseRow(p, t.vec[i], row, rho, i, v)
    i = i + 1

proc matrixVectorPointwiseByRows(p: DilithiumParams, t: var DilithiumPolyVecK,
    rho: array[dilithiumSeedBytes, byte], v: DilithiumPolyVecL) {.inline, otterBench.} =
  var
    row: DilithiumPolyVecL
    i: int = 0
  if p.k == 4:
    polyvecMatrixExpandRowInto(p, row, rho, 0)
    polyveclPointwiseAccMontgomery(t.vec[0], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 1)
    polyveclPointwiseAccMontgomery(t.vec[1], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 2)
    polyveclPointwiseAccMontgomery(t.vec[2], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 3)
    polyveclPointwiseAccMontgomery(t.vec[3], row, v)
    return
  if p.k == 6:
    polyvecMatrixExpandRowInto(p, row, rho, 0)
    polyveclPointwiseAccMontgomery(t.vec[0], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 1)
    polyveclPointwiseAccMontgomery(t.vec[1], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 2)
    polyveclPointwiseAccMontgomery(t.vec[2], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 3)
    polyveclPointwiseAccMontgomery(t.vec[3], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 4)
    polyveclPointwiseAccMontgomery(t.vec[4], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 5)
    polyveclPointwiseAccMontgomery(t.vec[5], row, v)
    return
  if p.k == 8:
    polyvecMatrixExpandRowInto(p, row, rho, 0)
    polyveclPointwiseAccMontgomery(t.vec[0], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 1)
    polyveclPointwiseAccMontgomery(t.vec[1], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 2)
    polyveclPointwiseAccMontgomery(t.vec[2], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 3)
    polyveclPointwiseAccMontgomery(t.vec[3], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 4)
    polyveclPointwiseAccMontgomery(t.vec[4], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 5)
    polyveclPointwiseAccMontgomery(t.vec[5], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 6)
    polyveclPointwiseAccMontgomery(t.vec[6], row, v)
    polyvecMatrixExpandRowInto(p, row, rho, 7)
    polyveclPointwiseAccMontgomery(t.vec[7], row, v)
    return
  i = 0
  while i < p.k:
    polyvecMatrixExpandRowInto(p, row, rho, i)
    polyveclPointwiseAccMontgomery(t.vec[i], row, v)
    i = i + 1

template sampleIntermediateVectorGamma1(p, z, seed, nonceBase: untyped) =
  polyveclUniformGamma1BaseNonce(p, z, seed, nonceBase)
  nonceBase = nonceBase + uint16(p.l)

template signMatrixVectorDecompose(p, w1, w0, tmpL, mat, z: untyped) =
  tmpL = z
  polyveclNtt(tmpL)
  polyvecMatrixPointwiseMontgomery(p, w1, mat, tmpL)
  polyveckReduce(w1)
  polyveckInvnttTomont(w1)
  polyveckCaddq(w1)
  polyveckDecompose(p, w1, w0, w1)

template signChallengeFromW1(p, cp, cseed, mu, packedW1, w1: untyped) =
  polyveckPackW1(p, packedW1.toOpenArray(0, p.k * p.polyW1PackedBytes - 1), w1)
  shake256Into(cseed.toOpenArray(0, p.ctildeBytes - 1), mu,
    packedW1.toOpenArray(0, p.k * p.polyW1PackedBytes - 1))
  polyChallengeSeed(p, cp, cseed.toOpenArray(0, p.ctildeBytes - 1))
  polyNtt(cp)

template signRejectZ(p, z, tmpL, cp, s1: untyped): untyped =
  block:
    polyveclPointwisePolyMontgomery(tmpL, cp, s1)
    polyveclInvnttTomont(tmpL)
    polyveclAdd(z, z, tmpL)
    polyveclReduce(z)
    polyveclChkNorm(z, p.gamma1 - p.beta)

template signRejectW0(p, h, w0, cp, s2: untyped): untyped =
  block:
    polyveckPointwisePolyMontgomery(h, cp, s2)
    polyveckInvnttTomont(h)
    polyveckSub(w0, w0, h)
    polyveckReduce(w0)
    polyveckChkNorm(w0, p.gamma2 - p.beta)

template signRejectHints(p, h, w0, w1, cp, t0: untyped): untyped =
  block:
    polyveckPointwisePolyMontgomery(h, cp, t0)
    polyveckInvnttTomont(h)
    polyveckReduce(h)
    if polyveckChkNorm(h, p.gamma2):
      true
    else:
      polyveckAdd(w0, w0, h)
      polyveckMakeHint(p, h, w0, w1) > uint32(p.omega)

proc keypairFromRandomSeedInto(p: DilithiumParams, seed: openArray[byte], publicKey,
    secretKey: var openArray[byte]) {.otterBench.} =
  var
    seedInput: array[dilithiumSeedBytes + 2, byte]
    seedbuf: array[2 * dilithiumSeedBytes + dilithiumCrhBytes, byte]
    rho: array[dilithiumSeedBytes, byte]
    rhoprime: array[dilithiumCrhBytes, byte]
    key: array[dilithiumSeedBytes, byte]
    tr: array[dilithiumTrBytes, byte]
    s1: DilithiumPolyVecL
    s1hat: DilithiumPolyVecL
    s2: DilithiumPolyVecK
    t1: DilithiumPolyVecK
    t0: DilithiumPolyVecK
    i: int = 0
  defer:
    clearSensitivePlainData(seedInput)
    clearSensitivePlainData(seedbuf)
    clearPlainData(rho)
    clearSensitivePlainData(rhoprime)
    clearSensitivePlainData(key)
    clearPlainData(tr)
    clearSensitivePlainData(s1)
    clearSensitivePlainData(s1hat)
    clearSensitivePlainData(s2)
    clearPlainData(t1)
    clearSensitivePlainData(t0)
  i = 0
  while i < dilithiumSeedBytes:
    seedInput[i] = seed[i]
    i = i + 1
  seedInput[dilithiumSeedBytes + 0] = byte(p.k)
  seedInput[dilithiumSeedBytes + 1] = byte(p.l)
  shake256Into(seedbuf, seedInput)
  i = 0
  while i < dilithiumSeedBytes:
    rho[i] = seedbuf[i]
    key[i] = seedbuf[dilithiumSeedBytes + dilithiumCrhBytes + i]
    i = i + 1
  i = 0
  while i < dilithiumCrhBytes:
    rhoprime[i] = seedbuf[dilithiumSeedBytes + i]
    i = i + 1
  s1 = initPolyVecL(p)
  s1hat = initPolyVecL(p)
  s2 = initPolyVecK(p)
  t1 = initPolyVecK(p)
  t0 = initPolyVecK(p)
  sampleSecretVectorsEta(p, s1, s2, rhoprime)
  s1hat = s1
  polyveclNtt(s1hat)
  matrixVectorPointwiseByRowsKeypair(p, t1, rho, s1hat)
  polyveckReduce(t1)
  polyveckInvnttTomont(t1)
  polyveckAdd(t1, t1, s2)
  polyveckCaddq(t1)
  polyveckPower2Round(t1, t0, t1)
  packPkInto(p, publicKey, rho, t1)
  shake256Into(tr, publicKey)
  packSkInto(p, secretKey, rho, tr, key, t0, s1, s2)

proc keypairFromRandomSeed(p: DilithiumParams, seed: openArray[byte]): DilithiumTyrKeypair =
  result.variant = variantFromParams(p)
  result.publicKey = newSeq[byte](p.publicKeyBytes)
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  keypairFromRandomSeedInto(p, seed, result.publicKey, result.secretKey)

proc dilithiumTyrKeypairInto*(v: DilithiumVariant, publicKey,
    secretKey: var openArray[byte]) =
  ## Generate a pure-Nim ML-DSA keypair into caller-owned buffers.
  var
    randomness: seq[byte]
    p: DilithiumParams = params(v)
  defer:
    clearSensitiveBytes(randomness)
  if publicKey.len != p.publicKeyBytes:
    raise newException(ValueError, "Dilithium public key buffer has wrong size for variant")
  if secretKey.len != p.secretKeyBytes:
    raise newException(ValueError, "Dilithium secret key buffer has wrong size for variant")
  randomness = cryptoRandomBytes(dilithiumSeedBytes)
  keypairFromRandomSeedInto(p, randomness, publicKey, secretKey)

proc dilithiumTyrKeypairInto*(v: DilithiumVariant, publicKey, secretKey: var openArray[byte],
    seed: openArray[byte]) =
  ## Generate a deterministic pure-Nim ML-DSA keypair into caller-owned buffers.
  let p = params(v)
  if seed.len != dilithiumSeedBytes:
    raise newException(ValueError, "Dilithium seeded keypair requires 32 bytes")
  if publicKey.len != p.publicKeyBytes:
    raise newException(ValueError, "Dilithium public key buffer has wrong size for variant")
  if secretKey.len != p.secretKeyBytes:
    raise newException(ValueError, "Dilithium secret key buffer has wrong size for variant")
  keypairFromRandomSeedInto(p, seed, publicKey, secretKey)

proc dilithiumTyrKeypair*(v: DilithiumVariant, seed: seq[byte] = @[]): DilithiumTyrKeypair =
  ## Generate a pure-Nim ML-DSA keypair.
  var
    p: DilithiumParams = params(v)
  result.variant = v
  result.publicKey = newSeq[byte](p.publicKeyBytes)
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  if seed.len == 0:
    dilithiumTyrKeypairInto(v, result.publicKey, result.secretKey)
  else:
    dilithiumTyrKeypairInto(v, result.publicKey, result.secretKey, seed)

proc dilithiumTyrSignDerandInto*(v: DilithiumVariant, sig: var openArray[byte], msg: openArray[byte],
    sk: openArray[byte], rnd: openArray[byte], ctx: openArray[byte] = @[]) {.otterBench.} =
  ## Sign a message with explicit ML-DSA randomness into a caller-owned buffer.
  let p = params(v)
  if sig.len != p.signatureBytes:
    raise newException(ValueError, "Dilithium signature buffer has wrong size for variant")
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "Dilithium secret key has wrong size for variant")
  if rnd.len != dilithiumRndBytes:
    raise newException(ValueError, "Dilithium signing randomness must be 32 bytes")
  var
    skp: DilithiumSecretKeyState = unpackSk(p, sk)
    pre: array[257, byte]
    preLen: int = 0
    mu: array[dilithiumCrhBytes, byte]
    rhoprime: array[dilithiumCrhBytes, byte]
    mat: DilithiumMatrix
    z: DilithiumPolyVecL
    tmpL: DilithiumPolyVecL
    s1: DilithiumPolyVecL
    w1: DilithiumPolyVecK
    w0: DilithiumPolyVecK
    h: DilithiumPolyVecK
    s2: DilithiumPolyVecK
    t0: DilithiumPolyVecK
    cp: DilithiumPoly
    nonceBase: uint16 = 0
    packedW1: array[dilithiumMaxK * 192, byte]
    cseed: array[dilithiumMaxCtildeBytes, byte]
  defer:
    clearSensitivePlainData(skp)
    clearPlainData(pre)
    clearPlainData(mu)
    clearSensitivePlainData(rhoprime)
    clearPlainData(mat)
    clearPlainData(z)
    clearSensitivePlainData(tmpL)
    clearSensitivePlainData(s1)
    clearPlainData(w1)
    clearSensitivePlainData(w0)
    clearPlainData(h)
    clearSensitivePlainData(s2)
    clearSensitivePlainData(t0)
    clearPlainData(cp)
    clearPlainData(packedW1)
    clearPlainData(cseed)
  preLen = writePre(ctx, pre)
  messageDigestInto(skp.tr, pre.toOpenArray(0, preLen - 1), msg, mu)
  shake256Into(rhoprime, skp.key, rnd, mu)
  mat = polyvecMatrixExpand(p, skp.rho)
  z = initPolyVecL(p)
  tmpL = initPolyVecL(p)
  s1 = skp.s1
  s2 = skp.s2
  t0 = skp.t0
  w1 = initPolyVecK(p)
  w0 = initPolyVecK(p)
  h = initPolyVecK(p)
  polyveclNtt(s1)
  polyveckNtt(s2)
  polyveckNtt(t0)
  while true:
    sampleIntermediateVectorGamma1(p, z, rhoprime, nonceBase)
    signMatrixVectorDecompose(p, w1, w0, tmpL, mat, z)
    signChallengeFromW1(p, cp, cseed, mu, packedW1, w1)
    if signRejectZ(p, z, tmpL, cp, s1):
      continue
    if signRejectW0(p, h, w0, cp, s2):
      continue
    if signRejectHints(p, h, w0, w1, cp, t0):
      continue
    packSigInto(p, sig, cseed.toOpenArray(0, p.ctildeBytes - 1), z, h)
    break

proc dilithiumTyrSignDerand*(v: DilithiumVariant, msg: openArray[byte], sk: openArray[byte],
    rnd: openArray[byte], ctx: openArray[byte] = @[]): seq[byte] =
  ## Sign a message with explicit ML-DSA randomness.
  let p = params(v)
  result = newSeq[byte](p.signatureBytes)
  dilithiumTyrSignDerandInto(v, result, msg, sk, rnd, ctx)

proc dilithiumTyrSignDeterministicInto*(v: DilithiumVariant, sig: var openArray[byte],
    msg: openArray[byte], sk: openArray[byte], ctx: openArray[byte] = @[]) =
  ## Sign deterministically with zeroed ML-DSA randomness into a caller-owned buffer.
  var
    rnd: array[dilithiumRndBytes, byte]
  dilithiumTyrSignDerandInto(v, sig, msg, sk, rnd, ctx)

proc dilithiumTyrSignDeterministic*(v: DilithiumVariant, msg: openArray[byte], sk: openArray[byte],
    ctx: openArray[byte] = @[]): seq[byte] =
  ## Sign deterministically with zeroed ML-DSA randomness.
  let p = params(v)
  result = newSeq[byte](p.signatureBytes)
  dilithiumTyrSignDeterministicInto(v, result, msg, sk, ctx)

proc dilithiumTyrSignInto*(v: DilithiumVariant, sig: var openArray[byte], msg: openArray[byte],
    sk: openArray[byte], ctx: openArray[byte] = @[]) =
  ## Sign using liboqs-compatible randomized ML-DSA signing into a caller-owned buffer.
  var
    rnd: seq[byte]
  defer:
    clearSensitiveBytes(rnd)
  rnd = cryptoRandomBytes(dilithiumRndBytes)
  dilithiumTyrSignDerandInto(v, sig, msg, sk, rnd, ctx)

proc dilithiumTyrSign*(v: DilithiumVariant, msg: openArray[byte], sk: openArray[byte],
    ctx: openArray[byte] = @[]): seq[byte] =
  ## Sign using liboqs-compatible randomized ML-DSA signing.
  let p = params(v)
  result = newSeq[byte](p.signatureBytes)
  dilithiumTyrSignInto(v, result, msg, sk, ctx)

proc dilithiumTyrVerify*(v: DilithiumVariant, msg, sig, pk: openArray[byte],
    ctx: openArray[byte] = @[]): bool {.otterBench.} =
  ## Verify a signature with the pure-Nim ML-DSA backend.
  var
    p: DilithiumParams = params(v)
    pkp: DilithiumPublicKeyState = unpackPk(p, pk)
    sigp: DilithiumSignatureState = unpackSig(p, sig)
    pre: array[257, byte]
    preLen: int = 0
    tr: array[dilithiumTrBytes, byte]
    mu: array[dilithiumCrhBytes, byte]
    cp: DilithiumPoly
    t1: DilithiumPolyVecK
    w1: DilithiumPolyVecK
    h: DilithiumPolyVecK
    z: DilithiumPolyVecL
    packedW1: array[dilithiumMaxK * 192, byte]
    c2: array[dilithiumMaxCtildeBytes, byte]
  if sig.len != p.signatureBytes:
    return false
  if pk.len != p.publicKeyBytes:
    return false
  if not sigp.ok:
    return false
  z = sigp.z
  h = sigp.h
  if polyveclChkNorm(z, p.gamma1 - p.beta):
    return false
  preLen = writePre(ctx, pre)
  shake256Into(tr, pk)
  messageDigestInto(tr, pre.toOpenArray(0, preLen - 1), msg, mu)
  polyChallengeSeed(p, cp, sigp.c.toOpenArray(0, sigp.cLen - 1))
  polyveclNtt(z)
  w1 = initPolyVecK(p)
  matrixVectorPointwiseByRows(p, w1, pkp.rho, z)
  polyNtt(cp)
  t1 = pkp.t1
  polyveckShiftl(t1)
  polyveckNtt(t1)
  polyveckPointwisePolyMontgomery(t1, cp, t1)
  polyveckSub(w1, w1, t1)
  polyveckReduce(w1)
  polyveckInvnttTomont(w1)
  polyveckCaddq(w1)
  polyveckUseHint(p, w1, w1, h)
  polyveckPackW1(p, packedW1.toOpenArray(0, p.k * p.polyW1PackedBytes - 1), w1)
  shake256Into(c2.toOpenArray(0, p.ctildeBytes - 1), mu,
    packedW1.toOpenArray(0, p.k * p.polyW1PackedBytes - 1))
  var
    i: int = 0
  while i < p.ctildeBytes:
    if c2[i] != sigp.c[i]:
      return false
    i = i + 1
  result = true
{.pop.}
