## ----------------------------------------------------------------
## Kyber INDCPA <- CPA-secure public-key encryption core for Kyber
## ----------------------------------------------------------------

import ./params
import ./types
import ./util
import ./poly
import ./polyvec
import ./symmetric
import ../sha3/sha3
import ../../helpers/otter_support
import ../random

{.push boundChecks: off.}

const
  kyberGenMatrixBlockCount = (((12 * kyberN div 8) * (1 shl 12) div kyberQ) + kyberXofBlockBytes) div
    kyberXofBlockBytes
  kyberGenMatrixBufBytes = kyberGenMatrixBlockCount * kyberXofBlockBytes + 2

proc packPkInto*(dst: var openArray[byte], p: KyberParams, pk: PolyVec, seed: openArray[byte]) =
  ## Serialize a public key as `polyvec || publicSeed` into a caller-provided buffer.
  var
    i: int = 0
  if dst.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid Kyber public key length")
  if seed.len != kyberSymBytes:
    raise newException(ValueError, "Kyber public seed must be 32 bytes")
  polyvecToBytesInto(dst.toOpenArray(0, p.k * kyberPolyBytes - 1), p, pk)
  i = 0
  while i < kyberSymBytes:
    dst[p.k * kyberPolyBytes + i] = seed[i]
    i = i + 1

proc packPk*(p: KyberParams, pk: PolyVec, seed: openArray[byte]): seq[byte] =
  ## Serialize a public key as `polyvec || publicSeed`.
  result = newSeq[byte](p.indcpaPublicKeyBytes)
  packPkInto(result, p, pk, seed)

proc unpackPkInto*(p: KyberParams, pk: var PolyVec, seed: var array[kyberSymBytes, byte],
    packed: openArray[byte]) =
  ## Deserialize a public key into its polynomial vector and matrix seed.
  var
    i: int = 0
  if packed.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid Kyber public key length")
  polyvecFromBytesInto(pk, p, packed.toOpenArray(0, p.k * kyberPolyBytes - 1))
  i = 0
  while i < kyberSymBytes:
    seed[i] = packed[p.k * kyberPolyBytes + i]
    i = i + 1

proc unpackPk*(p: KyberParams, packed: openArray[byte]): tuple[pk: PolyVec, seed: array[kyberSymBytes, byte]] =
  ## Deserialize a public key into its polynomial vector and matrix seed.
  unpackPkInto(p, result.pk, result.seed, packed)

proc packSkInto*(dst: var openArray[byte], p: KyberParams, sk: PolyVec) =
  ## Serialize the CPA secret key polynomial vector into a caller-provided buffer.
  if dst.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid Kyber secret key length")
  polyvecToBytesInto(dst, p, sk)

proc packSk*(p: KyberParams, sk: PolyVec): seq[byte] =
  ## Serialize the CPA secret key polynomial vector.
  result = newSeq[byte](p.indcpaSecretKeyBytes)
  packSkInto(result, p, sk)

proc unpackSkInto*(p: KyberParams, sk: var PolyVec, packed: openArray[byte]) =
  ## Deserialize the CPA secret key polynomial vector into a caller-provided vector.
  if packed.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid Kyber secret key length")
  polyvecFromBytesInto(sk, p, packed)

proc unpackSk*(p: KyberParams, packed: openArray[byte]): PolyVec =
  ## Deserialize the CPA secret key polynomial vector.
  unpackSkInto(p, result, packed)

proc packCiphertextInto*(dst: var openArray[byte], p: KyberParams, b: PolyVec, v: Poly) =
  ## Serialize the CPA ciphertext as `compress(b) || compress(v)` into a caller-provided buffer.
  if dst.len != p.indcpaBytes:
    raise newException(ValueError, "invalid Kyber ciphertext length")
  polyvecCompressInto(dst.toOpenArray(0, p.polyVecCompressedBytes - 1), p, b)
  polyCompressInto(dst.toOpenArray(p.polyVecCompressedBytes, p.indcpaBytes - 1), p, v)

proc packCiphertext*(p: KyberParams, b: PolyVec, v: Poly): seq[byte] =
  ## Serialize the CPA ciphertext as `compress(b) || compress(v)`.
  result = newSeq[byte](p.indcpaBytes)
  packCiphertextInto(result, p, b, v)

proc unpackCiphertextInto*(p: KyberParams, b: var PolyVec, v: var Poly, packed: openArray[byte]) =
  ## Deserialize the CPA ciphertext into caller-provided buffers.
  if packed.len != p.indcpaBytes:
    raise newException(ValueError, "invalid Kyber ciphertext length")
  polyvecDecompressInto(b, p, packed.toOpenArray(0, p.polyVecCompressedBytes - 1))
  polyDecompressInto(v, p, packed.toOpenArray(p.polyVecCompressedBytes, packed.len - 1))

proc unpackCiphertext*(p: KyberParams, packed: openArray[byte]): tuple[b: PolyVec, v: Poly] =
  ## Deserialize the CPA ciphertext.
  unpackCiphertextInto(p, result.b, result.v, packed)

proc rejUniformFill(coeffs: var array[kyberN, int16], start, len: int, buf: openArray[byte]): int =
  var
    ctr: int = 0
    pos: int = 0
    val0: uint16 = 0
    val1: uint16 = 0
  ctr = 0
  pos = 0
  while ctr < len and pos + 3 <= buf.len:
    val0 = ((uint16(buf[pos + 0]) shr 0) or (uint16(buf[pos + 1]) shl 8)) and 0x0fff'u16
    val1 = ((uint16(buf[pos + 1]) shr 4) or (uint16(buf[pos + 2]) shl 4)) and 0x0fff'u16
    pos = pos + 3
    if val0 < uint16(kyberQ):
      coeffs[start + ctr] = int16(val0)
      ctr = ctr + 1
    if ctr < len and val1 < uint16(kyberQ):
      coeffs[start + ctr] = int16(val1)
      ctr = ctr + 1
  result = ctr

proc sampleUniformPoly(p: KyberParams, r: var Poly, seed: openArray[byte], x, y: byte) =
  var
    S: Sha3State
    material {.noinit.}: array[kyberSymBytes + 2, byte]
    buf {.noinit.}: array[kyberGenMatrixBufBytes, byte]
    filled: int = 0
    buflen: int = 0
    off: int = 0
    i: int = 0
  if seed.len != kyberSymBytes:
    raise newException(ValueError, "Kyber matrix seed must be 32 bytes")
  i = 0
  while i < kyberSymBytes:
    material[i] = seed[i]
    i = i + 1
  material[kyberSymBytes + 0] = x
  material[kyberSymBytes + 1] = y
  shake128AbsorbOnce(S, material)
  buflen = kyberGenMatrixBlockCount * p.xofBlockBytes
  shake128SqueezeBlocksInto(S, buf.toOpenArray(0, buflen - 1))
  filled = rejUniformFill(r.coeffs, 0, kyberN, buf.toOpenArray(0, buflen - 1))
  while filled < kyberN:
    off = buflen mod 3
    i = 0
    while i < off:
      buf[i] = buf[buflen - off + i]
      i = i + 1
    shake128SqueezeBlocksInto(S, buf.toOpenArray(off, off + p.xofBlockBytes - 1))
    buflen = off + p.xofBlockBytes
    filled = filled + rejUniformFill(r.coeffs, filled, kyberN - filled,
      buf.toOpenArray(0, buflen - 1))

proc genMatrix*(p: KyberParams, M: var PolyMatrix, seed: openArray[byte], transposed: bool) =
  ## Deterministically generate the Kyber public matrix A or A^T.
  otterSpan("kyber.genMatrix"):
    var
      i: int = 0
      j: int = 0
      x: byte = 0
      y: byte = 0
    if seed.len != kyberSymBytes:
      raise newException(ValueError, "Kyber matrix seed must be 32 bytes")
    i = 0
    while i < p.k:
      j = 0
      while j < p.k:
        if transposed:
          x = byte(i)
          y = byte(j)
        else:
          x = byte(j)
          y = byte(i)
        sampleUniformPoly(p, M[i].vec[j], seed, x, y)
        j = j + 1
      i = i + 1

proc genMatrix*(p: KyberParams, seed: openArray[byte], transposed: bool): PolyMatrix =
  ## Deterministically generate the Kyber public matrix A or A^T.
  genMatrix(p, result, seed, transposed)

proc indcpaKeypairInto*(p: KyberParams, pk, sk: var openArray[byte], seed: openArray[byte]) =
  ## Generate the underlying CPA-secure Kyber keypair into caller-provided buffers.
  var
    buf {.noinit.}: array[2 * kyberSymBytes, byte]
    nonce: byte = 0
    a {.noinit.}: PolyMatrix
    e {.noinit.}: PolyVec
    pkpv {.noinit.}: PolyVec
    skpv {.noinit.}: PolyVec
    skpvCache {.noinit.}: PolyVecMulCache
    i: int = 0
  if seed.len != kyberSymBytes:
    raise newException(ValueError, "Kyber seeded keypair requires a 32-byte seed")
  if pk.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid Kyber public key length")
  if sk.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid Kyber secret key length")
  hashGInto(buf, seed)
  genMatrix(p, a, buf.toOpenArray(0, kyberSymBytes - 1), false)
  nonce = 0'u8
  i = 0
  while i < p.k:
    polyGetNoiseEta1Into(p, skpv.vec[i], buf.toOpenArray(kyberSymBytes, 2 * kyberSymBytes - 1), nonce)
    nonce = nonce + 1'u8
    i = i + 1
  i = 0
  while i < p.k:
    polyGetNoiseEta1Into(p, e.vec[i], buf.toOpenArray(kyberSymBytes, 2 * kyberSymBytes - 1), nonce)
    nonce = nonce + 1'u8
    i = i + 1
  polyvecNtt(p, skpv)
  polyvecNtt(p, e)
  polyvecMulCacheCompute(p, skpvCache, skpv)
  case p.k
  of 2:
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[0], a[0], skpv, skpvCache)
    polyToMont(pkpv.vec[0])
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[1], a[1], skpv, skpvCache)
    polyToMont(pkpv.vec[1])
  of 3:
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[0], a[0], skpv, skpvCache)
    polyToMont(pkpv.vec[0])
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[1], a[1], skpv, skpvCache)
    polyToMont(pkpv.vec[1])
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[2], a[2], skpv, skpvCache)
    polyToMont(pkpv.vec[2])
  of 4:
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[0], a[0], skpv, skpvCache)
    polyToMont(pkpv.vec[0])
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[1], a[1], skpv, skpvCache)
    polyToMont(pkpv.vec[1])
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[2], a[2], skpv, skpvCache)
    polyToMont(pkpv.vec[2])
    polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[3], a[3], skpv, skpvCache)
    polyToMont(pkpv.vec[3])
  else:
    i = 0
    while i < p.k:
      polyvecBaseMulAccMontgomeryCached(p, pkpv.vec[i], a[i], skpv, skpvCache)
      polyToMont(pkpv.vec[i])
      i = i + 1
  polyvecAdd(p, pkpv, pkpv, e)
  polyvecReduce(p, pkpv)
  packSkInto(sk, p, skpv)
  packPkInto(pk, p, pkpv, buf.toOpenArray(0, kyberSymBytes - 1))
  clearPod(skpv)
  secureClearBytes(buf)

proc indcpaKeypair*(p: KyberParams, seed: seq[byte] = @[]): tuple[pk, sk: seq[byte]] =
  ## Generate the underlying CPA-secure Kyber keypair.
  otterSpan("kyber.indcpaKeypair"):
    var
      seedIn: seq[byte] = @[]
    if seed.len > 0 and seed.len != kyberSymBytes:
      raise newException(ValueError, "Kyber seeded keypair requires a 32-byte seed")
    result.pk = newSeq[byte](p.indcpaPublicKeyBytes)
    result.sk = newSeq[byte](p.indcpaSecretKeyBytes)
    if seed.len == 0:
      seedIn = cryptoRandomBytes(kyberSymBytes)
      indcpaKeypairInto(p, result.pk, result.sk, seedIn)
      secureClearBytes(seedIn)
    else:
      indcpaKeypairInto(p, result.pk, result.sk, seed)

proc indcpaEncInto*(p: KyberParams, ct: var openArray[byte], m, pk, coins: openArray[byte]) =
  ## Encrypt one Kyber message with the underlying CPA-secure primitive into a caller buffer.
  var
    pkpv {.noinit.}: PolyVec
    seed {.noinit.}: array[kyberSymBytes, byte]
    k {.noinit.}: Poly
    at {.noinit.}: PolyMatrix
    sp {.noinit.}: PolyVec
    ep {.noinit.}: PolyVec
    b {.noinit.}: PolyVec
    v {.noinit.}: Poly
    epp {.noinit.}: Poly
    spCache {.noinit.}: PolyVecMulCache
    nonce: byte = 0
    i: int = 0
  if m.len != kyberSymBytes:
    raise newException(ValueError, "Kyber message must be 32 bytes")
  if pk.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid Kyber public key length")
  if coins.len != kyberSymBytes:
    raise newException(ValueError, "Kyber coins must be 32 bytes")
  if ct.len != p.indcpaBytes:
    raise newException(ValueError, "invalid Kyber ciphertext length")
  unpackPkInto(p, pkpv, seed, pk)
  polyFromMsg(k, m)
  genMatrix(p, at, seed, true)
  nonce = 0'u8
  i = 0
  while i < p.k:
    polyGetNoiseEta1Into(p, sp.vec[i], coins, nonce)
    nonce = nonce + 1'u8
    i = i + 1
  i = 0
  while i < p.k:
    polyGetNoiseEta2Into(p, ep.vec[i], coins, nonce)
    nonce = nonce + 1'u8
    i = i + 1
  polyGetNoiseEta2Into(p, epp, coins, nonce)
  polyvecNtt(p, sp)
  polyvecMulCacheCompute(p, spCache, sp)
  case p.k
  of 2:
    polyvecBaseMulAccMontgomeryCached(p, b.vec[0], at[0], sp, spCache)
    polyvecBaseMulAccMontgomeryCached(p, b.vec[1], at[1], sp, spCache)
  of 3:
    polyvecBaseMulAccMontgomeryCached(p, b.vec[0], at[0], sp, spCache)
    polyvecBaseMulAccMontgomeryCached(p, b.vec[1], at[1], sp, spCache)
    polyvecBaseMulAccMontgomeryCached(p, b.vec[2], at[2], sp, spCache)
  of 4:
    polyvecBaseMulAccMontgomeryCached(p, b.vec[0], at[0], sp, spCache)
    polyvecBaseMulAccMontgomeryCached(p, b.vec[1], at[1], sp, spCache)
    polyvecBaseMulAccMontgomeryCached(p, b.vec[2], at[2], sp, spCache)
    polyvecBaseMulAccMontgomeryCached(p, b.vec[3], at[3], sp, spCache)
  else:
    i = 0
    while i < p.k:
      polyvecBaseMulAccMontgomeryCached(p, b.vec[i], at[i], sp, spCache)
      i = i + 1
  polyvecBaseMulAccMontgomeryCached(p, v, pkpv, sp, spCache)
  polyvecInvNttToMont(p, b)
  polyInvNttToMont(v)
  polyvecAdd(p, b, b, ep)
  polyAdd(v, v, epp)
  polyAdd(v, v, k)
  polyvecReduce(p, b)
  polyReduce(v)
  packCiphertextInto(ct, p, b, v)
  clearPod(k)

proc indcpaEnc*(p: KyberParams, m, pk, coins: openArray[byte]): seq[byte] =
  ## Encrypt one Kyber message with the underlying CPA-secure primitive.
  otterSpan("kyber.indcpaEnc"):
    result = newSeq[byte](p.indcpaBytes)
    indcpaEncInto(p, result, m, pk, coins)

proc indcpaDecInto*(p: KyberParams, m: var openArray[byte], ct, sk: openArray[byte]) =
  ## Decrypt one Kyber CPA ciphertext into a caller-provided 32-byte message buffer.
  var
    b {.noinit.}: PolyVec
    v {.noinit.}: Poly
    skpv {.noinit.}: PolyVec
    mp {.noinit.}: Poly
    bCache {.noinit.}: PolyVecMulCache
  if ct.len != p.indcpaBytes:
    raise newException(ValueError, "invalid Kyber ciphertext length")
  if sk.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid Kyber secret key length")
  if m.len != kyberSymBytes:
    raise newException(ValueError, "Kyber message output must be 32 bytes")
  unpackCiphertextInto(p, b, v, ct)
  unpackSkInto(p, skpv, sk)
  polyvecNtt(p, b)
  polyvecMulCacheCompute(p, bCache, b)
  polyvecBaseMulAccMontgomeryCached(p, mp, skpv, b, bCache)
  clearPod(skpv)
  polyInvNttToMont(mp)
  polySub(mp, v, mp)
  polyReduce(mp)
  polyToMsgInto(m, mp)
  clearPod(mp)

proc indcpaDec*(p: KyberParams, ct, sk: openArray[byte]): seq[byte] =
  ## Decrypt one Kyber CPA ciphertext into its 32-byte message.
  otterSpan("kyber.indcpaDec"):
    result = newSeq[byte](kyberSymBytes)
    indcpaDecInto(p, result, ct, sk)

{.pop.}
