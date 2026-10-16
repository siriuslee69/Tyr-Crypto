## ----------------------------------------------------------------
## ML-KEM INDCPA <- CPA-secure public-key encryption core for ML-KEM
## ----------------------------------------------------------------

import ./params
import ../../helpers/secure_memory
import ./types
import ./util
import ./poly
import ./polyvec
import ./symmetric
import ../../hashes/sha3
import ../../helpers/otter_support
import ../../helpers/random

{.push boundChecks: off.}

const
  mlkemGenMatrixBlockCount = (((12 * mlkemN div 8) * (1 shl 12) div mlkemQ) + mlkemXofBlockBytes) div
    mlkemXofBlockBytes
  mlkemGenMatrixBufBytes = mlkemGenMatrixBlockCount * mlkemXofBlockBytes + 2

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `packPkInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packPkInto*(dst: var openArray[byte], p: MlKemParams, pk: PolyVec, seed: openArray[byte]) =
  ## Serialize a public key as `polyvec || publicSeed` into a caller-provided buffer.
  var
    i: int = 0
  if dst.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid ML-KEM public key length")
  if seed.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM public seed must be 32 bytes")
  polyvecToBytesInto(dst.toOpenArray(0, p.k * mlkemPolyBytes - 1), p, pk)
  i = 0
  while i < mlkemSymBytes:
    dst[p.k * mlkemPolyBytes + i] = seed[i]
    i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `packPk`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packPk*(p: MlKemParams, pk: PolyVec, seed: openArray[byte]): seq[byte] =
  ## Serialize a public key as `polyvec || publicSeed`.
  result = newSeq[byte](p.indcpaPublicKeyBytes)
  packPkInto(result, p, pk, seed)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `unpackPkInto`; pitfall: reject malformed or non-canonical input before indexed access.
proc unpackPkInto*(p: MlKemParams, pk: var PolyVec, seed: var array[mlkemSymBytes, byte],
    packed: openArray[byte]) =
  ## Deserialize a public key into its polynomial vector and matrix seed.
  var
    i: int = 0
  if packed.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid ML-KEM public key length")
  polyvecFromBytesInto(pk, p, packed.toOpenArray(0, p.k * mlkemPolyBytes - 1))
  i = 0
  while i < mlkemSymBytes:
    seed[i] = packed[p.k * mlkemPolyBytes + i]
    i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `unpackPk`; pitfall: reject malformed or non-canonical input before indexed access.
proc unpackPk*(p: MlKemParams, packed: openArray[byte]): tuple[pk: PolyVec, seed: array[mlkemSymBytes, byte]] =
  ## Deserialize a public key into its polynomial vector and matrix seed.
  unpackPkInto(p, result.pk, result.seed, packed)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `packSkInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packSkInto*(dst: var openArray[byte], p: MlKemParams, sk: PolyVec) =
  ## Serialize the CPA secret key polynomial vector into a caller-provided buffer.
  if dst.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid ML-KEM secret key length")
  polyvecToBytesInto(dst, p, sk)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `packSk`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packSk*(p: MlKemParams, sk: PolyVec): seq[byte] =
  ## Serialize the CPA secret key polynomial vector.
  result = newSeq[byte](p.indcpaSecretKeyBytes)
  packSkInto(result, p, sk)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `unpackSkInto`; pitfall: reject malformed or non-canonical input before indexed access.
proc unpackSkInto*(p: MlKemParams, sk: var PolyVec, packed: openArray[byte]) =
  ## Deserialize the CPA secret key polynomial vector into a caller-provided vector.
  if packed.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid ML-KEM secret key length")
  polyvecFromBytesInto(sk, p, packed)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `unpackSk`; pitfall: reject malformed or non-canonical input before indexed access.
proc unpackSk*(p: MlKemParams, packed: openArray[byte]): PolyVec =
  ## Deserialize the CPA secret key polynomial vector.
  unpackSkInto(p, result, packed)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `packCiphertextInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packCiphertextInto*(dst: var openArray[byte], p: MlKemParams, b: PolyVec, v: Poly) =
  ## Serialize the CPA ciphertext as `compress(b) || compress(v)` into a caller-provided buffer.
  if dst.len != p.indcpaBytes:
    raise newException(ValueError, "invalid ML-KEM ciphertext length")
  polyvecCompressInto(dst.toOpenArray(0, p.polyVecCompressedBytes - 1), p, b)
  polyCompressInto(dst.toOpenArray(p.polyVecCompressedBytes, p.indcpaBytes - 1), p, v)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `packCiphertext`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packCiphertext*(p: MlKemParams, b: PolyVec, v: Poly): seq[byte] =
  ## Serialize the CPA ciphertext as `compress(b) || compress(v)`.
  result = newSeq[byte](p.indcpaBytes)
  packCiphertextInto(result, p, b, v)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `unpackCiphertextInto`; pitfall: reject malformed or non-canonical input before indexed access.
proc unpackCiphertextInto*(p: MlKemParams, b: var PolyVec, v: var Poly, packed: openArray[byte]) =
  ## Deserialize the CPA ciphertext into caller-provided buffers.
  if packed.len != p.indcpaBytes:
    raise newException(ValueError, "invalid ML-KEM ciphertext length")
  polyvecDecompressInto(b, p, packed.toOpenArray(0, p.polyVecCompressedBytes - 1))
  polyDecompressInto(v, p, packed.toOpenArray(p.polyVecCompressedBytes, packed.len - 1))

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `unpackCiphertext`; pitfall: reject malformed or non-canonical input before indexed access.
proc unpackCiphertext*(p: MlKemParams, packed: openArray[byte]): tuple[b: PolyVec, v: Poly] =
  ## Deserialize the CPA ciphertext.
  unpackCiphertextInto(p, result.b, result.v, packed)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `rejUniformFill`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc rejUniformFill(coeffs: var array[mlkemN, int16], start, len: int, buf: openArray[byte]): int =
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
    if val0 < uint16(mlkemQ):
      coeffs[start + ctr] = int16(val0)
      ctr = ctr + 1
    if ctr < len and val1 < uint16(mlkemQ):
      coeffs[start + ctr] = int16(val1)
      ctr = ctr + 1
  result = ctr

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `sampleUniformPoly`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc sampleUniformPoly(p: MlKemParams, r: var Poly, seed: openArray[byte], x, y: byte) =
  var
    S: Sha3State = default(Sha3State)
    material {.noinit.}: array[mlkemSymBytes + 2, byte]
    buf {.noinit.}: array[mlkemGenMatrixBufBytes, byte]
    filled: int = 0
    buflen: int = 0
    off: int = 0
    i: int = 0
  if seed.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM matrix seed must be 32 bytes")
  i = 0
  while i < mlkemSymBytes:
    material[i] = seed[i]
    i = i + 1
  material[mlkemSymBytes + 0] = x
  material[mlkemSymBytes + 1] = y
  shake128AbsorbOnce(S, material)
  buflen = mlkemGenMatrixBlockCount * p.xofBlockBytes
  shake128SqueezeBlocksInto(S, buf.toOpenArray(0, buflen - 1))
  filled = rejUniformFill(r.coeffs, 0, mlkemN, buf.toOpenArray(0, buflen - 1))
  while filled < mlkemN:
    off = buflen mod 3
    i = 0
    while i < off:
      buf[i] = buf[buflen - off + i]
      i = i + 1
    shake128SqueezeBlocksInto(S, buf.toOpenArray(off, off + p.xofBlockBytes - 1))
    buflen = off + p.xofBlockBytes
    filled = filled + rejUniformFill(r.coeffs, filled, mlkemN - filled,
      buf.toOpenArray(0, buflen - 1))

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `genMatrix`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc genMatrix*(p: MlKemParams, M: var PolyMatrix, seed: openArray[byte], transposed: bool) =
  ## Deterministically generate the ML-KEM public matrix A or A^T.
  otterSpan("mlkem.genMatrix"):
    var
      i: int = 0
      j: int = 0
      x: byte = 0
      y: byte = 0
    if seed.len != mlkemSymBytes:
      raise newException(ValueError, "ML-KEM matrix seed must be 32 bytes")
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

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `genMatrix`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc genMatrix*(p: MlKemParams, seed: openArray[byte], transposed: bool): PolyMatrix =
  ## Deterministically generate the ML-KEM public matrix A or A^T.
  genMatrix(p, result, seed, transposed)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `indcpaKeypairInto`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc indcpaKeypairInto*(p: MlKemParams, pk, sk: var openArray[byte], seed: openArray[byte]) =
  ## Generate the underlying CPA-secure ML-KEM keypair into caller-provided buffers.
  var
    material: array[mlkemSymBytes + 1, byte] = default(array[mlkemSymBytes + 1, byte])
    buf {.noinit.}: array[2 * mlkemSymBytes, byte]
    nonce: byte = 0
    a {.noinit.}: PolyMatrix
    e {.noinit.}: PolyVec
    pkpv {.noinit.}: PolyVec
    skpv {.noinit.}: PolyVec
    skpvCache {.noinit.}: PolyVecMulCache
    i: int = 0
  if seed.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM seeded keypair requires a 32-byte seed")
  if pk.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid ML-KEM public key length")
  if sk.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid ML-KEM secret key length")
  # FIPS 203 algorithm 13 step 1: (rho, sigma) = G(d || k). The k byte is
  # the one domain-separation change from round-3 Kyber in key generation.
  copyMem(addr material[0], unsafeAddr seed[0], mlkemSymBytes)
  material[mlkemSymBytes] = byte(p.k)
  hashGInto(buf, material)
  secureClearBytes(material)
  genMatrix(p, a, buf.toOpenArray(0, mlkemSymBytes - 1), false)
  nonce = 0'u8
  i = 0
  while i < p.k:
    polyGetNoiseEta1Into(p, skpv.vec[i], buf.toOpenArray(mlkemSymBytes, 2 * mlkemSymBytes - 1), nonce)
    nonce = nonce + 1'u8
    i = i + 1
  i = 0
  while i < p.k:
    polyGetNoiseEta1Into(p, e.vec[i], buf.toOpenArray(mlkemSymBytes, 2 * mlkemSymBytes - 1), nonce)
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
  packPkInto(pk, p, pkpv, buf.toOpenArray(0, mlkemSymBytes - 1))
  secureClearPod(skpv)
  secureClearPod(skpvCache)
  secureClearPod(e)
  secureClearBytes(buf)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `indcpaKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc indcpaKeypair*(p: MlKemParams, seed: seq[byte] = @[]): tuple[pk, sk: seq[byte]] =
  ## Generate the underlying CPA-secure ML-KEM keypair.
  otterSpan("mlkem.indcpaKeypair"):
    var
      seedIn: seq[byte] = @[]
    if seed.len > 0 and seed.len != mlkemSymBytes:
      raise newException(ValueError, "ML-KEM seeded keypair requires a 32-byte seed")
    result.pk = newSeq[byte](p.indcpaPublicKeyBytes)
    result.sk = newSeq[byte](p.indcpaSecretKeyBytes)
    if seed.len == 0:
      seedIn = cryptoRandomBytes(mlkemSymBytes)
      indcpaKeypairInto(p, result.pk, result.sk, seedIn)
      secureClearBytes(seedIn)
    else:
      indcpaKeypairInto(p, result.pk, result.sk, seed)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `indcpaEncInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc indcpaEncInto*(p: MlKemParams, ct: var openArray[byte], m, pk, coins: openArray[byte]) =
  ## Encrypt one ML-KEM message with the underlying CPA-secure primitive into a caller buffer.
  var
    pkpv {.noinit.}: PolyVec
    seed {.noinit.}: array[mlkemSymBytes, byte]
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
  if m.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM message must be 32 bytes")
  if pk.len != p.indcpaPublicKeyBytes:
    raise newException(ValueError, "invalid ML-KEM public key length")
  if coins.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM coins must be 32 bytes")
  if ct.len != p.indcpaBytes:
    raise newException(ValueError, "invalid ML-KEM ciphertext length")
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
  secureClearPod(sp)
  secureClearPod(ep)
  secureClearPod(epp)
  secureClearPod(spCache)
  secureClearPod(k)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `indcpaEnc`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc indcpaEnc*(p: MlKemParams, m, pk, coins: openArray[byte]): seq[byte] =
  ## Encrypt one ML-KEM message with the underlying CPA-secure primitive.
  otterSpan("mlkem.indcpaEnc"):
    result = newSeq[byte](p.indcpaBytes)
    indcpaEncInto(p, result, m, pk, coins)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `indcpaDecInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc indcpaDecInto*(p: MlKemParams, m: var openArray[byte], ct, sk: openArray[byte]) =
  ## Decrypt one ML-KEM CPA ciphertext into a caller-provided 32-byte message buffer.
  var
    b {.noinit.}: PolyVec
    v {.noinit.}: Poly
    skpv {.noinit.}: PolyVec
    mp {.noinit.}: Poly
    bCache {.noinit.}: PolyVecMulCache
  if ct.len != p.indcpaBytes:
    raise newException(ValueError, "invalid ML-KEM ciphertext length")
  if sk.len != p.indcpaSecretKeyBytes:
    raise newException(ValueError, "invalid ML-KEM secret key length")
  if m.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM message output must be 32 bytes")
  unpackCiphertextInto(p, b, v, ct)
  unpackSkInto(p, skpv, sk)
  polyvecNtt(p, b)
  polyvecMulCacheCompute(p, bCache, b)
  polyvecBaseMulAccMontgomeryCached(p, mp, skpv, b, bCache)
  secureClearPod(skpv)
  polyInvNttToMont(mp)
  polySub(mp, v, mp)
  polyReduce(mp)
  polyToMsgInto(m, mp)
  secureClearPod(mp)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; public-key encryption key generation, encryption, and decryption algorithms for `indcpaDec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc indcpaDec*(p: MlKemParams, ct, sk: openArray[byte]): seq[byte] =
  ## Decrypt one ML-KEM CPA ciphertext into its 32-byte message.
  otterSpan("mlkem.indcpaDec"):
    result = newSeq[byte](mlkemSymBytes)
    indcpaDecInto(p, result, ct, sk)

{.pop.}
