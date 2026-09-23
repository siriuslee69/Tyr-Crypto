## Parameterized Classic McEliece KEM operations for the pure-Nim backend.

import runePragmas
import ./params
export params
import ./util
import ./sk_gen
import ./pk_gen
import ./controlbits
import ./encrypt
export encrypt.publicKeyPaddingIsZero, encrypt.ciphertextPaddingIsZero
import ./decrypt
import ../../helpers/otter_support
import ../../hashes/sha3
import ../../helpers/random

type
  ## Public/secret keypair emitted by the pure-Nim McEliece backend.
  McElieceTyrKeypair* = object
    variant*: McElieceVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Detached ciphertext plus shared secret from encapsulation.
  McElieceTyrCipher* = object
    variant*: McElieceVariant
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `publicKeyBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc publicKeyBytes*(p: McElieceParams): int {.inline.} =
  p.pkNRows * p.pkRowBytes

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `secretKeyBytes`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc secretKeyBytes*(p: McElieceParams): int {.inline.} =
  32 + 8 + p.irrBytes + p.condBytes + p.sysN div 8

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `ciphertextBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ciphertextBytes*(p: McElieceParams): int {.inline.} =
  p.syndBytes

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `sharedKeyBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc sharedKeyBytes*: int {.inline.} = 32

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `buildSeedMaterial`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc buildSeedMaterial(seed: openArray[byte]): seq[byte] =
  ## Prepend domain byte 64 to the 32-byte seed, as in PQClean operations.c.
  result = newSeq[byte](33)
  result[0] = 64
  for i in 0 ..< 32:
    result[1 + i] = seed[i]

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `buildKeypairStreamLength`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc buildKeypairStreamLength(p: McElieceParams): int =
  ## Length of the SHAKE-derived stream used during keypair generation.
  (p.sysN div 8) + ((1 shl p.gfBits) * 4) + (p.sysT * 2) + 32

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `parseGoppaPolynomial`; pitfall: reject malformed or non-canonical input before indexed access.
proc parseGoppaPolynomial(p: McElieceParams; buf: openArray[byte];
    outPoly: var seq[GF]) =
  if outPoly.len < p.sysT:
    outPoly.setLen(p.sysT)
  for i in 0 ..< p.sysT:
    outPoly[i] = loadGF(buf.toOpenArray(i * 2, i * 2 + 1))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `encodeGoppaPolynomial`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc encodeGoppaPolynomial(f: openArray[GF]): seq[byte] =
  result = newSeq[byte](f.len * 2)
  for i in 0 ..< f.len:
    storeGF(result.toOpenArray(i * 2, i * 2 + 1), f[i])

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mcelieceTyrKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mcelieceTyrKeypair*(v: McElieceVariant; seed: seq[byte] = @[]): McElieceTyrKeypair {.otterTrace.} =
  ## Generate a McEliece keypair (optionally seeded for reproducibility).
  var
    p = params(v)
    seedBytes: seq[byte] = default(seq[byte])
    seedMaterial: seq[byte] = default(seq[byte])
    stream: seq[byte] = default(seq[byte])
    perm = newSeq[uint32](1 shl p.gfBits)
    pi = newSeq[int16](1 shl p.gfBits)
    irr = newSeq[GF](p.sysT)
    g = newSeq[GF](p.sysT + 1)
    storedSeed = newSeq[byte](32)
    controlBits: seq[byte] = default(seq[byte])
    pivots: uint64 = 0
    fWords: seq[GF] = default(seq[GF])
    seedOffset = 0
    permOffset = 0
    fOffset = 0
    nextSeedOffset = 0
    pk: seq[byte] = default(seq[byte])
    irrBytes: seq[byte] = default(seq[byte])
  defer:
    clearSensitiveWords(seedBytes)
    clearSensitiveWords(seedMaterial)
    clearSensitiveWords(stream)
    clearSensitiveWords(perm)
    clearSensitiveWords(pi)
    clearSensitiveWords(irr)
    clearSensitiveWords(g)
    clearSensitiveWords(storedSeed)
    clearSensitiveWords(controlBits)
    clearSensitiveWords(fWords)
    clearSensitiveWords(irrBytes)

  if seed.len > 0 and seed.len != 32:
    raise newException(ValueError, "McEliece seeded keypair requires a 32-byte seed")
  if seed.len == 0:
    seedBytes = cryptoRandomBytes(32)
  else:
    seedBytes = newSeq[byte](32)
    for i in 0 ..< 32:
      seedBytes[i] = seed[i]

  seedMaterial = buildSeedMaterial(seedBytes)
  seedOffset = 0
  permOffset = p.sysN div 8
  fOffset = permOffset + ((1 shl p.gfBits) * 4)
  nextSeedOffset = fOffset + (p.sysT * 2)

  while true:
    for i in 0 ..< 32:
      storedSeed[i] = seedMaterial[i + 1]
    clearSensitiveWords(stream)
    otterSpan("mceliece.keypair.shake256"):
      stream = shake256(seedMaterial, buildKeypairStreamLength(p))
    for i in 0 ..< 32:
      seedMaterial[i + 1] = stream[nextSeedOffset + i]

    parseGoppaPolynomial(p, stream.toOpenArray(fOffset, nextSeedOffset - 1), fWords)
    var genpolyOk: bool = false
    otterSpan("mceliece.keypair.genpoly"):
      genpolyOk = genpolyGen(p, irr, fWords)
    if not genpolyOk:
      continue

    for i in 0 ..< p.sysT:
      g[i] = irr[i]
    g[p.sysT] = 1

    for i in 0 ..< perm.len:
      perm[i] = load4(stream.toOpenArray(permOffset + i * 4, permOffset + i * 4 + 3))

    var pkOk: bool = false
    otterSpan("mceliece.keypair.pkGen"):
      pkOk = pkGen(p, g, perm, pi, pk, pivots)
    if not pkOk:
      continue

    otterSpan("mceliece.keypair.controlBits"):
      when defined(danger):
        controlBits = controlBitsFromPermutationUnchecked(pi, p.gfBits)
      else:
        controlBits = controlBitsFromPermutation(pi, p.gfBits)
    otterSpan("mceliece.keypair.encodeIrr"):
      irrBytes = encodeGoppaPolynomial(irr)
    result.variant = v
    result.publicKey = pk
    result.secretKey = newSeq[byte](secretKeyBytes(p))
    for i in 0 ..< 32:
      result.secretKey[i] = storedSeed[i]
    store8(result.secretKey.toOpenArray(32, 39), pivots)
    for i in 0 ..< irrBytes.len:
      result.secretKey[40 + i] = irrBytes[i]
    for i in 0 ..< controlBits.len:
      result.secretKey[40 + irrBytes.len + i] = controlBits[i]
    for i in 0 ..< p.sysN div 8:
      result.secretKey[40 + irrBytes.len + controlBits.len + i] = stream[seedOffset + i]
    break

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `buildEncapPreimage`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc buildEncapPreimage(p: McElieceParams; e, syndrome: openArray[byte]): seq[byte] =
  result = newSeq[byte](1 + p.sysN div 8 + p.syndBytes)
  result[0] = 1
  for i in 0 ..< p.sysN div 8:
    result[1 + i] = e[i]
  for i in 0 ..< p.syndBytes:
    result[1 + p.sysN div 8 + i] = syndrome[i]

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `buildDecapPreimage`; pitfall: preserve implicit rejection and never expose a secret-dependent validity oracle.
proc buildDecapPreimage(p: McElieceParams; okMask: uint16; e, c, sk: openArray[byte]): seq[byte] =
  var
    condOffset: int = 32 + 8 + p.irrBytes
    sOffset: int = condOffset + p.condBytes
    m: uint16 = okMask and 0x00FF'u16
    nm: uint16 = m xor 0x00FF'u16
    i: int = 0
    ev: byte = 0
  result = newSeq[byte](1 + p.sysN div 8 + p.syndBytes)
  result[0] = byte(m and 1)
  i = 0
  while i < p.sysN div 8:
    ev = (if i < e.len: e[i] else: 0)
    result[1 + i] = byte((nm and uint16(sk[sOffset + i])) or (m and uint16(ev)))
    i = i + 1
  i = 0
  while i < p.syndBytes:
    result[1 + p.sysN div 8 + i] = c[i]
    i = i + 1

## Reference: [MCELIECE-20221023] section 3 public-key encoding; input rule for `requireValidPublicKey`; pitfall: a key with padding bits set must be refused, as the reference refuses it.
proc requireValidPublicKey(p: McElieceParams, pk: openArray[byte]) {.role: {sanitizer}.} =
  ## p/pk: the parameter set, and the public key a sender was handed.
  ## Raise unless the key has the right length and its padding bits are zero.
  if pk.len != publicKeyBytes(p):
    raise newException(ValueError, "invalid McEliece public key length")
  if not publicKeyPaddingIsZero(p, pk):
    raise newException(ValueError, "McEliece public key has nonzero padding bits")

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mcelieceTyrEncaps`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mcelieceTyrEncaps*(v: McElieceVariant, pk: openArray[byte]): McElieceTyrCipher {.otterTrace.} =
  ## Encapsulate against a McEliece public key and derive the shared secret.
  var
    p = params(v)
    enc: tuple[syndrome, errorVec: seq[byte]] = (@[], @[])
    preimage: seq[byte] = @[]
  defer:
    clearSensitiveWords(enc.errorVec)
    clearSensitiveWords(preimage)
  requireValidPublicKey(p, pk)
  otterSpan("mceliece.encaps.encryptError"):
    enc = encryptError(p, pk)
  otterSpan("mceliece.encaps.buildPreimage"):
    preimage = buildEncapPreimage(p, enc.errorVec, enc.syndrome)
  result.variant = v
  result.ciphertext = enc.syndrome
  otterSpan("mceliece.encaps.shake256"):
    result.sharedSecret = shake256(preimage, sharedKeyBytes())

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mcelieceTyrEncapsDerand`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mcelieceTyrEncapsDerand*(v: McElieceVariant, pk, randomness: openArray[byte]): McElieceTyrCipher {.otterTrace.} =
  ## Encapsulate against a McEliece public key from explicit PQClean `gen_e`
  ## random block material.
  var
    p = params(v)
    enc: tuple[syndrome, errorVec: seq[byte]] = (@[], @[])
    preimage: seq[byte] = @[]
  defer:
    clearSensitiveWords(enc.errorVec)
    clearSensitiveWords(preimage)
  requireValidPublicKey(p, pk)
  otterSpan("mceliece.encaps.encryptErrorDerand"):
    enc = encryptErrorDerand(p, pk, randomness)
  otterSpan("mceliece.encaps.buildPreimage"):
    preimage = buildEncapPreimage(p, enc.errorVec, enc.syndrome)
  result.variant = v
  result.ciphertext = enc.syndrome
  otterSpan("mceliece.encaps.shake256"):
    result.sharedSecret = shake256(preimage, sharedKeyBytes())

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mcelieceTyrTryDecaps`; pitfall: preserve implicit rejection and never expose a secret-dependent validity oracle.
proc mcelieceTyrTryDecapsInternal(v: McElieceVariant, sk,
    ct: openArray[byte]): tuple[sharedSecret: seq[byte], ok: bool] =
  ## Decapsulate with implicit rejection: `sharedSecret` is always derived and
  ## invalid ciphertexts yield pseudorandom keys. The `ok` flag is diagnostic
  ## only and must not gate online use of `sharedSecret`.
  var
    p = params(v)
    dec: tuple[ok: bool, okMask: uint16, errorVec: seq[byte]] = (false, 0'u16, @[])
    preimage: seq[byte] = @[]
  defer:
    clearSensitiveWords(dec.errorVec)
    clearSensitiveWords(preimage)
  if ct.len != ciphertextBytes(p):
    raise newException(ValueError, "invalid McEliece ciphertext length")
  if sk.len != secretKeyBytes(p):
    raise newException(ValueError, "invalid McEliece secret key length")
  ## Only the public ciphertext bytes decide this, never the secret key,
  ## so refusing loudly cannot turn into a validity oracle.
  if not ciphertextPaddingIsZero(p, ct):
    raise newException(ValueError, "McEliece ciphertext has nonzero padding bits")
  otterSpan("mceliece.decaps.decodeErrorVector"):
    dec = decodeErrorVector(p, sk.toOpenArray(40, sk.len - 1), ct)
  otterSpan("mceliece.decaps.buildPreimage"):
    preimage = buildDecapPreimage(p, dec.okMask, dec.errorVec, ct, sk)
  otterSpan("mceliece.decaps.shake256"):
    result.sharedSecret = shake256(preimage, sharedKeyBytes())
  result.ok = dec.ok

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mcelieceTyrDecaps`; pitfall: preserve implicit rejection and never expose a secret-dependent validity oracle.
proc mcelieceTyrDecaps*(v: McElieceVariant, sk, ct: openArray[byte]): seq[byte] {.otterTrace.} =
  ## Decapsulate and return the derived shared secret bytes (implicit rejection).
  ## Ciphertext validity is only exposed through a compile-time test hook.
  result = mcelieceTyrTryDecapsInternal(v, sk, ct).sharedSecret

when defined(tyrCryptoTestHooks):
  ## Reference: [MCELIECE-20221023] section 4.3, decapsulation algorithm; test-only diagnostic exposure must remain compile-time gated and must not alter implicit rejection.
  proc mcelieceTyrTryDecaps*(v: McElieceVariant, sk,
      ct: openArray[byte]): tuple[sharedSecret: seq[byte], ok: bool] =
    ## Test-only visibility for implicit-rejection regression checks.
    result = mcelieceTyrTryDecapsInternal(v, sk, ct)
