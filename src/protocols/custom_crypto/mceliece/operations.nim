## Parameterized Classic McEliece KEM operations for the pure-Nim backend.

import ./params
import ./util
import ./sk_gen
import ./pk_gen
import ./encrypt
import ./decrypt
import ../sha3/sha3
import ../random

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

proc publicKeyBytes*(p: McElieceParams): int {.inline.} =
  p.pkNRows * p.pkRowBytes

proc secretKeyBytes*(p: McElieceParams): int {.inline.} =
  32 + 8 + p.irrBytes + p.condBytes + p.sysN div 8

proc ciphertextBytes*(p: McElieceParams): int {.inline.} =
  p.syndBytes

proc sharedKeyBytes*: int {.inline.} = 32

proc buildSeedMaterial(seed: openArray[byte]): seq[byte] =
  ## Prepend domain byte 64 to the 32-byte seed, as in PQClean operations.c.
  result = newSeq[byte](33)
  result[0] = 64
  for i in 0 ..< 32:
    result[1 + i] = seed[i]

proc buildKeypairStreamLength(p: McElieceParams): int =
  ## Length of the SHAKE-derived stream used during keypair generation.
  (p.sysN div 8) + ((1 shl p.gfBits) * 4) + (p.sysT * 2) + 32

proc parseGoppaPolynomial(p: McElieceParams; buf: openArray[byte]): seq[GF] =
  result = newSeq[GF](p.sysT)
  for i in 0 ..< p.sysT:
    result[i] = loadGF(buf.toOpenArray(i * 2, i * 2 + 1))

proc encodeGoppaPolynomial(f: openArray[GF]): seq[byte] =
  result = newSeq[byte](f.len * 2)
  for i in 0 ..< f.len:
    storeGF(result.toOpenArray(i * 2, i * 2 + 1), f[i])

proc mcelieceTyrKeypair*(v: McElieceVariant; seed: seq[byte] = @[]): McElieceTyrKeypair =
  ## Generate a McEliece keypair (optionally seeded for reproducibility).
  var
    p = params(v)
    seedBytes: seq[byte]
    seedMaterial: seq[byte]
    stream: seq[byte]
    perm = newSeq[uint32](1 shl p.gfBits)
    irr = newSeq[GF](p.sysT)
    g = newSeq[GF](p.sysT + 1)
    storedSeed = newSeq[byte](32)
    controlBits: seq[byte]
    pivots: uint64 = 0
    fWords: seq[GF]
    seedOffset = 0
    permOffset = 0
    fOffset = 0
    nextSeedOffset = 0
    pk: seq[byte]
    irrBytes: seq[byte]

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
    stream = shake256(seedMaterial, buildKeypairStreamLength(p))
    for i in 0 ..< 32:
      seedMaterial[i + 1] = stream[nextSeedOffset + i]

    fWords = parseGoppaPolynomial(p, stream.toOpenArray(fOffset, nextSeedOffset - 1))
    if not genpolyGen(p, irr, fWords):
      continue

    for i in 0 ..< p.sysT:
      g[i] = irr[i]
    g[p.sysT] = 1

    for i in 0 ..< perm.len:
      perm[i] = load4(stream.toOpenArray(permOffset + i * 4, permOffset + i * 4 + 3))

    pk = newSeq[byte](publicKeyBytes(p))
    if not pkGen(p, g, perm, pk, controlBits, pivots):
      continue

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

proc buildEncapPreimage(p: McElieceParams; e, syndrome: openArray[byte]): seq[byte] =
  result = newSeq[byte](1 + p.sysN div 8 + p.syndBytes)
  result[0] = 1
  for i in 0 ..< p.sysN div 8:
    result[1 + i] = e[i]
  for i in 0 ..< p.syndBytes:
    result[1 + p.sysN div 8 + i] = syndrome[i]

proc buildDecapPreimage(p: McElieceParams; ok: bool; e, c, sk: openArray[byte]): seq[byte] =
  let condOffset = 32 + 8 + p.irrBytes
  let sOffset = condOffset + p.condBytes
  let m = (if ok: 0x00FF'u16 else: 0'u16)
  let nm = m xor 0xFFFF'u16

  result = newSeq[byte](1 + p.sysN div 8 + p.syndBytes)
  result[0] = byte(m and 1)
  for i in 0 ..< p.sysN div 8:
    let ev = if i < e.len: e[i] else: 0
    result[1 + i] = byte((nm and uint16(sk[sOffset + i])) or (m and uint16(ev)))
  for i in 0 ..< p.syndBytes:
    result[1 + p.sysN div 8 + i] = c[i]

proc mcelieceTyrEncaps*(v: McElieceVariant, pk: openArray[byte]): McElieceTyrCipher =
  ## Encapsulate against a McEliece public key and derive the shared secret.
  var
    p = params(v)
    enc: tuple[syndrome, errorVec: seq[byte]]
  assert pk.len == publicKeyBytes(p)
  enc = encryptError(p, pk)
  let preimage = buildEncapPreimage(p, enc.errorVec, enc.syndrome)
  result.variant = v
  result.ciphertext = enc.syndrome
  result.sharedSecret = shake256(preimage, sharedKeyBytes())

proc mcelieceTyrTryDecaps*(v: McElieceVariant, sk, ct: openArray[byte]): tuple[sharedSecret: seq[byte], ok: bool] =
  ## Decapsulate and return the derived shared secret plus a success flag.
  var
    p = params(v)
    dec: tuple[ok: bool, errorVec: seq[byte]]
  assert ct.len == ciphertextBytes(p)
  assert sk.len == secretKeyBytes(p)
  dec = decodeErrorVector(p, sk.toOpenArray(40, sk.len - 1), ct)
  let preimage = buildDecapPreimage(p, dec.ok, dec.errorVec, ct, sk)
  result.sharedSecret = shake256(preimage, sharedKeyBytes())
  result.ok = dec.ok

proc mcelieceTyrDecaps*(v: McElieceVariant, sk, ct: openArray[byte]): seq[byte] =
  ## Decapsulate and return the derived shared secret bytes.
  result = mcelieceTyrTryDecaps(v, sk, ct).sharedSecret
