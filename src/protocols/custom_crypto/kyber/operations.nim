## ---------------------------------------------------------
## Kyber Operations <- KEM wrappers for the pure-Nim backend
## ---------------------------------------------------------

import ./params
import ./util
import ./indcpa
import ./symmetric
import ./verify
import ../random

type
  ## Public/secret keypair emitted by the pure-Nim Kyber backend.
  KyberTyrKeypair* = object
    variant*: KyberVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Detached ciphertext plus shared secret emitted by encapsulation.
  KyberTyrCipher* = object
    variant*: KyberVariant
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]

## Testing/reproducibility surface. Keep public during KAT and optimization
## work; tighten or remove this from the public API once Kyber stabilizes.
proc kyberTyrKeypairFromParts*(v: KyberVariant, indcpaSeed, zSeed: openArray[byte]): KyberTyrKeypair

proc kyberTyrKeypairDerand*(v: KyberVariant, seedMaterial: openArray[byte]): KyberTyrKeypair =
  ## Generate a pure-Nim Kyber keypair from explicit 64-byte keypair material.
  ## Testing/reproducibility surface to narrow later.
  result = kyberTyrKeypairFromParts(v,
    seedMaterial.toOpenArray(0, 31),
    seedMaterial.toOpenArray(32, 63))

proc kyberTyrKeypairFromParts*(v: KyberVariant, indcpaSeed, zSeed: openArray[byte]): KyberTyrKeypair =
  ## Generate a pure-Nim Kyber keypair from the two exact randomness draws used by the KEM.
  var
    p: KyberParams = params(v)
    pkHash: array[kyberSymBytes, byte]
  if indcpaSeed.len != 32:
    raise newException(ValueError, "Kyber indcpa keypair seed must be 32 bytes")
  if zSeed.len != 32:
    raise newException(ValueError, "Kyber fallback z seed must be 32 bytes")
  result.variant = v
  result.publicKey = newSeq[byte](p.publicKeyBytes)
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  indcpaKeypairInto(p,
    result.publicKey,
    result.secretKey.toOpenArray(0, p.indcpaSecretKeyBytes - 1),
    indcpaSeed)
  hashHInto(pkHash, result.publicKey)
  copyBytes(result.secretKey, p.indcpaSecretKeyBytes, result.publicKey)
  copyBytes(result.secretKey, p.secretKeyBytes - 2 * kyberSymBytes, pkHash)
  copyBytes(result.secretKey, p.secretKeyBytes - kyberSymBytes, zSeed)
  clearBytes(pkHash)

proc kyberTyrKeypair*(v: KyberVariant, seed: seq[byte] = @[]): KyberTyrKeypair =
  ## Generate a pure-Nim Kyber keypair.
  var
    seedMaterial: seq[byte] = @[]
    seedMaterialBuf: array[2 * kyberSymBytes, byte]
  if seed.len > 0 and seed.len != kyberSymBytes:
    raise newException(ValueError, "Kyber seeded keypair requires a 32-byte seed")
  if seed.len == 0:
    seedMaterial = cryptoRandomBytes(64)
    fillArray(seedMaterialBuf, seedMaterial)
    secureClearBytes(seedMaterial)
  else:
    hashGInto(seedMaterialBuf, seed)
  result = kyberTyrKeypairDerand(v, seedMaterialBuf)
  secureClearBytes(seedMaterialBuf)

proc kyberTyrEncaps*(v: KyberVariant, pk: openArray[byte], seed: seq[byte] = @[]): KyberTyrCipher =
  ## Encapsulate against a pure-Nim Kyber public key.
  var
    p: KyberParams = params(v)
    entropy: seq[byte] = @[]
    entropyBuf: array[kyberSymBytes, byte]
    buf: array[2 * kyberSymBytes, byte]
    kr: array[2 * kyberSymBytes, byte]
    pkHash: array[kyberSymBytes, byte]
    ctHash: array[kyberSymBytes, byte]
  if pk.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid Kyber public key length")
  if seed.len > 0 and seed.len != kyberSymBytes:
    raise newException(ValueError, "Kyber seeded encapsulation requires a 32-byte seed")
  if seed.len == 0:
    entropy = cryptoRandomBytes(kyberSymBytes)
    fillArray(entropyBuf, entropy)
    secureClearBytes(entropy)
  else:
    fillArray(entropyBuf, seed)
  hashHInto(buf.toOpenArray(0, kyberSymBytes - 1), entropyBuf)
  hashHInto(pkHash, pk)
  copyBytes(buf, kyberSymBytes, pkHash)
  hashGInto(kr, buf)
  result.variant = v
  result.ciphertext = newSeq[byte](p.ciphertextBytes)
  indcpaEncInto(p, result.ciphertext, buf.toOpenArray(0, kyberSymBytes - 1), pk,
    kr.toOpenArray(kyberSymBytes, 2 * kyberSymBytes - 1))
  hashHInto(ctHash, result.ciphertext)
  copyBytes(kr, kyberSymBytes, ctHash)
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  kdfInto(result.sharedSecret, kr)
  secureClearBytes(entropyBuf)
  secureClearBytes(buf)
  secureClearBytes(kr)
  clearBytes(pkHash)
  clearBytes(ctHash)

proc kyberTyrTryDecaps(v: KyberVariant, sk, ct: openArray[byte]): tuple[sharedSecret: seq[byte], ok: bool] =
  ## Internal decapsulation helper that keeps the re-encryption check private
  ## so callers cannot accidentally expose a validity oracle.
  var
    p: KyberParams = params(v)
    buf: array[2 * kyberSymBytes, byte]
    kr: array[2 * kyberSymBytes, byte]
    cmp: array[1568, byte]
    hct: array[kyberSymBytes, byte]
    fail: int = 0
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid Kyber secret key length")
  if ct.len != p.ciphertextBytes:
    raise newException(ValueError, "invalid Kyber ciphertext length")
  indcpaDecInto(p, buf.toOpenArray(0, kyberSymBytes - 1), ct,
    sk.toOpenArray(0, p.indcpaSecretKeyBytes - 1))
  copyBytes(buf, kyberSymBytes, sk.toOpenArray(p.secretKeyBytes - 2 * kyberSymBytes,
    p.secretKeyBytes - kyberSymBytes - 1))
  hashGInto(kr, buf)
  indcpaEncInto(p, cmp.toOpenArray(0, p.ciphertextBytes - 1), buf.toOpenArray(0, kyberSymBytes - 1),
    sk.toOpenArray(p.indcpaSecretKeyBytes, p.indcpaSecretKeyBytes + p.indcpaPublicKeyBytes - 1),
    kr.toOpenArray(kyberSymBytes, 2 * kyberSymBytes - 1))
  fail = verifyBytes(ct, cmp.toOpenArray(0, p.ciphertextBytes - 1))
  hashHInto(hct, ct)
  copyBytes(kr, kyberSymBytes, hct)
  cmovBytes(kr.toOpenArray(0, kyberSymBytes - 1),
    sk.toOpenArray(p.secretKeyBytes - kyberSymBytes, p.secretKeyBytes - 1), uint8(fail))
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  kdfInto(result.sharedSecret, kr)
  result.ok = fail == 0
  secureClearBytes(buf)
  secureClearBytes(kr)
  clearBytes(cmp)
  clearBytes(hct)

proc kyberTyrDecaps*(v: KyberVariant, sk, ct: openArray[byte]): seq[byte] =
  ## Decapsulate a Kyber ciphertext and return the derived shared secret
  ## without exposing the internal re-encryption check result.
  result = kyberTyrTryDecaps(v, sk, ct).sharedSecret
