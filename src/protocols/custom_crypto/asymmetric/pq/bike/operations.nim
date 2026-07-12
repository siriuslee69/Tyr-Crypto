## ----------------------------------------------------------
## BIKE Operations <- pure-Nim BIKE-L1 key encapsulation flow
## ----------------------------------------------------------

import ./params
import ./types
import ./util
import ./sampling
import ./gf2x
import ./decode
import ../../../../helpers/otter_support
import ../../../sha3

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrKeypairFromParts`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc bikeTyrKeypairFromParts*(v: BikeVariant, seed0, seed1: openArray[byte]): BikeTyrKeypair

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `seedToMessage`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc seedToMessage(seed: BikeSeed): BikeMessage =
  var
    i: int = 0
  i = 0
  while i < bikeMessageBytes:
    result[i] = seed[i]
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `messageToSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc messageToSeed(m: BikeMessage): BikeSeed =
  var
    i: int = 0
  i = 0
  while i < bikeSeedBytes:
    result[i] = m[i]
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `functionH`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc functionH(m: BikeMessage): BikeRawError =
  result = generateErrorVector(messageToSeed(m))

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `functionL`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc functionL(E: BikeRawError): BikeMessage =
  var
    tmp: seq[byte] = @[]
    dgst: seq[byte] = @[]
    i: int = 0
  tmp = newSeq[byte](bikeRBytes * 2)
  copyMem(addr tmp[0], unsafeAddr E[0][0], bikeRBytes)
  copyMem(addr tmp[bikeRBytes], unsafeAddr E[1][0], bikeRBytes)
  dgst = sha3_384(tmp)
  i = 0
  while i < bikeMessageBytes:
    result[i] = dgst[i]
    i = i + 1
  secureZeroBytes(tmp)
  secureZeroBytes(dgst)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `functionK`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc functionK(m: BikeMessage, ct: BikeCiphertextRaw): BikeSharedSecret =
  var
    tmp: seq[byte] = @[]
    dgst: seq[byte] = @[]
    i: int = 0
  tmp = newSeq[byte](bikeMessageBytes + bikeRBytes + bikeMessageBytes)
  copyMem(addr tmp[0], unsafeAddr m[0], bikeMessageBytes)
  copyMem(addr tmp[bikeMessageBytes], unsafeAddr ct.c0[0], bikeRBytes)
  copyMem(addr tmp[bikeMessageBytes + bikeRBytes], unsafeAddr ct.c1[0], bikeMessageBytes)
  dgst = sha3_384(tmp)
  i = 0
  while i < bikeSharedSecretBytes:
    result[i] = dgst[i]
    i = i + 1
  secureZeroBytes(tmp)
  secureZeroBytes(dgst)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `encryptRaw`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc encryptRaw(E: BikeRawError, pkRaw: BikeRawPoly, m: BikeMessage): BikeCiphertextRaw =
  var
    pk: BikePadPoly = @[]
    ePad: array[bikeN0, BikePadPoly]
    c0: BikePadPoly = @[]
    l: BikeMessage
    i: int = 0
  pk = rawToPadPoly(pkRaw)
  ePad = rawErrorToPad(E)
  c0 = gf2xModMul(ePad[1], pk)
  gf2xModAdd(c0, c0, ePad[0])
  result.c0 = padPolyToRaw(c0)
  l = functionL(E)
  i = 0
  while i < bikeMessageBytes:
    result.c1[i] = l[i] xor m[i]
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `reencrypt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reencrypt(E: BikeRawError, ct: BikeCiphertextRaw): BikeMessage =
  var
    l: BikeMessage
    i: int = 0
  l = functionL(E)
  i = 0
  while i < bikeMessageBytes:
    result[i] = l[i] xor ct.c1[i]
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrKeypairDerand`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc bikeTyrKeypairDerand*(v: BikeVariant, randomness: openArray[byte]): BikeTyrKeypair {.otterTrace.} =
  ## Generate a pure-Nim BIKE keypair from explicit 64-byte keypair material.
  if randomness.len != bikeKeypairRandomBytes:
    raise newException(ValueError, "BIKE-L1 keypair randomness must be 64 bytes")
  result = bikeTyrKeypairFromParts(v,
    randomness.toOpenArray(0, bikeSeedBytes - 1),
    randomness.toOpenArray(bikeSeedBytes, bikeKeypairRandomBytes - 1))

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrKeypairFromParts`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc bikeTyrKeypairFromParts*(v: BikeVariant, seed0, seed1: openArray[byte]): BikeTyrKeypair =
  ## Generate a BIKE keypair from the two exact 32-byte seeds used by the KEM.
  var
    secret: tuple[h0, h1: BikePadPoly, w0, w1: BikeIndexList]
    sigma: BikeMessage
    h0Inv: BikePadPoly = @[]
    h: BikePadPoly = @[]
    skState: BikeSecretKeyState
  if seed0.len != bikeSeedBytes or seed1.len != bikeSeedBytes:
    raise newException(ValueError, "BIKE-L1 keypair seeds must both be 32 bytes")
  secret = generateSecretKey(toSeed(seed0))
  sigma = seedToMessage(toSeed(seed1))
  h0Inv = gf2xModInv(secret.h0)
  h = gf2xModMul(secret.h1, h0Inv)
  skState.wlist[0] = secret.w0
  skState.wlist[1] = secret.w1
  skState.bin[0] = padPolyToRaw(secret.h0)
  skState.bin[1] = padPolyToRaw(secret.h1)
  skState.pk = padPolyToRaw(h)
  skState.sigma = sigma
  result.variant = v
  result.publicKey = serializePublicKey(skState.pk)
  result.secretKey = serializeSecretKey(skState)
  secureZeroWords(secret.h0)
  secureZeroWords(secret.h1)
  secureZeroPod(secret.w0)
  secureZeroPod(secret.w1)
  secureZeroPod(sigma)
  secureZeroWords(h0Inv)
  secureZeroPod(skState.wlist)
  secureZeroPod(skState.bin)
  secureZeroPod(skState.sigma)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc bikeTyrKeypair*(v: BikeVariant, randomness: seq[byte] = @[]): BikeTyrKeypair {.otterTrace.} =
  ## Generate a BIKE-L1 keypair, optionally from explicit 64-byte randomness.
  var
    material: seq[byte] = @[]
  if randomness.len > 0 and randomness.len != bikeKeypairRandomBytes:
    raise newException(ValueError, "BIKE-L1 seeded keypair requires 64 bytes")
  if randomness.len == 0:
    material = randomKeypairMaterial()
  else:
    material = copyByteSeq(randomness)
  result = bikeTyrKeypairDerand(v, material)
  secureZeroBytes(material)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrEncapsDerand`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc bikeTyrEncapsDerand*(v: BikeVariant, pk: openArray[byte],
    randomness: openArray[byte]): BikeTyrCipher {.otterTrace.} =
  ## Encapsulate against a BIKE-L1 public key from explicit 64-byte randomness.
  var
    pkRaw: BikeRawPoly
    m: BikeMessage
    E: BikeRawError
    ct: BikeCiphertextRaw
    ss: BikeSharedSecret
  if pk.len != bikePublicKeyBytes:
    raise newException(ValueError, "invalid BIKE public key length")
  if randomness.len != bikeEncapsRandomBytes:
    raise newException(ValueError, "BIKE-L1 encaps randomness must be 64 bytes")
  pkRaw = parsePublicKey(pk)
  m = seedToMessage(toSeed(randomness, 0))
  E = functionH(m)
  ct = encryptRaw(E, pkRaw, m)
  ss = functionK(m, ct)
  result.variant = v
  result.ciphertext = serializeCiphertext(ct)
  result.sharedSecret = copyByteSeq(ss)
  secureZeroPod(m)
  secureZeroPod(E)
  secureZeroPod(ss)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrEncaps`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc bikeTyrEncaps*(v: BikeVariant, pk: openArray[byte],
    randomness: seq[byte] = @[]): BikeTyrCipher {.otterTrace.} =
  ## Encapsulate against a BIKE-L1 public key.
  var
    material: seq[byte] = @[]
  if randomness.len > 0 and randomness.len != bikeEncapsRandomBytes:
    raise newException(ValueError, "BIKE-L1 seeded encaps requires 64 bytes")
  if randomness.len == 0:
    material = randomEncapsMaterial()
  else:
    material = copyByteSeq(randomness)
  result = bikeTyrEncapsDerand(v, pk, material)
  secureZeroBytes(material)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrTryDecaps`; pitfall: preserve implicit rejection and never expose a secret-dependent validity oracle.
proc bikeTyrTryDecaps*(v: BikeVariant, sk, ctBytes: openArray[byte]): tuple[sharedSecret: seq[byte], ok: bool] =
  ## Decapsulate with implicit rejection. The `ok` result is diagnostic only:
  ## application code must not branch on it or expose it to a peer because that
  ## converts the decoder result into a ciphertext-validity oracle. Normal
  ## callers must use `bikeTyrDecaps` and consume its derived secret uniformly.
  var
    skState: BikeSecretKeyState
    ct: BikeCiphertextRaw
    E: BikeRawError
    ePrime: BikeRawError
    mPrime: BikeMessage
    eTmp: BikeRawError
    successCond: uint32 = 0
    mask: uint32 = 0
    i: int = 0
    ss: BikeSharedSecret
  if sk.len != bikeSecretKeyBytes:
    raise newException(ValueError, "invalid BIKE secret key length")
  if ctBytes.len != bikeCiphertextBytes:
    raise newException(ValueError, "invalid BIKE ciphertext length")
  skState = parseSecretKey(sk)
  ct = parseCiphertext(ctBytes)
  E = decodeBike(ct, skState)
  ePrime = E
  mPrime = reencrypt(ePrime, ct)
  eTmp = functionH(mPrime)
  successCond = secureCmpBytes(ePrime[0], eTmp[0])
  successCond = successCond and secureCmpBytes(ePrime[1], eTmp[1])
  mask = secureL32Mask(0'u32, successCond)
  i = 0
  while i < bikeMessageBytes:
    mPrime[i] = byte((mPrime[i] and byte((not mask) and 0xff'u32)) or
      (skState.sigma[i] and byte(mask and 0xff'u32)))
    i = i + 1
  ss = functionK(mPrime, ct)
  result.sharedSecret = copyByteSeq(ss)
  result.ok = successCond == 1'u32
  secureZeroPod(skState)
  secureZeroPod(E)
  secureZeroPod(ePrime)
  secureZeroPod(eTmp)
  secureZeroPod(mPrime)
  secureZeroPod(ss)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `bikeTyrDecaps`; pitfall: preserve implicit rejection and never expose a secret-dependent validity oracle.
proc bikeTyrDecaps*(v: BikeVariant, sk, ctBytes: openArray[byte]): seq[byte] {.otterTrace.} =
  ## Decapsulate a BIKE-L1 ciphertext and return the shared secret.
  result = bikeTyrTryDecaps(v, sk, ctBytes).sharedSecret
