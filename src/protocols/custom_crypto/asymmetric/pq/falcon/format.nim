## ------------------------------------------------------------------
## Falcon Format <- key/signature decoding for the pure-Nim Falcon API
## ------------------------------------------------------------------

import ./codec
import ./common
import ./params
import ./shake
import ./util
import ./vrfy

const
  falconNonceLen* = 40

type
  FalconDecodedSecret* = object
    logn*: int
    f*: seq[int8]
    g*: seq[int8]
    F*: seq[int8]
    G*: seq[int8]

  FalconDecodedPublic* = object
    logn*: int
    h*: seq[uint16]

  FalconDecodedSignature* = object
    logn*: int
    nonce*: array[falconNonceLen, byte]
    s2*: seq[int16]

proc expectHeader(data: openArray[byte], tag, logn: int): bool {.inline.} =
  data.len > 0 and data[0] == byte(tag + logn)

proc decodeSecretKey*(decoded: var FalconDecodedSecret, sk: openArray[byte], v: FalconVariant): bool =
  let
    p = params(v)
    logn = p.logn
    n = mkn(logn)
  var u = 1
  if sk.len != p.secretKeyBytes or not expectHeader(sk, 0x50, logn):
    return false
  decoded.logn = logn
  decoded.f = newSeq[int8](n)
  decoded.g = newSeq[int8](n)
  decoded.F = newSeq[int8](n)
  decoded.G = newSeq[int8](n)
  let usedF = trimI8Decode(decoded.f, sk.toOpenArray(u, sk.high), logn, int(falconMaxSmallBits[logn]))
  if usedF == 0:
    return false
  u += usedF
  let usedG = trimI8Decode(decoded.g, sk.toOpenArray(u, sk.high), logn, int(falconMaxSmallBits[logn]))
  if usedG == 0:
    return false
  u += usedG
  let usedBigF = trimI8Decode(decoded.F, sk.toOpenArray(u, sk.high), logn, int(falconMaxLargeBits[logn]))
  if usedBigF == 0:
    return false
  u += usedBigF
  if u != sk.len:
    return false
  completePrivate(decoded.G, decoded.f, decoded.g, decoded.F, logn)

proc decodePublicKey*(decoded: var FalconDecodedPublic, pk: openArray[byte], v: FalconVariant): bool =
  let
    p = params(v)
    logn = p.logn
    n = mkn(logn)
  if pk.len != p.publicKeyBytes or not expectHeader(pk, 0x00, logn):
    return false
  decoded.logn = logn
  decoded.h = newSeq[uint16](n)
  if modQDecode(decoded.h, pk.toOpenArray(1, pk.high), logn) != p.publicKeyBytes - 1:
    return false
  true

proc decodePublicKeyToNtt*(decoded: var FalconDecodedPublic, pk: openArray[byte], v: FalconVariant): bool =
  if not decodePublicKey(decoded, pk, v):
    return false
  toNttMonty(decoded.h, decoded.logn)
  true

proc decodeSignature*(decoded: var FalconDecodedSignature, sig: openArray[byte], v: FalconVariant): bool =
  let
    p = params(v)
    logn = p.logn
    n = mkn(logn)
  if sig.len < 1 + falconNonceLen or sig.len > p.signatureBytes:
    return false
  if not expectHeader(sig, 0x30, logn):
    return false
  decoded.logn = logn
  decoded.s2 = newSeq[int16](n)
  var i = 0
  while i < falconNonceLen:
    decoded.nonce[i] = sig[1 + i]
    inc i
  let used = compDecode(decoded.s2, sig.toOpenArray(1 + falconNonceLen, sig.high), logn)
  if used == 0:
    return false
  if used != sig.len - 1 - falconNonceLen:
    return false
  true

proc hashNonceMessageToPoint*(dst: var openArray[uint16], nonce: openArray[byte], msg: openArray[byte], logn: int) =
  var ctx: FalconShake256
  initFalconShake256(ctx, nonce, msg)
  hashToPointVarTime(ctx, dst, logn)
