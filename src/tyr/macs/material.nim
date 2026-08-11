## ---------------------------------------------------------------------
## | MAC Material <- typed authenticator material, sizes in the type    |
## ---------------------------------------------------------------------
##
##   var tag = hmac(message, blake3hmacM(key: k))
##   var ok  = authenticate(message, blake3hmacVerifyM(key: k, tag: tag))
##
## Creating a tag and checking one are separate types on purpose: the
## verify material carries the tag that arrived, so there is no way to
## call `authenticate` having forgotten to supply it.
##
## ⚠ `poly1305hmacM` is a ONE-TIME authenticator despite the `hmac` in the
## name. Its key must never authenticate a second message - reuse lets an
## attacker recover the key and forge any message they like. The other
## three take a long-lived key safely. See `tyr/macs/types` for the split.
##
## Verification is constant-time throughout: `authenticate` compares via
## `constantTimeEqual`, so the time it takes never reveals how much of a
## tag a guesser got right.

import ../helpers/material
import ../helpers/tiers
import ./hmac
import ./poly1305

export material

type
  ## Material for BLAKE3-backed HMAC creation.
  blake3hmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for Gimli-backed HMAC creation.
  gimlihmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for Poly1305 one-time tag creation.
  poly1305hmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for SHA3-backed HMAC creation.
  sha3hmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for BLAKE3-backed HMAC verification.
  blake3hmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16
  ## Material for Gimli-backed HMAC verification.
  gimlihmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16
  ## Material for Poly1305 one-time tag verification.
  poly1305hmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16
  ## Material for SHA3-backed HMAC verification.
  sha3hmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16

  ## Tyr-suffixed alias for the local BLAKE3 HMAC material.
  blake3TyrHmacM* = blake3hmacM
  ## Tyr-suffixed alias for the local Gimli HMAC material.
  gimliTyrHmacM* = gimlihmacM
  ## Tyr-suffixed alias for the local Poly1305 HMAC material.
  poly1305TyrHmacM* = poly1305hmacM
  ## Tyr-suffixed alias for the local SHA3 HMAC material.
  sha3TyrHmacM* = sha3hmacM
  ## Tyr-suffixed alias for the local BLAKE3 HMAC verification material.
  blake3TyrHmacVerifyM* = blake3hmacVerifyM
  ## Tyr-suffixed alias for the local Gimli HMAC verification material.
  gimliTyrHmacVerifyM* = gimlihmacVerifyM
  ## Tyr-suffixed alias for the local Poly1305 HMAC verification material.
  poly1305TyrHmacVerifyM* = poly1305hmacVerifyM
  ## Tyr-suffixed alias for the local SHA3 HMAC verification material.
  sha3TyrHmacVerifyM* = sha3hmacVerifyM

## ╭⟢ Which layout entry each material type names

proc algorithmOf*(T: typedesc[blake3hmacM]): AlgorithmKind = akBlake3Hmac
proc algorithmOf*(T: typedesc[gimlihmacM]): AlgorithmKind = akGimliHmac
proc algorithmOf*(T: typedesc[poly1305hmacM]): AlgorithmKind = akPoly1305Hmac
proc algorithmOf*(T: typedesc[sha3hmacM]): AlgorithmKind = akSha3Hmac
proc algorithmOf*(T: typedesc[blake3hmacVerifyM]): AlgorithmKind = akBlake3Hmac
proc algorithmOf*(T: typedesc[gimlihmacVerifyM]): AlgorithmKind = akGimliHmac
proc algorithmOf*(T: typedesc[poly1305hmacVerifyM]): AlgorithmKind = akPoly1305Hmac
proc algorithmOf*(T: typedesc[sha3hmacVerifyM]): AlgorithmKind = akSha3Hmac

## ╭⟢ Output lengths
##
## `outLen = 0` in the material means "this algorithm's natural length".
## Poly1305 has exactly one, so it gets its own resolver.

proc hmacLen(outLen: uint16): int =
  if outLen == 0'u16:
    result = digestBytes
  else:
    result = int(outLen)

proc poly1305Len(outLen: uint16): int =
  if outLen == 0'u16:
    result = 16
  else:
    result = int(outLen)

## ╭⟢ Pick the authenticator by its tier value

proc macOutLen(alg: MacAlgorithm, outLen: int): int =
  ## alg/outLen: which authenticator, and the requested tag length, or 0
  ## for its natural one.
  ##
  ## A requested length is validated like any other. This used to return
  ## early on `outLen > 0` and skip both checks below, so the policy was
  ## really being enforced by whatever the backend happened to do next -
  ## which meant it moved whenever a backend changed. It lives here now.
  result = outLen
  if result <= 0:
    case alg
    of maPoly1305:
      result = 16
    else:
      result = digestBytes
  if result < 16:
    raise newException(ValueError, "high-level MAC output must be at least 16 bytes")
  if alg == maPoly1305 and result != 16:
    raise newException(ValueError, "Poly1305 MAC output must be exactly 16 bytes")

proc hmacCreate*(alg: MacAlgorithm, key, msg: seq[uint8], outLen: int = 0): seq[uint8] =
  ## Create a detached MAC/tag with the selected keyed hash backend.
  ##
  ## ⚠ `maPoly1305` is a ONE-TIME authenticator and this entry point hands
  ## `key` straight to it. That key must never cover a second message: two
  ## tags under one key let an attacker solve for the key and forge
  ## freely. The other three take a long-lived key safely.
  ##
  ## For a Poly1305 tag that IS safe under a reused key, use
  ## `poly1305DerivedTag` from `tyr/macs/poly1305`, which takes a nonce and
  ## derives a fresh one-time key from it.
  let resolvedOutLen = macOutLen(alg, outLen)
  case alg
  of maBlake3:
    result = blake3CustomHmac(key, msg, resolvedOutLen)
  of maGimli:
    result = gimliCustomHmac(key, msg, resolvedOutLen)
  of maPoly1305:
    result = poly1305Tag(key, msg)
  of maSha3:
    result = sha3CustomHmac(key, msg, resolvedOutLen)

proc hmacAuth*(alg: MacAlgorithm, key, msg, tag: seq[uint8], outLen: int = 0): bool =
  ## Verify a detached MAC/tag with the selected keyed hash backend.
  var expected: seq[uint8] = @[]
  expected = hmacCreate(alg, key, msg, macOutLen(alg, outLen))
  result = constantTimeEqual(expected, tag)

## ╭⟢ Tagging and checking from typed material

proc hmac*(message: openArray[byte], m: blake3hmacM): seq[byte] =
  ## Create a detached BLAKE3-backed HMAC tag from typed material.
  result = hmacCreate(maBlake3, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc hmac*(message: openArray[byte], m: gimlihmacM): seq[byte] =
  result = hmacCreate(maGimli, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc hmac*(message: openArray[byte], m: poly1305hmacM): seq[byte] =
  result = hmacCreate(maPoly1305, toSeqBytes(m.key), toSeqBytes(message), poly1305Len(m.outLen))

proc hmac*(message: openArray[byte], m: sha3hmacM): seq[byte] =
  result = hmacCreate(maSha3, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: blake3hmacVerifyM): bool =
  ## Verify a detached BLAKE3-backed HMAC tag from typed material.
  result = hmacAuth(maBlake3, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: gimlihmacVerifyM): bool =
  result = hmacAuth(maGimli, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: poly1305hmacVerifyM): bool =
  result = hmacAuth(maPoly1305, toSeqBytes(m.key), toSeqBytes(message), m.tag, poly1305Len(m.outLen))

proc authenticate*(message: openArray[byte], m: sha3hmacVerifyM): bool =
  result = hmacAuth(maSha3, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))
