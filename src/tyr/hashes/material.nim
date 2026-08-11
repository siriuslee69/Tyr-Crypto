## ---------------------------------------------------------------------
## | Hash Material <- typed hash material, sizes carried by the type    |
## ---------------------------------------------------------------------
##
##   var d = hash(message, blake3HashM())          <- fixed 32-byte digest
##   var d = hash(message, sha3HashM(outLen: 64))  <- variable length
##
## Every type here is empty or holds only a key and a length, because a
## hash needs no more than its input. The keyed variants carry their key
## as `array[32, byte]`, so a wrong-length key is a compile error rather
## than a runtime check.
##
## Shared pieces (`AlgorithmKind`, `layoutOf`, `HashDigest32`) come from
## `tyr/helpers/material`.

import ../helpers/material
import ./blake3
import ./sha3
import ../ciphers/gimli_sponge

export material

type
  ## Material for plain BLAKE3 hashing. Fixed 32-byte output.
  blake3HashM* = object

  ## Material for plain Gimli sponge hashing. Fixed 32-byte output.
  gimliHashM* = object

  ## Material for SHA3 hashing. `outLen = 0` means the natural 32 bytes.
  sha3HashM* = object
    outLen*: uint16

  ## Material for keyed BLAKE3 hashing. `outLen = 0` means 32 bytes.
  blake3KeyedHashM* = object
    key*: array[32, byte]
    outLen*: uint16

  ## Short alias kept for callers that spell the plain BLAKE3 material
  ## without the `Hash` in the middle.
  blake3M* = blake3HashM

  ## Tyr-suffixed alias for the local BLAKE3 hash material.
  blake3TyrHashM* = blake3HashM
  ## Tyr-suffixed alias for the local Gimli hash material.
  gimliTyrHashM* = gimliHashM
  ## Tyr-suffixed alias for the local SHA3 hash material.
  sha3TyrHashM* = sha3HashM
  ## Tyr-suffixed alias for the local keyed BLAKE3 material.
  blake3TyrKeyedHashM* = blake3KeyedHashM

## ╭⟢ Which layout entry each material type names

proc algorithmOf*(T: typedesc[blake3HashM]): AlgorithmKind = akBlake3Hash
proc algorithmOf*(T: typedesc[gimliHashM]): AlgorithmKind = akGimliHash
proc algorithmOf*(T: typedesc[sha3HashM]): AlgorithmKind = akSha3Hash
proc algorithmOf*(T: typedesc[blake3KeyedHashM]): AlgorithmKind = akBlake3KeyedHash

## ╭⟢ Hashing

proc hash*(message: openArray[byte], _: blake3HashM): HashDigest32 =
  ## Hash `message` with plain BLAKE3 and return the fixed 32-byte digest type.
  result = toDigest32(blake3Hash(message, digestBytes))

proc hash*(message: openArray[byte], _: gimliHashM): HashDigest32 =
  ## Hash `message` with the Gimli sponge and return the fixed 32-byte digest type.
  result = toDigest32(gimliXof(@[], @[], message, digestBytes))

proc hash*(message: openArray[byte], m: sha3HashM): seq[byte] =
  ## Hash `message` with SHA3 and optional variable output length.
  let outLen =
    if m.outLen == 0'u16: digestBytes
    else: int(m.outLen)
  result = sha3Hash(message, outLen)

proc hash*(message: openArray[byte], m: blake3KeyedHashM): seq[byte] =
  ## Hash `message` with keyed BLAKE3 and optional variable output length.
  let outLen =
    if m.outLen == 0'u16: digestBytes
    else: int(m.outLen)
  result = blake3KeyedHash(toSeqBytes(m.key), toSeqBytes(message), outLen)
