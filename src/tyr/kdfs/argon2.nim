## ----------------------------------------
## | Argon2 <- public surface
## ----------------------------------------
##
## Deliberately slow, memory-hard derivation. The right choice for human passwords.
##
## The full implementation lives in `./argon2/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./argon2/argon2

export argon2
## ╭⟢ Public names
##
## `argon2idHash` is the internal name used by the rest of Tyr.
## `argon2idTyrHash` is the same code under the name other repos call,
## chosen so it cannot collide with a library-backed Argon2.
##
## Two shapes are offered for each. The first takes a filled-in
## `Argon2Params` object. The second takes the four numbers directly, for
## callers that do not want to build the object first.

proc argon2iTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2i hash.
  result = argon2iHash(password, salt, p, b)

proc argon2iTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2i hash variant.
  result = argon2iHash(password, salt, p, h, b)

proc argon2iTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2i hash.
  result = argon2iHash(password, salt, passCount, memoryKiB, laneCount, outLen, b)

proc argon2iTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2i hash variant.
  result = argon2iHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)

proc argon2idTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2id hash.
  result = argon2idHash(password, salt, p, b)

proc argon2idTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2id hash variant.
  result = argon2idHash(password, salt, p, h, b)

proc argon2idTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2id hash.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, b)

proc argon2idTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2id hash variant.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)

proc deriveArgonLikeKey*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Standalone Tyr-owned custom Argon2id-style key derivation surface.
  result = argon2idHash(password, salt, p, h, b)

proc deriveArgonLikeKey*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Standalone Tyr-owned custom Argon2id-style key derivation surface.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)
