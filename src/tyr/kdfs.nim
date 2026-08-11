## ---------------------------------------------------------------------
## | KDFs <- default tier: `deriveKey` for password and secret material |
## ---------------------------------------------------------------------
##
##   import tyr/kdfs            <- THIS FILE. deriveKey(kdfArgon2id, ...)
##   import tyr/kdfs/argon2     <- one family: argon2idHash(...)
##   import tyr/kdfs/dynamic    <- pick from a stored value at runtime
##   import tyr/kdfs/single     <- one family by build flag, for devices
##
## Each algorithm also answers to a `...Tyr...` public name, meaning "this
## repo's own version of it" - see the block at the bottom of this file.
##
## ⚠ Read `types.nim` before choosing. Feeding a human password to a FAST
## KDF is the classic mistake; use `isPasswordSafe` to check.

import ./kdfs/types
import ./kdfs/argon2
import ./kdfs/blake3_gimli_kdf
import ./kdfs/kdf

export types
export argon2, blake3_gimli_kdf, kdf

proc deriveKey*(f: KdfFamily, secret, salt: openArray[byte],
    outLen: int = 32, passCount: int = 3, memoryKiB: int = 65536,
    laneCount: int = 1): seq[byte] =
  ## f/secret/salt: family, the input secret or password, and a salt.
  ## outLen: how many key bytes you want back.
  ## passCount/memoryKiB/laneCount: cost knobs, used by the Argon2 families
  ## only. Higher means slower for you AND for an attacker. The defaults
  ## (3 passes, 64 MiB, 1 lane) are a reasonable desktop starting point;
  ## lower `memoryKiB` on a small device.
  ##
  ## ⚠ The salt must be unique per secret. Reusing one lets an attacker
  ## attack many derivations at once. 16 random bytes is the usual choice.
  case f
  of kdfArgon2i:
    result = argon2iHash(secret, salt, passCount, memoryKiB, laneCount, outLen)
  of kdfArgon2id:
    result = argon2idHash(secret, salt, passCount, memoryKiB, laneCount, outLen)
  of kdfBlake3Gimli:
    result = deriveBlake3GimliStageKey(secret, salt, 0,
      cfg = initBlake3GimliKdfConfig(keyBytes = outLen))
  of kdfCustom:
    result = deriveCustomKdf(secret, ckaBlake3, passCount, memoryKiB * 1024,
      1, 64)[0 ..< outLen]

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
