## ---------------------------------------------------------------------
## | KDFs <- default tier: `deriveKey` for password and secret material |
## ---------------------------------------------------------------------
##
##   import tyr/kdfs            <- THIS FILE. deriveKey(kdfArgon2id, ...)
##   import tyr/kdfs/argon2     <- one family: argon2idHash(...)
##   import tyr/kdfs/dynamic    <- pick from a stored value at runtime
##   import tyr/kdfs/single     <- one family by build flag, for devices
##
## Each algorithm also answers to a `...Tyr...` public name on its own
## surface, e.g. `tyr/kdfs/argon2` gives `argon2idTyrHash`.
##
## ⚠ Read `types.nim` before choosing. Feeding a human password to a FAST
## KDF is the classic mistake; use `isPasswordSafe` to check.

import metaPragmas
import ./kdfs/types
import ./kdfs/argon2
import ./kdfs/blake3_gimli_kdf
import ./kdfs/kdf

export types
export argon2, blake3_gimli_kdf, kdf

proc deriveKey*(f: KdfFamily, secret, salt: openArray[byte],
    outLen: int = 32, passCount: int = 3, memoryKiB: int = 65536,
    laneCount: int = 1): seq[byte] {.role: {math}.} =
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
    result = deriveBlake3GimliStageKey(secret, salt, 1,
      cfg = initBlake3GimliKdfConfig(keyBytes = outLen))
  of kdfCustom:
    result = deriveCustomKdf(secret, ckaBlake3, passCount, memoryKiB * 1024,
      1, 64)[0 ..< outLen]
