## ---------------------------------------------------------------------
## | KDF Dynamic <- pick the derivation family from a VALUE at runtime  |
## ---------------------------------------------------------------------
##
## `deriveKeyOf` takes the family as data, so a stored profile can name it.
## ⚠ Check `isPasswordSafe(f)` before deriving from anything a human typed;
## a config that names a fast KDF for a password is a real risk.

import ./types
import ./argon2
import ./blake3_gimli_kdf
import ./kdf

export types

proc deriveKeyOf*(f: KdfFamily, secret, salt: openArray[byte],
    outLen: int = 32, passCount: int = 3, memoryKiB: int = 65536,
    laneCount: int = 1): seq[byte] =
  ## f/secret/salt/outLen: family read at runtime, input secret, salt, length.
  ## passCount/memoryKiB/laneCount: cost knobs, used by the Argon2 families.
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
