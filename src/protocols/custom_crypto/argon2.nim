## ------------------------------------------------
## Argon2 <- compatibility facade to argon2 folder
## ------------------------------------------------

import ./symmetric/argon2/argon2

export argon2

proc argon2iTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local Argon2i hash.
  result = argon2iHash(password, salt, p, b)

proc argon2iTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local custom Argon2i hash variant.
  result = argon2iHash(password, salt, p, h, b)

proc argon2idTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local Argon2id hash.
  result = argon2idHash(password, salt, p, b)

proc argon2idTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local custom Argon2id hash variant.
  result = argon2idHash(password, salt, p, h, b)

proc argon2iTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local Argon2i hash.
  result = argon2iHash(password, salt, passCount, memoryKiB, laneCount, outLen, b)

proc argon2iTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local custom Argon2i hash variant.
  result = argon2iHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)

proc argon2idTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local Argon2id hash.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, b)

proc argon2idTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## Tyr-suffixed alias for the local custom Argon2id hash variant.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)

proc deriveArgonLikeKey*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## Standalone Tyr-owned custom Argon2id-style key derivation surface.
  result = argon2idHash(password, salt, p, h, b)

proc deriveArgonLikeKey*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## Standalone Tyr-owned custom Argon2id-style key derivation surface.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)
