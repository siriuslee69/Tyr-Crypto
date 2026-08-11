## ---------------------------------------------------------------------
## | KDF Single <- import ONE family, or all, from one flag
## | no flag -> everything    -d:tyrKdf=<name> -> that one alone
## ---------------------------------------------------------------------
##
##     import tyr/kdfs/single        # works with no flag at all
##
## Add one flag for a small build; your source does not change:
##
##     nim c -d:tyrKdf=<name> myfirmware.nim
##
## Nim resolves every import before any of your code exists, so what
## enters the build is a build-time decision by nature. This keeps that
## decision down to one flag, and makes the no-flag case work.

import ./types
export types

const tyrKdf* {.strdefine.}: string = ""
  ## Which single family to compile. Empty (the default) means all.

when tyrKdf == "":
  import ./argon2
  import ./blake3_gimli_kdf
  import ./kdf
  export argon2, blake3_gimli_kdf, kdf
elif tyrKdf == "argon2":
  import ./argon2
  export argon2
elif tyrKdf == "blake3gimli":
  import ./blake3_gimli_kdf
  export blake3_gimli_kdf
elif tyrKdf == "custom":
  import ./kdf
  export kdf
else:
  {.error: "unknown -d:tyrKdf=" & tyrKdf &
    " (expected: argon2, blake3gimli, custom, or omit the flag for all)".}

proc deriveKeySingle*(f: static KdfFamily, secret, salt: openArray[byte],
    outLen: int = 32, passCount: int = 3, memoryKiB: int = 65536,
    laneCount: int = 1): seq[byte] =
  ## f: family named as a COMPILE-TIME value.
  ## secret/salt: the input secret or password, and a per-secret salt.
  ## outLen/passCount/memoryKiB/laneCount: length and Argon2 cost knobs.
  ##
  ## ⚠ Feeding a human password to a FAST family is the classic mistake.
  ## `isPasswordSafe` in `types.nim` says which is which.
  when f == kdfArgon2i:
    when not declared(argon2iHash):
      {.error: "Argon2 is not in this build; use -d:tyrKdf=argon2 or omit the flag".}
    else:
      result = argon2iHash(secret, salt, passCount, memoryKiB, laneCount, outLen)
  elif f == kdfArgon2id:
    when not declared(argon2idHash):
      {.error: "Argon2 is not in this build; use -d:tyrKdf=argon2 or omit the flag".}
    else:
      result = argon2idHash(secret, salt, passCount, memoryKiB, laneCount, outLen)
  elif f == kdfBlake3Gimli:
    when not declared(deriveBlake3GimliStageKey):
      {.error: "BLAKE3+Gimli is not in this build; use -d:tyrKdf=blake3gimli or omit the flag".}
    else:
      result = deriveBlake3GimliStageKey(secret, salt, 1,
        cfg = initBlake3GimliKdfConfig(keyBytes = outLen))
  elif f == kdfCustom:
    when not declared(deriveCustomKdf):
      {.error: "the custom KDF is not in this build; use -d:tyrKdf=custom or omit the flag".}
    else:
      result = deriveCustomKdf(secret, ckaBlake3, passCount, memoryKiB * 1024,
        1, 64)[0 ..< outLen]
