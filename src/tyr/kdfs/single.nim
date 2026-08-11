## ---------------------------------------------------------------------
## | KDF Single <- compile exactly ONE derivation family, by build flag |
## ---------------------------------------------------------------------
##
##   -d:tyrKdfArgon2        ->  argon2idHash(...)   slow, for passwords
##   -d:tyrKdfBlake3Gimli   ->  deriveBlake3GimliStageKey(...)   fast
##   -d:tyrKdfCustom        ->  deriveCustomKdf(...)             fast
##
## ⚠ On a device that checks a human PIN or password, pick tyrKdfArgon2.
## The fast families are for material that is already a strong secret.

import ./types
export types

when defined(tyrKdfArgon2):
  when defined(tyrKdfBlake3Gimli) or defined(tyrKdfCustom):
    {.error: "pick only one -d:tyrKdf... flag".}
  import ./argon2
  export argon2
elif defined(tyrKdfBlake3Gimli):
  when defined(tyrKdfCustom):
    {.error: "pick only one -d:tyrKdf... flag".}
  import ./blake3_gimli_kdf
  export blake3_gimli_kdf
elif defined(tyrKdfCustom):
  import ./kdf
  export kdf
else:
  {.error: "tyr/kdfs/single needs one -d:tyrKdf... flag " &
    "(tyrKdfArgon2, tyrKdfBlake3Gimli, tyrKdfCustom). " &
    "For every family at once use `import tyr/kdfs` instead.".}
