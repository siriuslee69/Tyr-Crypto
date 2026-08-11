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
