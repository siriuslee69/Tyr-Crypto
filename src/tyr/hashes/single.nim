## ---------------------------------------------------------------------
## | Hash Single <- import ONE family, or all, from one flag
## | no flag -> everything    -d:tyrHash=<name> -> that one alone
## ---------------------------------------------------------------------
##
##     import tyr/hashes/single        # works with no flag at all
##
## Add one flag for a small build; your source does not change:
##
##     nim c -d:tyrHash=<name> myfirmware.nim
##
## Nim resolves every import before any of your code exists, so what
## enters the build is a build-time decision by nature. This keeps that
## decision down to one flag, and makes the no-flag case work.

import ./types
export types

const tyrHash* {.strdefine.}: string = ""
  ## Which single family to compile. Empty (the default) means all.

when tyrHash == "":
  import ./blake3
  import ./sha256
  import ./sha512
  import ./sha3
  export blake3, sha256, sha512, sha3
elif tyrHash == "blake3":
  import ./blake3
  export blake3
elif tyrHash == "sha256":
  import ./sha256
  export sha256
elif tyrHash == "sha512":
  import ./sha512
  export sha512
elif tyrHash == "sha3":
  import ./sha3
  export sha3
else:
  {.error: "unknown -d:tyrHash=" & tyrHash &
    " (expected: blake3, sha256, sha512, sha3, or omit the flag for all)".}
