## ---------------------------------------------------------------------
## | Cipher Single <- import ONE family, or all, from one flag
## | no flag -> everything    -d:tyrCipher=<name> -> that one alone
## ---------------------------------------------------------------------
##
##     import tyr/ciphers/single        # works with no flag at all
##
## Add one flag for a small build; your source does not change:
##
##     nim c -d:tyrCipher=<name> myfirmware.nim
##
## Nim resolves every import before any of your code exists, so what
## enters the build is a build-time decision by nature. This keeps that
## decision down to one flag, and makes the no-flag case work.

import ./types
export types

const tyrCipher* {.strdefine.}: string = ""
  ## Which single family to compile. Empty (the default) means all.

when tyrCipher == "":
  import ./chacha20
  import ./xchacha20
  import ./aes_ctr
  import ./gimli_sponge
  export chacha20, xchacha20, aes_ctr, gimli_sponge
elif tyrCipher == "chacha20":
  import ./chacha20
  export chacha20
elif tyrCipher == "xchacha20":
  import ./xchacha20
  export xchacha20
elif tyrCipher == "aesctr":
  import ./aes_ctr
  export aes_ctr
elif tyrCipher == "gimli":
  import ./gimli_sponge
  export gimli_sponge
else:
  {.error: "unknown -d:tyrCipher=" & tyrCipher &
    " (expected: chacha20, xchacha20, aesctr, gimli, or omit the flag for all)".}
