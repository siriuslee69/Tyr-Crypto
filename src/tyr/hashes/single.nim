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

proc digestSingle*(f: static HashFamily, data: openArray[byte],
    outLen: int = 0): seq[byte] =
  ## f/data/outLen: family named as a COMPILE-TIME value, the bytes, and
  ## the wanted length. `outLen = 0` means this family's natural length.
  ##
  ## `f` is `static`, so the branch below is chosen while compiling and
  ## the others are discarded. Asking for a family this build excluded is
  ## a compile error naming the flag to change.
  when f == hfBlake3:
    when not declared(blake3Hash):
      {.error: "BLAKE3 is not in this build; use -d:tyrHash=blake3 or omit the flag".}
    else:
      result = blake3Hash(data, if outLen <= 0: 32 else: outLen)
  elif f == hfSha256:
    when not declared(sha256Hash):
      {.error: "SHA-256 is not in this build; use -d:tyrHash=sha256 or omit the flag".}
    else:
      result = @(sha256Hash(data))
  elif f == hfSha512:
    when not declared(sha512Hash):
      {.error: "SHA-512 is not in this build; use -d:tyrHash=sha512 or omit the flag".}
    else:
      result = @(sha512Hash(data))
  elif f == hfSha3:
    when not declared(sha3Hash):
      {.error: "SHA-3 is not in this build; use -d:tyrHash=sha3 or omit the flag".}
    else:
      result = sha3Hash(data, if outLen <= 0: 32 else: outLen)
