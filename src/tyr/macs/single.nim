## ---------------------------------------------------------------------
## | MAC Single <- import ONE family, or all, from one flag
## | no flag -> everything    -d:tyrMac=<name> -> that one alone
## ---------------------------------------------------------------------
##
##     import tyr/macs/single        # works with no flag at all
##
## Add one flag for a small build; your source does not change:
##
##     nim c -d:tyrMac=<name> myfirmware.nim
##
## Nim resolves every import before any of your code exists, so what
## enters the build is a build-time decision by nature. This keeps that
## decision down to one flag, and makes the no-flag case work.

import ./types
export types

const tyrMac* {.strdefine.}: string = ""
  ## Which single family to compile. Empty (the default) means all.

when tyrMac == "":
  import ./poly1305
  import ./hmac
  export poly1305, hmac
elif tyrMac == "poly1305":
  import ./poly1305
  export poly1305
elif tyrMac == "hmac":
  import ./hmac
  export hmac
else:
  {.error: "unknown -d:tyrMac=" & tyrMac &
    " (expected: poly1305, hmac, or omit the flag for all)".}
