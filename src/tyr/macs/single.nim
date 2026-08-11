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

proc macSingle*(f: static MacFamily, key, msg: openArray[byte],
    outLen: int = 32): seq[byte] =
  ## f/key/msg/outLen: family as a COMPILE-TIME value, secret key,
  ## message, and wanted tag length.
  ##
  ## ⚠ For `mfPoly1305` the key must be fresh for this one message, and
  ## the tag is always 16 bytes whatever `outLen` says. See `types.nim`.
  when f == mfBlake3Keyed:
    when not declared(blake3CustomHmac):
      {.error: "BLAKE3-keyed is not in this build; use -d:tyrMac=hmac or omit the flag".}
    else:
      result = blake3CustomHmac(key, msg, outLen)
  elif f == mfGimli:
    when not declared(gimliCustomHmac):
      {.error: "Gimli MAC is not in this build; use -d:tyrMac=hmac or omit the flag".}
    else:
      result = gimliCustomHmac(key, msg, outLen)
  elif f == mfPoly1305:
    when not declared(poly1305Tag):
      {.error: "Poly1305 is not in this build; use -d:tyrMac=poly1305 or omit the flag".}
    else:
      result = poly1305Tag(key, msg)
  elif f == mfHmacSha3:
    when not declared(sha3CustomHmac):
      {.error: "HMAC-SHA3 is not in this build; use -d:tyrMac=hmac or omit the flag".}
    else:
      result = sha3CustomHmac(key, msg, outLen)
