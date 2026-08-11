## ---------------------------------------------------------------------
## | MAC Dynamic <- pick the authenticator from a VALUE while running   |
## ---------------------------------------------------------------------
##
## `macOf` takes the family as data, so the choice can come from a config
## file or a message header. The `Of` suffix lets this tier be imported
## alongside `tyr/macs` without clashing.

import ./types
import ./hmac
import ./poly1305

export types

proc macOf*(f: MacFamily, key, msg: openArray[byte], outLen: int = 32): seq[byte] =
  ## f/key/msg/outLen: family read at runtime, key, message, tag length.
  ## ⚠ `mfPoly1305` needs a fresh key per message - see `isOneTime`.
  case f
  of mfBlake3Keyed: result = blake3CustomHmac(key, msg, outLen)
  of mfGimli:       result = gimliCustomHmac(key, msg, outLen)
  of mfPoly1305:    result = poly1305Tag(key, msg)
  of mfHmacSha3:    result = sha3CustomHmac(key, msg, outLen)

proc macVerifyOf*(expected, actual: openArray[byte]): bool =
  ## expected/actual: computed tag and received tag, compared in constant time.
  result = hmacVerify(expected, actual)
