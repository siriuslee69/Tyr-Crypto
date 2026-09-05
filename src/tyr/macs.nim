## ---------------------------------------------------------------------
## | MACs <- default tier: one `mac` name for every authenticator       |
## ---------------------------------------------------------------------
##
##   import tyr/macs            <- THIS FILE. mac(mfBlake3Keyed, key, msg)
##   import tyr/macs/poly1305   <- one family: poly1305Tag(key, msg)
##   import tyr/macs/dynamic    <- pick from a stored value at runtime
##   import tyr/macs/single     <- one family by build flag, for devices
##
## Always compare tags with `macVerify`, never with `==`. A plain compare
## stops at the first differing byte, and the time it took leaks how much
## of the tag an attacker has guessed correctly.

import metaPragmas
import ./macs/types
import ./macs/hmac
import ./macs/poly1305
import ./macs/material

export types
export hmac, poly1305
export material

proc mac*(f: MacFamily, key, msg: openArray[byte], outLen: int = 32): seq[byte]
    {.role: {actor}.} =
  ## f/key/msg/outLen: family, secret key, message, wanted tag length.
  ## ⚠ For `mfPoly1305` the key must be fresh for this one message; see
  ## `isOneTime`. Poly1305 always returns 16 bytes and ignores `outLen`.
  case f
  of mfBlake3Keyed: result = blake3CustomHmac(key, msg, outLen)
  of mfGimli:       result = gimliCustomHmac(key, msg, outLen)
  of mfPoly1305:    result = poly1305Tag(key, msg)
  of mfHmacSha3:    result = sha3CustomHmac(key, msg, outLen)

proc macVerify*(expected, actual: openArray[byte]): bool {.role: {actor}.} =
  ## expected/actual: the tag you computed, and the tag that arrived.
  ## Constant-time compare: the answer takes the same time whether the tags
  ## differ in the first byte or the last, so nothing leaks.
  result = hmacVerify(expected, actual)
