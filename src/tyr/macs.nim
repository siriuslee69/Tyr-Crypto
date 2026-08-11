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

import ./macs/types
import ./macs/hmac
import ./macs/poly1305
import ./macs/material

export types
export hmac, poly1305
export material

proc mac*(f: MacFamily, key, msg: openArray[byte], outLen: int = 32): seq[byte] =
  ## f/key/msg/outLen: family, secret key, message, wanted tag length.
  ## ⚠ For `mfPoly1305` the key must be fresh for this one message; see
  ## `isOneTime`. Poly1305 always returns 16 bytes and ignores `outLen`.
  case f
  of mfBlake3Keyed: result = blake3CustomHmac(key, msg, outLen)
  of mfGimli:       result = gimliCustomHmac(key, msg, outLen)
  of mfPoly1305:    result = poly1305Tag(key, msg)
  of mfHmacSha3:    result = sha3CustomHmac(key, msg, outLen)

proc macVerify*(expected, actual: openArray[byte]): bool =
  ## expected/actual: the tag you computed, and the tag that arrived.
  ## Constant-time compare: the answer takes the same time whether the tags
  ## differ in the first byte or the last, so nothing leaks.
  result = hmacVerify(expected, actual)

## ╭⟢ Public names
##
## `poly1305Tag` is the internal name used by the rest of Tyr.
## `poly1305TyrTag` is the same code under the name other repos call,
## chosen so it cannot collide with a library-backed Poly1305.
##
## ⚠ Every one of these needs a key that has never authenticated another
## message. Poly1305 is a one-time authenticator: reuse a key across two
## messages and an attacker recovers it and can forge freely.

proc poly1305TyrMac*(key, msg: openArray[byte]): Poly1305Tag {.inline.} =
  ## Public name for the local Poly1305 MAC. ⚠ One-time key.
  result = poly1305Mac(key, msg)

proc poly1305TyrTag*(key, msg: openArray[byte]): seq[byte] {.inline.} =
  ## Public name for the local Poly1305 detached tag helper. ⚠ One-time key.
  result = poly1305Tag(key, msg)

proc poly1305TyrVerify*(key, msg, tag: openArray[byte]): bool {.inline.} =
  ## Public name for the local Poly1305 verifier. ⚠ One-time key.
  result = poly1305Verify(key, msg, tag)
