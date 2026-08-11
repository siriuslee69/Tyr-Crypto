## ------------------------------------------
## | Poly1305 <- public surface
## ------------------------------------------
##
## ONE-TIME authenticator. Its key must never cover two messages - see ../types.nim.
##
##   poly1305Tag(key, msg)              raw. YOU supply a one-time key.
##   poly1305xcTag(master, nonce, msg)  derives one per message. Standard.
##   poly1305b3Tag / poly1305giTag      same, deriving with BLAKE3 / Gimli
##
## Prefer the deriving forms unless you are already producing a fresh key
## per message yourself. `./poly1305/derive` explains the choice.
##
## The full implementation lives in `./poly1305/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./poly1305/poly1305
import ./poly1305/derive

export poly1305
export derive

## ╭⟢ Public names
##
## ⚠ All three take the key straight to Poly1305, so it must be one-time.
## For a long-lived key use `poly1305DerivedTag` above.

proc poly1305TyrMac*(key, msg: openArray[byte]): Poly1305Tag {.inline.} =
  ## Public name for the local Poly1305 MAC. ⚠ One-time key.
  result = poly1305Mac(key, msg)

proc poly1305TyrTag*(key, msg: openArray[byte]): seq[byte] {.inline.} =
  ## Public name for the local Poly1305 detached tag. ⚠ One-time key.
  result = poly1305Tag(key, msg)

proc poly1305TyrVerify*(key, msg, tag: openArray[byte]): bool {.inline.} =
  ## Public name for the local Poly1305 verifier. ⚠ One-time key.
  result = poly1305Verify(key, msg, tag)
