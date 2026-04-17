## ----------------------------------------------------
## Poly1305 <- compatibility facade to poly1305 folder
## ----------------------------------------------------

import ./poly1305/poly1305

export poly1305

proc poly1305TyrMac*(key, msg: openArray[byte]): Poly1305Tag =
  ## Tyr-suffixed alias for the local Poly1305 MAC.
  result = poly1305Mac(key, msg)

proc poly1305TyrTag*(key, msg: openArray[byte]): seq[byte] =
  ## Tyr-suffixed alias for the local Poly1305 detached tag helper.
  result = poly1305Tag(key, msg)

proc poly1305TyrVerify*(key, msg, tag: openArray[byte]): bool =
  ## Tyr-suffixed alias for the local Poly1305 verifier.
  result = poly1305Verify(key, msg, tag)
