## ------------------------------------------
## | Poly1305 <- public surface
## ------------------------------------------
##
## ONE-TIME authenticator. Its key must never cover two messages - see ../types.nim.
##
## The full implementation lives in `./poly1305/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./poly1305/poly1305

export poly1305
