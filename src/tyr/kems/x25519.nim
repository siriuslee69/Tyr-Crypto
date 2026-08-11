## ----------------------------------------
## | X25519 <- public surface
## ----------------------------------------
##
## Elliptic-curve key agreement on Curve25519. Classical, not post-quantum.
##
## The full implementation lives in `./x25519/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./x25519/x25519_common
import ./x25519/x25519_impl

export x25519_common
export x25519_impl
