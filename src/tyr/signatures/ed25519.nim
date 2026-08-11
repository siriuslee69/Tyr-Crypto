## -----------------------------------------
## | Ed25519 <- public surface
## -----------------------------------------
##
## Edwards-curve signatures. Classical, not post-quantum, and fast.
##
## The full implementation lives in `./ed25519/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./ed25519/ed25519_impl

export ed25519_impl
