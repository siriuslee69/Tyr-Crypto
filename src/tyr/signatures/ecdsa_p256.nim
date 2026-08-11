## ---------------------------------------------
## | ECDSA P-256 <- public surface
## ---------------------------------------------
##
## Elliptic-curve signatures on the NIST P-256 curve. Classical, not post-quantum.
##
## The full implementation lives in `./ecdsa_p256/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./ecdsa_p256/ecdsa_p256

export ecdsa_p256
