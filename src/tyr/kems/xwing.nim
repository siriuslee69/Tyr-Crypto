## ---------------------------------------------
## | X-Wing <- public surface
## ---------------------------------------------
##
## Hybrid KEM: ML-KEM-768 + X25519, joined by SHA3-256. Both halves must be
## broken to learn the shared secret. draft-connolly-cfrg-xwing-kem-11.
##
## The full implementation lives in `./xwing/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./xwing/operations

export operations
