## -----------------------------------------
## | SHA-256 <- public surface
## -----------------------------------------
##
## 32-byte hash from the SHA-2 family. Used by TLS and X.509.
##
## The full implementation lives in `./sha256/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./sha256/sha256

export sha256
