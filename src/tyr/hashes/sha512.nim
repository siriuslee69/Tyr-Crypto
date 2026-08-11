## -----------------------------------------
## | SHA-512 <- public surface
## -----------------------------------------
##
## 64-byte hash from the SHA-2 family.
##
## The full implementation lives in `./sha512/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./sha512/sha512

export sha512
