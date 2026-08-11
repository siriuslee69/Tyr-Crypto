## ----------------------------------------
## | Argon2 <- public surface
## ----------------------------------------
##
## Deliberately slow, memory-hard derivation. The right choice for human passwords.
##
## The full implementation lives in `./argon2/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./argon2/argon2

export argon2
