## ------------------------------------------
## | ChaCha20 <- public surface
## ------------------------------------------
##
## Stream cipher with a 12-byte nonce. The nonce must never repeat under one key.
##
## The full implementation lives in `./chacha/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./chacha/chacha20

export chacha20
