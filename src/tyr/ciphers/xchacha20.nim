## -------------------------------------------
## | XChaCha20 <- public surface
## -------------------------------------------
##
## ChaCha20 with a 24-byte nonce, long enough to pick at random safely.
##
## The full implementation lives in `./chacha/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./chacha/xchacha20

export xchacha20
