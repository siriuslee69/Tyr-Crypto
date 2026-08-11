## --------------------------------------
## | MACs <- public surface
## --------------------------------------
##
## Keyed fingerprints over BLAKE3, Gimli and SHA-3. Only the SHA-3 one is true HMAC.
##
## The full implementation lives in `./hmac/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./hmac/hmac

export hmac
