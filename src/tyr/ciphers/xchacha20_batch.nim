## -------------------------------------------------
## | XChaCha20 Batch <- public surface
## -------------------------------------------------
##
## Several independent XChaCha20 streams processed together.
##
## The full implementation lives in `./chacha/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./chacha/xchacha20_batch

export xchacha20_batch
