## -----------------------------------------
## | AES-CTR <- public surface
## -----------------------------------------
##
## AES run in counter mode, turning the block cipher into a stream cipher.
##
## The full implementation lives in `./aes/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./aes/aes_core
import ./aes/aes_ctr

export aes_core
export aes_ctr
