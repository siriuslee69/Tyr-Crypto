## ---------------------------------------------------------------------
## | Ciphers <- default tier: name the cipher by its family value       |
## ---------------------------------------------------------------------
##
##   import tyr/ciphers            <- THIS FILE. encrypt(cfXChaCha20, ...)
##   import tyr/ciphers/chacha20   <- one family: chacha20Xor(k, n, msg)
##   import tyr/ciphers/dynamic    <- pick from a stored value at runtime
##   import tyr/ciphers/single     <- one family by build flag, for devices
##   import tyr/ciphers/material   <- typed key+nonce material surface
##
## Stream ciphers have no per-family variant type to overload on, so the
## family is named by its enum value rather than inferred from a type.
##
## Two names for each algorithm
## ----------------------------
## Every algorithm here answers to two names.
##
##   chacha20Xor      <- the internal name. What the implementation calls
##                       itself, used by the rest of Tyr.
##   chacha20TyrXor   <- the public name. What other repos call.
##
## The "Tyr" in the middle means "this repo's own version of it". Tyr can
## expose its own ChaCha20 and a library-backed one at the same time, so a
## caller needs a way to say which it wants. The same split exists one
## level down in the algorithm enums, where `akKyber0Send` is the library
## route and `akKyber0TyrSend` is Tyr's.
##
## Each ALGORITHM SURFACE keeps its own public names, so a single-algorithm
## import reaches them too: `tyr/ciphers/chacha20` gives `chacha20TyrXor`,
## `tyr/hashes/blake3` gives `blake3TyrHash`. They are re-exported here.

import tyrPragmas
import ./ciphers/types
import ./ciphers/aes_ctr
import ./ciphers/chacha20
import ./ciphers/xchacha20
import ./ciphers/gimli_sponge
import ./ciphers/material

export types
export aes_ctr, chacha20, xchacha20, gimli_sponge
export material

## ╭⟢ Pick the cipher by its family value

proc encrypt*(f: CipherFamily, k, n, plain: openArray[byte]): seq[byte]
    {.role: {encryptor}.} =
  ## f/k/n/plain: cipher family, key, nonce, readable bytes.
  ## ⚠ The nonce must never repeat under one key - see `ciphers/types.nim`.
  case f
  of cfXChaCha20:   result = xchacha20Xor(k, n, plain)
  of cfChaCha20:    result = chacha20Xor(k, n, plain)
  of cfAesCtr:      result = aesCtrXor(k, n, plain)
  of cfGimliStream: result = gimliStreamXor(k, n, plain)

proc decrypt*(f: CipherFamily, k, n, cipherText: openArray[byte]): seq[byte]
    {.role: {decryptor}.} =
  ## f/k/n/cipherText: cipher family, key, nonce, scrambled bytes.
  ## Same work as `encrypt`; these ciphers undo themselves.
  result = encrypt(f, k, n, cipherText)
