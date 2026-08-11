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
## Each module keeps the public names for its own algorithms: hash names
## live in `tyr/hashes`, tag names in `tyr/macs`, password names in
## `tyr/kdfs`. Only the cipher names are below.

import ./ciphers/types
import ./ciphers/aes_ctr
import ./ciphers/chacha20
import ./ciphers/xchacha20
import ./ciphers/gimli_sponge
import ./ciphers/material

export types
export aes_ctr, chacha20, xchacha20, gimli_sponge
export material

## ╭⟢ AES-CTR

proc aesCtrTyrXor*(k, n, ps: openArray[uint8],
    b: AesCtrBackend = acbAuto): seq[uint8] {.inline.} =
  ## Public name for the local AES-CTR xor helper.
  result = aesCtrXor(k, n, ps, b)

proc initAesCtrTyrState*(k, n: openArray[uint8]): AesCtrState {.inline.} =
  ## Public name for the local AES-CTR state initializer.
  result = initAesCtrState(k, n)

## ╭⟢ ChaCha20 / XChaCha20

proc chacha20TyrXor*(key, nonce: openArray[byte],
    input: openArray[byte]): seq[byte] {.inline.} =
  ## Public name for the local ChaCha20 xor helper.
  result = chacha20Xor(key, nonce, input)

proc chacha20TyrStream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] {.inline.} =
  ## Public name for the local ChaCha20 keystream helper.
  result = chacha20Stream(key, nonce, length, initialCounter)

proc hchacha20Tyr*(key, nonce: openArray[byte]): array[32, byte] {.inline.} =
  ## Public name for the local HChaCha20 core.
  result = hchacha20(key, nonce)

proc xchacha20TyrXor*(key, nonce: openArray[byte],
    input: openArray[byte]): seq[byte] {.inline.} =
  ## Public name for the local XChaCha20 xor helper.
  result = xchacha20Xor(key, nonce, input)

proc xchacha20TyrStream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] {.inline.} =
  ## Public name for the local XChaCha20 keystream helper.
  result = xchacha20Stream(key, nonce, length, initialCounter)

## ╭⟢ Gimli sponge
##
## One permutation serving three jobs. The XOF and tag helpers live here
## rather than in `tyr/hashes` and `tyr/macs` because all three are the
## same sponge with different padding, and splitting them would scatter
## one implementation across three modules.

proc gimliTyrXof*(ks, ns, ms: openArray[uint8],
    outLen: int): seq[uint8] {.inline.} =
  ## Public name for the local Gimli XOF.
  result = gimliXof(ks, ns, ms, outLen)

proc gimliTyrTag*(ks, ns, ms: openArray[uint8],
    outLen: int): seq[uint8] {.inline.} =
  ## Public name for the local Gimli tag helper.
  result = gimliTag(ks, ns, ms, outLen)

proc gimliTyrStreamXor*(ks, ns, input: openArray[uint8]): seq[uint8] {.inline.} =
  ## Public name for the local Gimli stream-xor helper.
  result = gimliStreamXor(ks, ns, input)

## ╭⟢ Pick the cipher by its family value

proc encrypt*(f: CipherFamily, k, n, plain: openArray[byte]): seq[byte] =
  ## f/k/n/plain: cipher family, key, nonce, readable bytes.
  ## ⚠ The nonce must never repeat under one key - see `ciphers/types.nim`.
  case f
  of cfXChaCha20:   result = xchacha20Xor(k, n, plain)
  of cfChaCha20:    result = chacha20Xor(k, n, plain)
  of cfAesCtr:      result = aesCtrXor(k, n, plain)
  of cfGimliStream: result = gimliStreamXor(k, n, plain)

proc decrypt*(f: CipherFamily, k, n, cipherText: openArray[byte]): seq[byte] =
  ## f/k/n/cipherText: cipher family, key, nonce, scrambled bytes.
  ## Same work as `encrypt`; these ciphers undo themselves.
  result = encrypt(f, k, n, cipherText)
