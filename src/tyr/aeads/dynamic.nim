## ---------------------------------------------------------------------
## | AEAD Dynamic <- one-shot sealing, suite named by a VALUE            |
## ---------------------------------------------------------------------
##
## Use this when the suite is named by data rather than by source code -
## a config entry, or a field in a message header:
##
##   var s: CipherSuite = parseCipherSuite(readConfigValue())
##   var c = sealOf(s, keys, nonce, message)
##
## The default tier (`tyr/aeads`) already takes the suite as a runtime
## value, so this tier is not about dispatch - it is about not having to
## build and hold an `AeadState` for a single message. Each call makes its
## own state, uses it once and drops it.
##
## Names end in `Of` so this can be imported next to `tyr/aeads`.
##
## ⚠ Because each call builds a fresh state, the nonce-reuse guard that
## `AeadState` provides cannot help you here: two `sealOf` calls with the
## same nonce will both succeed. When you are sealing more than one
## message, prefer the default tier, where the state catches it.

import tyrPragmas

import ./types
import ../aeads

export types

proc sealOf*(a: CipherSuite, keys: seq[seq[uint8]], nonce: seq[uint8],
    plain: openArray[uint8], tagBytes: uint16 = 0'u16,
    cipherSource: SubkeySource = sksHChaCha20,
    macSource: Poly1305KeySource = pksXChaCha20): AeadCiphertext
    {.role: {actor}.} =
  ## a/keys/nonce/plain: suite named at runtime, one 32-byte key per
  ## layer, a nonce never used before with these keys, and the bytes.
  ## tagBytes: wanted tag length, or 0 for the suite's safe default.
  ## cipherSource/macSource: which algorithm derives XChaCha20's subkey
  ## and Poly1305's one-time key, defaulting to the standard route.
  ##
  ## These two travel with the suite for a reason: a caller who reads the
  ## suite out of a header or a config entry reads the sources from the
  ## same place. Leaving them off here would have made this tier the one
  ## place in the library where the choice cannot be expressed.
  result = seal(plain, initAeadState(a, keys, nonce, tagBytes, cipherSource,
    macSource))

proc openOf*(a: CipherSuite, keys: seq[seq[uint8]], nonce: seq[uint8],
    c: AeadCiphertext, tagBytes: uint16 = 0'u16,
    cipherSource: SubkeySource = sksHChaCha20,
    macSource: Poly1305KeySource = pksXChaCha20): seq[uint8]
    {.role: {actor}.} =
  ## a/keys/nonce/c: the same suite, keys and nonce that sealed it, and
  ## the sealed message. Raises if the tag does not match.
  ## cipherSource/macSource: must be the pair that sealed it. Both are
  ## bound into the tag, so a wrong one raises rather than decrypting to
  ## garbage.
  result = open(c, initAeadState(a, keys, nonce, tagBytes, cipherSource,
    macSource))
