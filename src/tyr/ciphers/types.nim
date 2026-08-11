## ---------------------------------------------------------------------
## | Cipher Types <- naming the stream ciphers and their key/nonce sizes |
## ---------------------------------------------------------------------
##
## All four ciphers here are STREAM ciphers. The algorithm turns the key
## and nonce into a long ribbon of pseudo-random bytes, then combines that
## ribbon with your data using `xor`:
##
##   plaintext  xor  ribbon  =  ciphertext
##   ciphertext xor  ribbon  =  plaintext
##
## `xor` undoes itself, so ONE routine both encrypts and decrypts.
##
##   cipher          key bytes   nonce bytes   note
##   -------------   ---------   -----------   -------------------------
##   cfXChaCha20        32           24        long nonce, safe to pick
##                                             at random
##   cfChaCha20         32           12        short nonce - must never
##                                             repeat under one key
##   cfAesCtr           32           16        counter block
##   cfGimliStream      32           24        Tyr's Gimli sponge
##
## ⚠ Never reuse a nonce with the same key. Two messages sharing one
## key+nonce pair share the same ribbon, and xoring the two ciphertexts
## together cancels it out, exposing the xor of your two plaintexts. With
## 24 bytes, random nonces are fine. With 12 (cfChaCha20), keep a counter.
##
## ⚠ These provide secrecy only, NOT tamper detection. An attacker who
## cannot read the message can still flip bits in it and you will not
## notice. Pair one with a MAC, or use `tyr/aeads`, which does both.

type
  CipherFamily* = enum
    cfXChaCha20,
    cfChaCha20,
    cfAesCtr,
    cfGimliStream

proc keyBytes*(f: CipherFamily): int =
  ## f: which cipher. All four take a 32-byte key.
  result = 32

proc nonceBytes*(f: CipherFamily): int =
  ## f: which cipher. How many nonce bytes it expects.
  case f
  of cfXChaCha20:   result = 24
  of cfChaCha20:    result = 12
  of cfAesCtr:      result = 16
  of cfGimliStream: result = 24

proc familyName*(f: CipherFamily): string =
  ## f: which cipher. Short stable text name for configs and logs.
  case f
  of cfXChaCha20:   result = "xchacha20"
  of cfChaCha20:    result = "chacha20"
  of cfAesCtr:      result = "aes-ctr"
  of cfGimliStream: result = "gimli-stream"

proc parseCipherFamily*(s: string): CipherFamily =
  ## s: a name produced by `familyName`. Raises on anything unknown.
  case s
  of "xchacha20":    result = cfXChaCha20
  of "chacha20":     result = cfChaCha20
  of "aes-ctr":      result = cfAesCtr
  of "gimli-stream": result = cfGimliStream
  else: raise newException(ValueError, "unknown cipher family: " & s)
