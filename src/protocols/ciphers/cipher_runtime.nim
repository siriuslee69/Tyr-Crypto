## ---------------------------------------------------------------------
## | Cipher Runtime <- pick the stream cipher while the program runs    |
## | TyrCipher value -> case -> the matching xor routine -> ciphertext  |
## ---------------------------------------------------------------------
##
## What this file is for
## ---------------------
## Tyr ships four stream ciphers. Sometimes the choice is only known while
## the program is running, for example because it arrived in a config file
## or in a message header. This file holds that choice as a plain value and
## a `case` that turns it into a real call.
##
##   TyrCipher value   ->   case   ->   the algorithm's own xor routine
##   tcXChaCha20       ->   ...    ->   xchacha20Xor(...)
##
## All four are "stream" ciphers. That word means the algorithm turns the
## key and nonce into a long ribbon of pseudo-random bytes, then combines
## that ribbon with the message one byte at a time using `xor`. `xor` is its
## own undo, so the SAME call both encrypts and decrypts:
##
##   plaintext  xor  ribbon  =  ciphertext
##   ciphertext xor  ribbon  =  plaintext
##
## That is why `tyrCipherEncrypt` and `tyrCipherDecrypt` below are the same
## routine under two names. The names exist only so calling code reads
## clearly; nothing differs between them.
##
## Sizes each cipher demands
## -------------------------
##
##   cipher          key bytes   nonce bytes   note
##   -------------   ---------   -----------   ------------------------
##   tcXChaCha20        32           24        long nonce, safe to pick
##                                             at random
##   tcChaCha20         32           12        short nonce, must never
##                                             repeat under one key
##   tcAesCtr           32           16        counter block
##   tcGimliStream      32           24        Tyr's Gimli sponge
##
## ⚠ A nonce must never be reused with the same key. Reusing one lets an
## observer recover the xor of two messages. With a 12-byte nonce
## (tcChaCha20) prefer a counter you keep; with 24 bytes, random is fine.
##
## This module is compiled only in the default build, where every cipher is
## present. A single-cipher build (see `../ciphers.nim`) skips it, because a
## runtime choice makes no sense when only one option was compiled in.

import metaPragmas

import ../custom_crypto/symmetric/aes/aes_ctr
import ../custom_crypto/symmetric/chacha/chacha20
import ../custom_crypto/symmetric/chacha/xchacha20
import ../custom_crypto/symmetric/gimli/gimli_sponge

export aes_ctr
export chacha20
export xchacha20
export gimli_sponge

type
  TyrCipher* = enum
    tcXChaCha20,
    tcChaCha20,
    tcAesCtr,
    tcGimliStream

const
  tyrCipherKeyBytes = 32

proc keyBytes*(c: TyrCipher): int {.role: {parser}.} =
  ## c: the chosen cipher.
  ## How many key bytes the cipher expects. All four take 32.
  result = tyrCipherKeyBytes

proc nonceBytes*(c: TyrCipher): int {.role: {parser}.} =
  ## c: the chosen cipher.
  ## How many nonce bytes the cipher expects.
  case c
  of tcXChaCha20:
    result = xchacha20NonceSize
  of tcChaCha20:
    result = 12
  of tcAesCtr:
    result = aesCtrNonceLen
  of tcGimliStream:
    result = gimliNonceBytes

proc cipherName*(c: TyrCipher): string {.role: {parser}.} =
  ## c: the chosen cipher.
  ## Short, stable text name. Safe to write into a config or a log line.
  case c
  of tcXChaCha20:
    result = "xchacha20"
  of tcChaCha20:
    result = "chacha20"
  of tcAesCtr:
    result = "aes-ctr"
  of tcGimliStream:
    result = "gimli-stream"

proc parseTyrCipher*(s: string): TyrCipher {.role: {parser}.} =
  ## s: a name produced by `cipherName`.
  ## Turn stored text back into a cipher choice. Raises on anything else,
  ## so an unknown or damaged config never silently falls back to a
  ## different algorithm than the one that was written down.
  case s
  of "xchacha20":
    result = tcXChaCha20
  of "chacha20":
    result = tcChaCha20
  of "aes-ctr":
    result = tcAesCtr
  of "gimli-stream":
    result = tcGimliStream
  else:
    raise newException(ValueError, "unknown cipher name: " & s)

proc checkCipherInput(c: TyrCipher, k, n: openArray[byte]) {.role: {parser}.} =
  ## c/k/n: chosen cipher, key, nonce.
  ## Reject a wrong-sized key or nonce before any cipher code runs, and say
  ## which one was wrong and what was expected.
  var
    wantKey: int = keyBytes(c)
    wantNonce: int = nonceBytes(c)
  if k.len != wantKey:
    raise newException(ValueError, cipherName(c) & " needs a " & $wantKey &
      "-byte key, got " & $k.len)
  if n.len != wantNonce:
    raise newException(ValueError, cipherName(c) & " needs a " & $wantNonce &
      "-byte nonce, got " & $n.len)

proc tyrCipherXor*(c: TyrCipher, k, n, data: openArray[byte]): seq[byte]
    {.role: {encryptor}.} =
  ## c/k/n/data: chosen cipher, key, nonce, and the bytes to transform.
  ## Combine `data` with the cipher's keystream. Encrypts plaintext and
  ## decrypts ciphertext, because xor undoes itself.
  checkCipherInput(c, k, n)
  case c
  of tcXChaCha20:
    result = xchacha20Xor(k, n, data)
  of tcChaCha20:
    result = chacha20Xor(k, n, data)
  of tcAesCtr:
    result = aesCtrXor(k, n, data)
  of tcGimliStream:
    result = gimliStreamXor(k, n, data)

proc tyrCipherEncrypt*(c: TyrCipher, k, n, plain: openArray[byte]): seq[byte]
    {.role: {encryptor}, inline.} =
  ## c/k/n/plain: chosen cipher, key, nonce, and the readable bytes.
  ## Reads as "encrypt". Same work as `tyrCipherXor`.
  result = tyrCipherXor(c, k, n, plain)

proc tyrCipherDecrypt*(c: TyrCipher, k, n, cipherText: openArray[byte]): seq[byte]
    {.role: {decryptor}, inline.} =
  ## c/k/n/cipherText: chosen cipher, key, nonce, and the scrambled bytes.
  ## Reads as "decrypt". Same work as `tyrCipherXor`.
  result = tyrCipherXor(c, k, n, cipherText)
