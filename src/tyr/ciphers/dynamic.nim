## ---------------------------------------------------------------------
## | Cipher Dynamic <- pick the stream cipher from a VALUE while running |
## | CipherFamily value -> case -> that cipher's xor routine             |
## ---------------------------------------------------------------------
##
## Use this when the cipher is named by data rather than by source code -
## a config entry, or a byte in a message header:
##
##   var c: CipherFamily = parseCipherFamily(readConfigValue())
##   var out: seq[byte] = encryptOf(c, key, nonce, message)
##
## Names end in `Of` so this tier can be imported next to `tyr/ciphers`.
## Sizes, the nonce-reuse warning and the "no tamper detection" warning all
## live in `types.nim`; read them before choosing.

import tyrPragmas

import ./types
import ./aes_ctr
import ./chacha20
import ./xchacha20
import ./gimli_sponge

export types

proc checkCipherInput(f: CipherFamily, k, n: openArray[byte]) {.role: {parser}.} =
  ## f/k/n: chosen cipher, key, nonce.
  ## Reject a wrong-sized key or nonce before any cipher code runs, naming
  ## which one was wrong and what was expected.
  var
    wantKey: int = keyBytes(f)
    wantNonce: int = nonceBytes(f)
  if k.len != wantKey:
    raise newException(ValueError, familyName(f) & " needs a " & $wantKey &
      "-byte key, got " & $k.len)
  if n.len != wantNonce:
    raise newException(ValueError, familyName(f) & " needs a " & $wantNonce &
      "-byte nonce, got " & $n.len)

proc cipherXorOf*(f: CipherFamily, k, n, data: openArray[byte]): seq[byte]
    {.role: {encryptor}.} =
  ## f/k/n/data: chosen cipher, key, nonce, and the bytes to transform.
  ## Combines `data` with the keystream. Encrypts plaintext and decrypts
  ## ciphertext, because xor undoes itself.
  checkCipherInput(f, k, n)
  case f
  of cfXChaCha20:   result = xchacha20Xor(k, n, data)
  of cfChaCha20:    result = chacha20Xor(k, n, data)
  of cfAesCtr:      result = aesCtrXor(k, n, data)
  of cfGimliStream: result = gimliStreamXor(k, n, data)

proc encryptOf*(f: CipherFamily, k, n, plain: openArray[byte]): seq[byte]
    {.role: {encryptor}, inline.} =
  ## f/k/n/plain: chosen cipher, key, nonce, readable bytes.
  result = cipherXorOf(f, k, n, plain)

proc decryptOf*(f: CipherFamily, k, n, cipherText: openArray[byte]): seq[byte]
    {.role: {decryptor}, inline.} =
  ## f/k/n/cipherText: chosen cipher, key, nonce, scrambled bytes.
  result = cipherXorOf(f, k, n, cipherText)
