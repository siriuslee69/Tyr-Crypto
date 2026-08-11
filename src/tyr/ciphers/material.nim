## ---------------------------------------------------------------------
## | Cipher Material <- typed key+nonce material, sizes in the type     |
## ---------------------------------------------------------------------
##
##   var m = xchacha20cipherM(key: k, nonce: n)
##   var ct = encrypt(message, m)
##   var pt = decrypt(ct, m)
##
## Each type nails the nonce width to what that cipher actually takes -
## 24 bytes for XChaCha20, 12 for ChaCha20, 16 for AES-CTR - so a nonce
## of the wrong size cannot be passed at all.
##
## ⚠ A nonce must never repeat under one key. These are stream ciphers:
## reusing a nonce XORs two messages together and both become readable.
## The `NoncePrefixed` helpers exist so the nonce travels WITH the
## ciphertext and cannot be lost; they do not make reuse safe.
##
## ⚠ None of these detect tampering. Anyone can flip a bit in the
## ciphertext and flip the matching bit in the plaintext. Pair them with
## an authenticator, or use `tyr/aeads`, which does both.

import ../helpers/material
import ../helpers/tiers
import ./aes_ctr
import ./chacha20
import ./xchacha20
import ./gimli_sponge

export material

type
  ## Material for XChaCha20 encryption and decryption.
  xchacha20cipherM* = object
    key*: array[32, byte]
    nonce*: array[24, byte]
  ## Material for ChaCha20 encryption and decryption.
  chacha20cipherM* = object
    key*: array[32, byte]
    nonce*: array[12, byte]
  ## Material for AES-256-CTR encryption and decryption.
  aesCtrcipherM* = object
    key*: array[32, byte]
    nonce*: array[16, byte]
  ## Material for Gimli stream-cipher encryption and decryption.
  gimliStreamCipherM* = object
    key*: array[32, byte]
    nonce*: array[24, byte]

  ## Tyr-suffixed alias for the local XChaCha20 cipher material.
  xchacha20TyrCipherM* = xchacha20cipherM
  ## Tyr-suffixed alias for the local ChaCha20 cipher material.
  chacha20TyrCipherM* = chacha20cipherM
  ## Tyr-suffixed alias for the local AES-CTR cipher material.
  aesCtrTyrCipherM* = aesCtrcipherM
  ## Tyr-suffixed alias for the local Gimli stream-cipher material.
  gimliStreamTyrCipherM* = gimliStreamCipherM

## ╭⟢ Which layout entry each material type names

proc algorithmOf*(T: typedesc[xchacha20cipherM]): AlgorithmKind = akXChaCha20Cipher
proc algorithmOf*(T: typedesc[chacha20cipherM]): AlgorithmKind = akChaCha20Cipher
proc algorithmOf*(T: typedesc[aesCtrcipherM]): AlgorithmKind = akAesCtrCipher
proc algorithmOf*(T: typedesc[gimliStreamCipherM]): AlgorithmKind = akGimliStreamCipher

## ╭⟢ Pick the cipher by its tier value

proc symEnc*(alg: StreamCipherAlgorithm, key, nonce, msg: seq[uint8]): seq[uint8] =
  ## Encrypt or stream-XOR `msg` with the selected primitive cipher.
  case alg
  of scaXChaCha20:
    result = xchacha20Xor(key, nonce, msg)
  of scaAesCtr:
    result = aesCtrXor(key, nonce, msg, acbAuto)
  of scaGimliStream:
    result = gimliStreamXor(key, nonce, msg)
  of scaChaCha20:
    result = chacha20Xor(key, nonce, msg)

proc symDec*(alg: StreamCipherAlgorithm, key, nonce, cipher: seq[uint8]): seq[uint8] =
  ## Decrypt or stream-XOR `cipher` with the selected primitive cipher.
  result = symEnc(alg, key, nonce, cipher)

proc streamNonceLen*(alg: StreamCipherAlgorithm): int =
  ## Return the nonce byte length expected by a primitive stream cipher.
  case alg
  of scaXChaCha20:
    result = 24
  of scaAesCtr:
    result = 16
  of scaGimliStream:
    result = 24
  of scaChaCha20:
    result = 12

proc prependNonce(nonce, cipher: seq[uint8]): seq[uint8] =
  var
    i: int = 0
    offset: int = 0
  result = newSeq[uint8](nonce.len + cipher.len)
  i = 0
  while i < nonce.len:
    result[i] = nonce[i]
    i = i + 1
  offset = nonce.len
  i = 0
  while i < cipher.len:
    result[offset + i] = cipher[i]
    i = i + 1

proc splitNoncePrefix(alg: StreamCipherAlgorithm, payload: seq[uint8],
    nonce, cipher: var seq[uint8]) =
  var
    n: int = 0
    i: int = 0
  n = streamNonceLen(alg)
  if payload.len < n:
    raise newException(ValueError, "ciphertext is shorter than the nonce prefix")
  nonce = newSeq[uint8](n)
  cipher = newSeq[uint8](payload.len - n)
  i = 0
  while i < n:
    nonce[i] = payload[i]
    i = i + 1
  i = 0
  while i < cipher.len:
    cipher[i] = payload[n + i]
    i = i + 1

proc symEncNoncePrefixed*(alg: StreamCipherAlgorithm, key, nonce,
    msg: seq[uint8]): seq[uint8] =
  ## Encrypt or stream-XOR `msg`, returning `nonce || ciphertext`.
  var
    cipher: seq[uint8] = @[]
  if nonce.len != streamNonceLen(alg):
    raise newException(ValueError, "invalid nonce length for nonce-prefixed ciphertext")
  cipher = symEnc(alg, key, nonce, msg)
  result = prependNonce(nonce, cipher)

proc symDecNoncePrefixed*(alg: StreamCipherAlgorithm, key,
    payload: seq[uint8]): seq[uint8] =
  ## Decrypt or stream-XOR a `nonce || ciphertext` payload.
  var
    nonce: seq[uint8] = @[]
    cipher: seq[uint8] = @[]
  splitNoncePrefix(alg, payload, nonce, cipher)
  result = symDec(alg, key, nonce, cipher)

## ╭⟢ Encrypting and decrypting from typed material

proc encrypt*(message: openArray[byte], m: xchacha20cipherM): seq[byte] =
  ## Encrypt or stream-XOR `message` with typed XChaCha20 material.
  result = symEnc(scaXChaCha20, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(message))

proc decrypt*(payload: openArray[byte], m: xchacha20cipherM): seq[byte] =
  ## Decrypt or stream-XOR `payload` with typed XChaCha20 material.
  result = symDec(scaXChaCha20, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(payload))

proc encryptNoncePrefixed*(message: openArray[byte], m: xchacha20cipherM): seq[byte] =
  ## Encrypt typed XChaCha20 material, returning `nonce || ciphertext`.
  result = symEncNoncePrefixed(scaXChaCha20, toSeqBytes(m.key),
    toSeqBytes(m.nonce), toSeqBytes(message))

proc decryptNoncePrefixed*(payload: openArray[byte], m: xchacha20cipherM): seq[byte] =
  ## Decrypt a typed XChaCha20 `nonce || ciphertext` payload.
  result = symDecNoncePrefixed(scaXChaCha20, toSeqBytes(m.key), toSeqBytes(payload))

proc encrypt*(message: openArray[byte], m: chacha20cipherM): seq[byte] =
  ## Encrypt or stream-XOR `message` with typed ChaCha20 material.
  result = symEnc(scaChaCha20, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(message))

proc decrypt*(payload: openArray[byte], m: chacha20cipherM): seq[byte] =
  ## Decrypt or stream-XOR `payload` with typed ChaCha20 material.
  result = symDec(scaChaCha20, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(payload))

proc encryptNoncePrefixed*(message: openArray[byte], m: chacha20cipherM): seq[byte] =
  ## Encrypt typed ChaCha20 material, returning `nonce || ciphertext`.
  result = symEncNoncePrefixed(scaChaCha20, toSeqBytes(m.key),
    toSeqBytes(m.nonce), toSeqBytes(message))

proc decryptNoncePrefixed*(payload: openArray[byte], m: chacha20cipherM): seq[byte] =
  ## Decrypt a typed ChaCha20 `nonce || ciphertext` payload.
  result = symDecNoncePrefixed(scaChaCha20, toSeqBytes(m.key), toSeqBytes(payload))

proc encrypt*(message: openArray[byte], m: aesCtrcipherM): seq[byte] =
  result = symEnc(scaAesCtr, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(message))

proc decrypt*(payload: openArray[byte], m: aesCtrcipherM): seq[byte] =
  result = symDec(scaAesCtr, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(payload))

proc encryptNoncePrefixed*(message: openArray[byte], m: aesCtrcipherM): seq[byte] =
  ## Encrypt typed AES-CTR material, returning `nonce || ciphertext`.
  result = symEncNoncePrefixed(scaAesCtr, toSeqBytes(m.key),
    toSeqBytes(m.nonce), toSeqBytes(message))

proc decryptNoncePrefixed*(payload: openArray[byte], m: aesCtrcipherM): seq[byte] =
  ## Decrypt a typed AES-CTR `nonce || ciphertext` payload.
  result = symDecNoncePrefixed(scaAesCtr, toSeqBytes(m.key), toSeqBytes(payload))

proc encrypt*(message: openArray[byte], m: gimliStreamCipherM): seq[byte] =
  result = symEnc(scaGimliStream, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(message))

proc decrypt*(payload: openArray[byte], m: gimliStreamCipherM): seq[byte] =
  result = symDec(scaGimliStream, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(payload))

proc encryptNoncePrefixed*(message: openArray[byte], m: gimliStreamCipherM): seq[byte] =
  ## Encrypt typed Gimli stream material, returning `nonce || ciphertext`.
  result = symEncNoncePrefixed(scaGimliStream, toSeqBytes(m.key),
    toSeqBytes(m.nonce), toSeqBytes(message))

proc decryptNoncePrefixed*(payload: openArray[byte], m: gimliStreamCipherM): seq[byte] =
  ## Decrypt a typed Gimli stream `nonce || ciphertext` payload.
  result = symDecNoncePrefixed(scaGimliStream, toSeqBytes(m.key), toSeqBytes(payload))
