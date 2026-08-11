## ---------------------------------------------------------------------
## | Public Names <- the one place internal names get their public name |
## | internal  blake3Hash    ->  public  blake3TyrHash                  |
## ---------------------------------------------------------------------
##
## Why this file exists
## --------------------
## Every algorithm here has two names.
##
##   blake3Hash      <- the internal name. What the implementation calls
##                      itself, used by the rest of Tyr.
##   blake3TyrHash   <- the public name. What other repos call.
##
## The "Tyr" in the middle means "this repo's own version of it". Tyr can
## expose its own BLAKE3 and a library-backed BLAKE3 at the same time, so a
## caller needs a way to say which one it wants:
##
##   blake3Hash(data)      -> Tyr's own code
##   blake3TyrHash(data)   -> same code, named so it cannot collide
##
## The same split already exists one level down in the algorithm enums,
## where `akKyber0Send` is the library route and `akKyber0TyrSend` is Tyr's.
##
## This used to be spread over 32 tiny files under `custom_crypto/`, one per
## algorithm, each importing one real module and re-exporting it. They are
## gone. Every public name is now defined exactly once, here.
##
## Not every algorithm needs an entry. X25519, Ed25519, Kyber, Dilithium,
## Falcon, SPHINCS+, BIKE, Frodo, McEliece, NTRU and SABER already define
## their public `...Tyr...` names inside their own implementation files, so
## they are re-exported directly by `tyr_crypto.nim` and never appear below.

import ./ciphers/aes_ctr
import ./kdfs/argon2
import ./hashes/blake3
import ./ciphers/chacha20
import ./ciphers/xchacha20
import ./ciphers/gimli_sponge
import ./macs/poly1305
import ./hashes/sha3

export aes_ctr, chacha20, xchacha20, gimli_sponge

## ╭⟢ AES-CTR

proc aesCtrTyrXor*(k, n, ps: openArray[uint8],
    b: AesCtrBackend = acbAuto): seq[uint8] {.inline.} =
  ## Public name for the local AES-CTR xor helper.
  result = aesCtrXor(k, n, ps, b)

proc initAesCtrTyrState*(k, n: openArray[uint8]): AesCtrState {.inline.} =
  ## Public name for the local AES-CTR state initializer.
  result = initAesCtrState(k, n)

## ╭⟢ BLAKE3

proc blake3TyrHash*(input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] {.inline.} =
  ## Public name for the local BLAKE3 hash.
  result = blake3Hash(input, outLen)

proc blake3TyrKeyedHash*(key, input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] {.inline.} =
  ## Public name for the local keyed BLAKE3 hash.
  result = blake3KeyedHash(key, input, outLen)

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

## ╭⟢ Poly1305

proc poly1305TyrMac*(key, msg: openArray[byte]): Poly1305Tag {.inline.} =
  ## Public name for the local Poly1305 MAC.
  result = poly1305Mac(key, msg)

proc poly1305TyrTag*(key, msg: openArray[byte]): seq[byte] {.inline.} =
  ## Public name for the local Poly1305 detached tag helper.
  result = poly1305Tag(key, msg)

proc poly1305TyrVerify*(key, msg, tag: openArray[byte]): bool {.inline.} =
  ## Public name for the local Poly1305 verifier.
  result = poly1305Verify(key, msg, tag)

## ╭⟢ SHA-3 / SHAKE

proc sha3TyrHash*(input: openArray[byte],
    outLen: int = 32): seq[byte] {.inline.} =
  ## Public name for the local SHA3 hash.
  result = sha3Hash(input, outLen)

proc shake256Tyr*(input: openArray[byte], outLen: int): seq[byte] {.inline.} =
  ## Public name for the local SHAKE256 XOF.
  result = shake256(input, outLen)

proc shake128Tyr*(input: openArray[byte], outLen: int): seq[byte] {.inline.} =
  ## Public name for the local SHAKE128 XOF.
  result = shake128(input, outLen)

## ╭⟢ Argon2
##
## Two shapes are offered for each. The first takes a filled-in
## `Argon2Params` object. The second takes the four numbers directly, for
## callers that do not want to build the object first.

proc argon2iTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2i hash.
  result = argon2iHash(password, salt, p, b)

proc argon2iTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2i hash variant.
  result = argon2iHash(password, salt, p, h, b)

proc argon2iTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2i hash.
  result = argon2iHash(password, salt, passCount, memoryKiB, laneCount, outLen, b)

proc argon2iTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2i hash variant.
  result = argon2iHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)

proc argon2idTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2id hash.
  result = argon2idHash(password, salt, p, b)

proc argon2idTyrHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2id hash variant.
  result = argon2idHash(password, salt, p, h, b)

proc argon2idTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local Argon2id hash.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, b)

proc argon2idTyrHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Public name for the local custom Argon2id hash variant.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)

proc deriveArgonLikeKey*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Standalone Tyr-owned custom Argon2id-style key derivation surface.
  result = argon2idHash(password, salt, p, h, b)

proc deriveArgonLikeKey*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] {.inline.} =
  ## Standalone Tyr-owned custom Argon2id-style key derivation surface.
  result = argon2idHash(password, salt, passCount, memoryKiB, laneCount, outLen, h, b)

## ╭⟢ Default tier: name the cipher by its family value
##
## Stream ciphers have no per-family variant type to overload on, so the
## family is named by its enum value rather than inferred from a type.
## For a choice that arrives at runtime use `tyr/ciphers/dynamic` instead;
## for one cipher and nothing else use `tyr/ciphers/single`.

import ./ciphers/types
export types

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
