## ---------------------------------------------------------------------
## | XChaCha20 Subkey Sources <- choose what derives the subkey          |
## | xchacha20Xor (default)   xchacha20b3Xor   xchacha20giXor            |
## ---------------------------------------------------------------------
##
## What XChaCha20 actually is
## --------------------------
## ChaCha20 takes a 12-byte nonce, which is too narrow to pick at random -
## collisions arrive around 2^48 messages. XChaCha20 widens it to 24 by
## adding a step in front:
##
##   subkey       = HChaCha20(key, nonce[0..15])
##   ciphertext   = ChaCha20(subkey, 00000000 || nonce[16..23], counter)
##
## Only the first step is new. The second is ordinary ChaCha20. So the
## 24-byte nonce is bought entirely with HChaCha20, and HChaCha20 is
## ChaCha20's permutation with the final feed-forward REMOVED - a related
## but separate construction, with its own security argument.
##
## This file lets you replace that first step.
##
##   suffix   subkey from                    what it removes
##   ------   --------------------------     -------------------------
##   (none)   HChaCha20 (default)            nothing - the standard
##   b3       BLAKE3 keyed hash              the HChaCha20 assumption
##   gi       Gimli sponge XOF               the HChaCha20 assumption
##
## ⚠ Read this before reaching for it. The variants remove HChaCha20 and
## NOTHING ELSE. The keystream is still ChaCha20 in every case - that is
## what makes it XChaCha20 rather than some other cipher. If your worry is
## ChaCha20 itself, this will not help you and you want a different cipher
## from `tyr/ciphers` instead.
##
## The variants are worth having for the narrower worry: HChaCha20 has had
## far less attention than ChaCha20, and dropping the feed-forward is
## exactly the kind of change that invalidates a proof. If you would
## rather not depend on it, derive the subkey with a hash you already
## trust for key derivation. That is all this does.
##
## ⚠ NOT interoperable. `xchacha20b3Xor` is not XChaCha20, and only
## `xchacha20b3Xor` can decrypt what it produced. Record which source you
## used - `sourceName` and `parseSubkeySource` are here for that.
##
## ⚠ Every warning about nonce reuse still applies unchanged. These are
## stream ciphers: one key plus one nonce, once, ever.

import ./chacha20
import ./xchacha20
import ../../hashes/blake3
import ../gimli/gimli_sponge
import ../../helpers/secure_memory

const
  subkeyDeriveContext* = "Tyr-Crypto xchacha20 subkey v1"  # otter:allow
    ## Domain separator, so a subkey can never collide with other key
    ## material derived from the same key.

type
  ## Which algorithm turns (key, first 16 nonce bytes) into the subkey.
  SubkeySource* = enum
    sksHChaCha20,   # the standard route
    sksBlake3,      # keyed BLAKE3
    sksGimli        # Gimli sponge XOF

proc sourceName*(s: SubkeySource): string =
  ## s: which source. The two-character tag to record beside a message.
  case s
  of sksHChaCha20: result = "hc"
  of sksBlake3:    result = "b3"
  of sksGimli:     result = "gi"

proc parseSubkeySource*(s: string): SubkeySource =
  ## s: a name produced by `sourceName`. Raises on anything unknown.
  case s
  of "hc": result = sksHChaCha20
  of "b3": result = sksBlake3
  of "gi": result = sksGimli
  else: raise newException(ValueError, "unknown xchacha20 subkey source: " & s)

proc contextBytes(): seq[byte] =
  result = newSeq[byte](subkeyDeriveContext.len)
  for i, ch in subkeyDeriveContext:
    result[i] = byte(ord(ch))

proc xchacha20Subkey*(src: SubkeySource,
    key, nonce: openArray[byte]): array[32, byte] =
  ## src/key/nonce: chosen source, the 32-byte key, the 24-byte nonce.
  ## Returns the subkey ChaCha20 is then run under. Only the first 16
  ## nonce bytes feed this step; the last 8 go into ChaCha20's own nonce.
  var
    head: seq[byte] = @[]
    ctx: seq[byte] = @[]
    derived: seq[byte] = @[]
    i: int = 0
  defer:
    secureClearBytes(ctx)
    secureClearBytes(derived)
  if key.len != 32:
    raise newException(ValueError, "XChaCha20 requires a 32-byte key")
  if nonce.len != xchacha20NonceSize:
    raise newException(ValueError, "XChaCha20 requires a 24-byte nonce")
  head = newSeq[byte](16)
  while i < 16:
    head[i] = nonce[i]
    i = i + 1
  case src
  of sksHChaCha20:
    result = hchacha20(key, head)
    return
  of sksBlake3:
    ctx = contextBytes()
    ctx.add(head)
    derived = blake3KeyedHash(key, ctx, 32)
  of sksGimli:
    ctx = contextBytes()
    derived = gimliXof(key, head, ctx, 32)
  i = 0
  while i < 32:
    result[i] = derived[i]
    i = i + 1

proc chachaNonceOf(nonce: openArray[byte]): array[12, byte] =
  ## The last 8 nonce bytes, right-aligned behind four zero bytes, which
  ## is what the ChaCha20 half of XChaCha20 runs under.
  var i: int = 0
  while i < 8:
    result[4 + i] = nonce[16 + i]
    i = i + 1

proc xchacha20VariantXor*(key, nonce: openArray[byte], input: openArray[byte],
    src: SubkeySource = sksHChaCha20,
    initialCounter: uint32 = 0'u32): seq[byte] =
  ## key/nonce/input: 32-byte key, 24-byte nonce, the bytes to transform.
  ## src: which algorithm derives the subkey. Defaults to the standard.
  ## initialCounter: keystream block to start at.
  ##
  ## Encrypts and decrypts alike - it is an xor either way.
  ## ⚠ Never reuse a key+nonce pair.
  var subkey: array[32, byte]
  defer:
    secureClearPod(subkey)
  subkey = xchacha20Subkey(src, key, nonce)
  result = chacha20Xor(subkey, chachaNonceOf(nonce), initialCounter, input)

proc xchacha20VariantStream*(key, nonce: openArray[byte], length: int,
    src: SubkeySource = sksHChaCha20,
    initialCounter: uint32 = 0'u32): seq[byte] =
  ## key/nonce/length: 32-byte key, 24-byte nonce, wanted keystream bytes.
  ## src/initialCounter: subkey source, and the block to start at.
  var subkey: array[32, byte]
  defer:
    secureClearPod(subkey)
  if length < 0:
    raise newException(ValueError, "length must be non-negative")
  subkey = xchacha20Subkey(src, key, nonce)
  result = chacha20Stream(subkey, chachaNonceOf(nonce), length, initialCounter)

## ╭⟢ One name per source
##
## The same calls under fixed names, for code that picks its source while
## being written rather than while running. The standard route keeps its
## original name, `xchacha20Xor`, and is what you get by default.

proc xchacha20b3Xor*(key, nonce: openArray[byte],
    input: openArray[byte]): seq[byte] {.inline.} =
  ## XChaCha20 with a BLAKE3-derived subkey. Not interoperable.
  result = xchacha20VariantXor(key, nonce, input, sksBlake3)

proc xchacha20b3Stream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] {.inline.} =
  ## Keystream from `xchacha20b3Xor`'s construction.
  result = xchacha20VariantStream(key, nonce, length, sksBlake3, initialCounter)

proc xchacha20giXor*(key, nonce: openArray[byte],
    input: openArray[byte]): seq[byte] {.inline.} =
  ## XChaCha20 with a Gimli-derived subkey. Not interoperable.
  result = xchacha20VariantXor(key, nonce, input, sksGimli)

proc xchacha20giStream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] {.inline.} =
  ## Keystream from `xchacha20giXor`'s construction.
  result = xchacha20VariantStream(key, nonce, length, sksGimli, initialCounter)
