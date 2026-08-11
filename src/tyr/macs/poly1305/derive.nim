## ---------------------------------------------------------------------
## | Poly1305 Key Sources <- choose what derives the one-time key        |
## | poly1305xcTag (default)   poly1305b3Tag   poly1305giTag             |
## ---------------------------------------------------------------------
##
## Why this file exists
## --------------------
## Poly1305 is a ONE-TIME authenticator. Its 32-byte key splits into a
## multiplier `r` and an additive mask `s`, and the tag is
##
##     tag = c1*r^2 + c2*r + ... + s
##
## where the message blocks are the coefficients. Use one `(r, s)` for two
## messages and the mask cancels out of the difference, leaving a
## polynomial in `r` with known coefficients. Solve it, recover `r`, then
## `s`, and forge anything you like. So every message needs its own key.
##
## Nobody hands Poly1305 a fresh 32-byte key per message by hand. It is
## always DERIVED from a long-lived master key plus a nonce. The standard
## derivation runs the cipher: take the first 32 bytes of the keystream.
##
## That choice bakes a second algorithm into your authentication. This
## file makes it swappable. If you stop trusting ChaCha20 as a generator,
## you can derive the same key with BLAKE3 or Gimli instead, and Poly1305
## itself does not change.
##
##   suffix   source                          what it removes
##   ------   ----------------------------    -------------------------
##   xc       XChaCha20 keystream (default)   nothing - the standard
##   b3       BLAKE3 keyed hash               ChaCha20, entirely
##   gi       Gimli sponge XOF                ChaCha20, entirely
##
## This is a real removal, not a gesture. Poly1305's own security does not
## rest on ChaCha20 in any way - it only needs `(r, s)` to be secret,
## unpredictable and fresh. Swap the source and no part of the tag depends
## on ChaCha20 any more.
##
## ⚠ These variants are NOT interoperable with each other or with anyone
## else's Poly1305. A tag made with `poly1305b3Tag` verifies only with
## `poly1305b3Verify`. Store which source you used alongside the tag -
## `sourceName` and `parsePoly1305KeySource` exist for exactly that.
##
## ⚠ The nonce still has to be unique per message under one master key.
## Changing the derivation does not change that; it only changes which
## algorithm turns your unique nonce into a unique key. 24 bytes is wide
## enough to pick at random.

import ./poly1305
import ../../hashes/blake3
import ../../ciphers/chacha/xchacha20
import ../../ciphers/gimli/gimli_sponge
import ../../helpers/secure_memory

const
  poly1305NonceBytes* = 24
    ## Same width as XChaCha20's nonce, so random selection is safe and
    ## every source below accepts the same input.
  poly1305DeriveContext* = "Tyr-Crypto poly1305 one-time key v1"
    ## Domain separator, so a key derived for Poly1305 can never collide
    ## with one derived for something else from the same master key.

type
  ## Which algorithm turns (master key, nonce) into Poly1305's `(r, s)`.
  Poly1305KeySource* = enum
    pksXChaCha20,   # the standard route: first 32 keystream bytes
    pksBlake3,      # keyed BLAKE3
    pksGimli        # Gimli sponge XOF

proc sourceName*(s: Poly1305KeySource): string =
  ## s: which source. The two-character tag to store beside a MAC.
  case s
  of pksXChaCha20: result = "xc"
  of pksBlake3:    result = "b3"
  of pksGimli:     result = "gi"

proc parsePoly1305KeySource*(s: string): Poly1305KeySource =
  ## s: a name produced by `sourceName`. Raises on anything unknown.
  case s
  of "xc": result = pksXChaCha20
  of "b3": result = pksBlake3
  of "gi": result = pksGimli
  else: raise newException(ValueError, "unknown poly1305 key source: " & s)

proc contextBytes(): seq[byte] =
  result = newSeq[byte](poly1305DeriveContext.len)
  for i, ch in poly1305DeriveContext:
    result[i] = byte(ord(ch))

proc poly1305DeriveKey*(src: Poly1305KeySource,
    master, nonce: openArray[byte]): seq[byte] =
  ## src/master/nonce: chosen source, the long-lived 32-byte key, and a
  ## 24-byte nonce never used before with that key.
  ##
  ## Returns the 32-byte one-time `(r, s)`. Treat it as a secret: anyone
  ## holding it can forge any message under it.
  ##
  ## ⚠ Same master and same nonce always give the same key, whichever
  ## source you pick. That is what makes the nonce's uniqueness the whole
  ## of your safety margin.
  var ctx: seq[byte] = @[]
  defer:
    secureClearBytes(ctx)
  if master.len != poly1305KeyBytes:
    raise newException(ValueError, "poly1305 key derivation requires a 32-byte master key")
  if nonce.len != poly1305NonceBytes:
    raise newException(ValueError, "poly1305 key derivation requires a 24-byte nonce")
  case src
  of pksXChaCha20:
    ## The standard route, as XChaCha20-Poly1305 does it: the first 32
    ## bytes of the keystream. Counter 0 is reserved for this, which is
    ## why real AEADs start encrypting at counter 1.
    result = xchacha20Stream(master, nonce, poly1305KeyBytes, 0'u32)
  of pksBlake3:
    ctx = contextBytes()
    ctx.add(nonce)
    result = blake3KeyedHash(master, ctx, poly1305KeyBytes)
  of pksGimli:
    ctx = contextBytes()
    result = gimliXof(master, nonce, ctx, poly1305KeyBytes)

proc poly1305DerivedTag*(master, nonce, msg: openArray[byte],
    src: Poly1305KeySource = pksXChaCha20): seq[byte] =
  ## master/nonce/msg: long-lived key, unique 24-byte nonce, the message.
  ## src: which algorithm derives the one-time key. Defaults to the
  ## standard XChaCha20 route.
  ##
  ## Safe to call repeatedly with ONE master key, as long as each call
  ## gets its own nonce.
  var oneTime: seq[byte] = @[]
  defer:
    secureClearBytes(oneTime)
  oneTime = poly1305DeriveKey(src, master, nonce)
  result = poly1305Tag(oneTime, msg)

proc poly1305DerivedVerify*(master, nonce, msg, tag: openArray[byte],
    src: Poly1305KeySource = pksXChaCha20): bool =
  ## master/nonce/msg/tag: as above, plus the tag that arrived.
  ## src: must match the source that produced the tag.
  ## Constant-time comparison; false means reject, with no detail leaked.
  var oneTime: seq[byte] = @[]
  defer:
    secureClearBytes(oneTime)
  oneTime = poly1305DeriveKey(src, master, nonce)
  result = poly1305Verify(oneTime, msg, tag)

## ╭⟢ One name per source
##
## The same three calls under fixed names, for code that picks its source
## while being written rather than while running.

proc poly1305xcTag*(master, nonce, msg: openArray[byte]): seq[byte] {.inline.} =
  ## Poly1305 with the standard XChaCha20-derived one-time key.
  result = poly1305DerivedTag(master, nonce, msg, pksXChaCha20)

proc poly1305xcVerify*(master, nonce, msg, tag: openArray[byte]): bool {.inline.} =
  ## Verify a tag made by `poly1305xcTag`.
  result = poly1305DerivedVerify(master, nonce, msg, tag, pksXChaCha20)

proc poly1305b3Tag*(master, nonce, msg: openArray[byte]): seq[byte] {.inline.} =
  ## Poly1305 with a BLAKE3-derived one-time key. No ChaCha20 involved.
  result = poly1305DerivedTag(master, nonce, msg, pksBlake3)

proc poly1305b3Verify*(master, nonce, msg, tag: openArray[byte]): bool {.inline.} =
  ## Verify a tag made by `poly1305b3Tag`.
  result = poly1305DerivedVerify(master, nonce, msg, tag, pksBlake3)

proc poly1305giTag*(master, nonce, msg: openArray[byte]): seq[byte] {.inline.} =
  ## Poly1305 with a Gimli-derived one-time key. No ChaCha20 involved.
  result = poly1305DerivedTag(master, nonce, msg, pksGimli)

proc poly1305giVerify*(master, nonce, msg, tag: openArray[byte]): bool {.inline.} =
  ## Verify a tag made by `poly1305giTag`.
  result = poly1305DerivedVerify(master, nonce, msg, tag, pksGimli)
