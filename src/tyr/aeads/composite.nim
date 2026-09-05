## ---------------------------------------------------------------------
## | Composite Suites <- layered stream ciphers, then a keyed tag        |
## ---------------------------------------------------------------------
##
## The five suites Tyr builds itself, out of its own primitives. The one
## standard AEAD primitive, AES-256-GCM, is not here - it brings its own
## tag and lives in `./gcm`.
##
## How one message is sealed
## -------------------------
##
##   plaintext
##      | xor with layer 1's keystream      (XChaCha20 / AES-CTR)
##      | xor with layer 2's keystream      (if the suite has one)
##      | xor with layer 3's keystream      (if the suite has one)
##      v
##   ciphertext ---> framed ---> keyed tag  (BLAKE3 / Gimli / +Poly1305)
##
## Each layer uses its own key and the SAME nonce. That is safe because
## the layers are different algorithms; it would not be safe to run one
## algorithm twice on one nonce.
##
## Why the tag covers a frame, not the raw bytes
## ---------------------------------------------
## `authFrame` prefixes a fixed domain string, the suite id, both
## derivation sources, and the LENGTHS of the nonce and ciphertext before
## the bytes themselves. Length prefixes make the input unambiguous:
## without them a nonce ending in some bytes and a ciphertext starting
## with them could be re-split differently and still produce the same tag,
## letting an attacker move the boundary. The suite id and the sources
## stop a tag made under one configuration from validating under another.
##
## EVERY tag here covers the frame, not the bare ciphertext - the BLAKE3
## one, all three Gimli ones, and the Poly1305 half. They used to differ:
## the Gimli suites tagged `(key, nonce, ciphertext)` directly, so they
## bound neither the suite id nor anything else this paragraph claims.
## That is fixed; the claim now holds for all five.
##
## Encrypt-then-MAC: the tag is computed over the CIPHERTEXT, so `open`
## can reject a forgery before decrypting anything.
##
## Why these tags are NOT HMAC
## ---------------------------
## Tyr has its own HMAC in `tyr/macs` - `blake3CustomHmac`,
## `gimliCustomHmac`, `sha3CustomHmac` - doing the real two-pass dance
## with the 0x36 and 0x5c constants. This file does not call it, on
## purpose.
##
## HMAC's inner/outer xor exists to solve ONE problem: Merkle-Damgard
## hashes (MD5, SHA-1, SHA-2) output their whole internal state, so
## `H(key || message)` can be extended by an attacker who never sees the
## key. Nesting blocks that.
##
## Neither primitive used below has that weakness:
##
##   BLAKE3   has a native keyed mode - the key replaces the IV. It is
##            specified as a PRF, and its own documentation says to use
##            keyed mode rather than HMAC-BLAKE3.
##   Gimli    is a sponge. The capacity is never squeezed out, so there is
##            no state to extend. `gimliTag` also absorbs under a domain
##            separator distinct from `gimliXof`'s, so a tag can never be
##            confused with XOF output taken under the same key.
##
## Wrapping either in ipad/opad would double the work and buy nothing.
## Use the HMAC procs in `tyr/macs` when you need a MAC over a
## Merkle-Damgard hash, or interoperability with something that expects
## RFC 2104 bytes.

import metaPragmas

import ./types
import ../ciphers/aes_ctr
import ../ciphers/gimli_sponge
import ../ciphers/xchacha20
import ../hashes/blake3

export types

proc appendUint64Le(dst: var seq[uint8], v: uint64) {.role: {dataWriter}.} =
  ## dst/v: destination frame and fixed-width little-endian length.
  var i: int = 0
  while i < 8:
    dst.add(uint8((v shr uint64(i * 8)) and 0xff'u64))
    i = i + 1

proc authFrame*(ct: openArray[uint8], s: AeadState): seq[uint8]
    {.role: {truthBuilder}.} =
  ## ct/s: ciphertext and suite state, bound into an unambiguous MAC input.
  ##
  ## The suite id AND both derivation sources go in, because all three are
  ## part of what "this ciphertext" means. Without the sources, two peers
  ## disagreeing about `cipherSource` would still agree on the tag - the
  ## tag covers the ciphertext, which is intact - and the receiver would
  ## get silent garbage instead of an error. Binding them turns that
  ## misconfiguration into a clean authentication failure.
  ##
  ## v3 of the domain marks exactly that change. Tags from v2 do not
  ## validate here, which is what a version bump is for.
  validateAeadState(s)
  const domain = "Tyr-Crypto authenticated suite v3"
  var i: int = 0
  result = newSeqOfCap[uint8](domain.len + 3 + 16 + s.nonce.len + ct.len)
  while i < domain.len:
    result.add(uint8(ord(domain[i])))
    i = i + 1
  result.add(uint8(ord(s.suite)))
  result.add(uint8(ord(s.cipherSource)))
  result.add(uint8(ord(s.macSource)))
  appendUint64Le(result, uint64(s.nonce.len))
  result.add(s.nonce)
  appendUint64Le(result, uint64(ct.len))
  result.add(ct)

proc xorLayer(data, key, nonce: openArray[uint8], useAes: bool,
    src: SubkeySource): seq[uint8] {.role: {actor}.} =
  ## data/key/nonce/useAes: bytes, 32-byte key, suite nonce, cipher choice.
  ## src: which algorithm derives XChaCha20's subkey. AES-CTR has no such
  ## step and ignores it.
  ## AES-CTR takes the first 16 nonce bytes; XChaCha20 takes all 24.
  if useAes:
    result = aesCtrXor(key, nonce.toOpenArray(0, 15), data)
  else:
    result = xchacha20VariantXor(key, nonce, data, src)

proc compositeCipher*(data: openArray[uint8], s: AeadState): seq[uint8]
    {.role: {actor}.} =
  validateAeadState(s)
  ## data/s: bytes and suite state. Runs this suite's cipher layers.
  ## One routine serves both directions: every layer is an xor, and xor
  ## undoes itself, so applying the same layers again decrypts.
  ##
  ## ⚠ Not for use on its own - it hides the message but proves nothing
  ## about it. `seal` in `tyr/aeads` pairs it with `compositeTag`.
  case s.suite
  of csXChaCha20Blake3:
    result = xorLayer(data, s.keys[0], s.nonce, false, s.cipherSource)
  of csXChaCha20Gimli:
    result = xorLayer(data, s.keys[0], s.nonce, false, s.cipherSource)
    result = gimliStreamXor(s.keys[1], s.nonce, result)
  of csAesGimli:
    result = xorLayer(data, s.keys[0], s.nonce, true, s.cipherSource)
    result = gimliStreamXor(s.keys[1], s.nonce, result)
  of csXChaCha20AesGimli, csXChaCha20AesGimliPoly1305:
    result = xorLayer(data, s.keys[0], s.nonce, false, s.cipherSource)
    result = xorLayer(result, s.keys[1], s.nonce, true, s.cipherSource)
    result = gimliStreamXor(s.keys[2], s.nonce, result)
  of csAes256Gcm:
    raise newException(ValueError,
      "AES-256-GCM is not a composite suite; it is handled in aeads/gcm")

proc compositeTag*(ct: openArray[uint8], s: AeadState): tuple[kind: AuthType,
    bytes: seq[uint8]] {.role: {actor}.} =
  ## ct/s: ciphertext and suite state. Produces the tag that proves the
  ## ciphertext arrived as it left, using the LAST key of the suite.
  validateAeadState(s)
  case s.suite
  of csXChaCha20Blake3:
    result.kind = atBlake3
    result.bytes = blake3KeyedHash(s.keys[1], authFrame(ct, s), int(s.tagBytes))
  of csXChaCha20Gimli:
    result.kind = atGimli
    result.bytes = gimliTag(s.keys[1], s.nonce, authFrame(ct, s), int(s.tagBytes))
  of csAesGimli:
    result.kind = atGimli
    result.bytes = gimliTag(s.keys[1], s.nonce, authFrame(ct, s), int(s.tagBytes))
  of csXChaCha20AesGimli:
    result.kind = atGimli
    result.bytes = gimliTag(s.keys[2], s.nonce, authFrame(ct, s), int(s.tagBytes))
  of csXChaCha20AesGimliPoly1305:
    ## Two authenticators over one ciphertext, appended. The Poly1305 half
    ## uses its own fourth key, which is what keeps it a one-time key.
    result.kind = atGimliPoly1305
    result.bytes = gimliTag(s.keys[2], s.nonce, authFrame(ct, s), int(s.tagBytes))
    result.bytes.add(poly1305DerivedTag(s.keys[3], s.nonce, authFrame(ct, s),
      s.macSource))
  of csAes256Gcm:
    raise newException(ValueError,
      "AES-256-GCM is not a composite suite; it is handled in aeads/gcm")
