## ---------------------------------------------------------------------
## | AEAD Types <- naming the suites, their keys, nonces and tags        |
## ---------------------------------------------------------------------
##
## What an AEAD is for
## -------------------
## A plain cipher (`tyr/ciphers`) hides your message but does not notice
## when someone changes it. An attacker who cannot read a stream cipher's
## output can still flip bit 12 of the ciphertext and flip bit 12 of your
## plaintext with it. You decrypt happily and act on altered data.
##
## An AEAD closes that hole: encrypt, then compute an authentication tag
## over the ciphertext. `open` recomputes the tag and REFUSES to return
## anything if it does not match. Wrong key, flipped bit, truncated
## message - all raise rather than hand back plausible-looking bytes.
##
## Encrypt-then-MAC, in that order. Tagging the ciphertext rather than the
## plaintext means a forgery is rejected before any decryption happens.
##
## The six suites
## --------------
##
##   suite                          keys  nonce  layers
##   ----------------------------   ----  -----  ------------------------
##   csXChaCha20Blake3                2     24   XChaCha20, BLAKE3 keyed
##   csXChaCha20Gimli                 2     24   XChaCha20 + Gimli, Gimli
##   csAesGimli                       2     24   AES-CTR + Gimli, Gimli
##   csXChaCha20AesGimli              3     24   all three, Gimli tag
##   csXChaCha20AesGimliPoly1305      4     24   all three, Gimli+Poly1305
##   csAes256Gcm                      1     12   one real AEAD primitive
##
## Every key is 32 bytes, and each layer gets its OWN key - a suite with
## three ciphers needs three keys plus one for the tag. Passing the same
## bytes twice defeats the layering, so derive them from one secret with
## `tyr/kdfs` rather than copying.
##
## Layering versus a single primitive
## ----------------------------------
## `csAes256Gcm` is a standard AEAD, from nimcrypto, available only with
## `-d:hasNimcrypto`. The other five are built here out of Tyr's own
## primitives: one or more stream ciphers applied in turn, then a keyed
## tag over the result.
##
## Stacking ciphers is not a security multiplier. The point is
## independence of implementation: a defect in one of Tyr's cipher cores
## does not by itself expose a message that also passed through two
## others. If you want one well-studied primitive instead, use
## `csAes256Gcm`.
##
## ⚠ A nonce must never repeat under one key, in ANY suite. These are
## stream ciphers underneath, and a repeated nonce means a repeated
## keystream. `AeadState` refuses a second `seal` to catch the common
## case, but it cannot see a nonce you reused in another process or after
## a restart - that part is yours to get right.
##
## ⚠ There is no associated-data input yet. Everything you need bound to
## the ciphertext must be inside the message.

import tyrPragmas
import ../ciphers/chacha/xchacha20_derive
import ../macs/poly1305/derive

export xchacha20_derive, derive

type
  ## Which authenticated composite to use. See the table above.
  CipherSuite* = enum
    csXChaCha20Blake3,
    csXChaCha20Gimli,
    csAesGimli,
    csXChaCha20AesGimli,
    csXChaCha20AesGimliPoly1305,
    csAes256Gcm

  ## What produced the tag on a ciphertext. Carried alongside the tag so
  ## `open` can reject a value whose tag was made a different way, before
  ## it ever compares bytes.
  AuthType* = enum
    atBlake3,          # keyed BLAKE3 over the framed ciphertext
    atGimli,           # Gimli sponge tag
    atGimliPoly1305,   # Gimli tag followed by a 16-byte Poly1305 tag
    atAeadTag          # the primitive's own tag (AES-256-GCM)

const
  suiteKeyBytes* = 32
    ## Every suite key is 32 bytes, in every suite.
  defaultTagBytes* = 32'u16
    ## Tag length used when the caller asks for 0.
  minTagBytes* = 16'u16
  maxTagBytes* = 32'u16
  gcmTagBytes* = 16'u16
    ## AES-256-GCM has exactly one tag length and rejects any other.

proc keyCount*(a: CipherSuite): int =
  ## a: which suite. How many 32-byte keys it needs, in order: one per
  ## cipher layer, then one per authenticator.
  case a
  of csAes256Gcm:
    result = 1
  of csXChaCha20Blake3, csXChaCha20Gimli, csAesGimli:
    result = 2
  of csXChaCha20AesGimli:
    result = 3
  of csXChaCha20AesGimliPoly1305:
    result = 4

proc nonceBytes*(a: CipherSuite): int =
  ## a: which suite. How many nonce bytes it expects.
  ## The composites use XChaCha20's 24, wide enough to pick at random.
  ## AES-256-GCM uses 12, which is NOT - keep a counter for it.
  case a
  of csAes256Gcm:
    result = 12
  else:
    result = 24

proc resolveTagBytes*(a: CipherSuite, t: uint16): uint16 =
  ## a/t: suite, and the requested tag length, or 0 for its safe default.
  ## Raises when the request is one this suite cannot honour, rather than
  ## quietly producing a shorter tag than the caller believes they asked
  ## for. A short tag is a weak tag: 16 bytes is the floor.
  if a == csAes256Gcm:
    if t != 0'u16 and t != gcmTagBytes:
      raise newException(ValueError,
        "AES-256-GCM requires a 16-byte authentication tag")
    return gcmTagBytes
  result = if t == 0'u16: defaultTagBytes else: t
  if result < minTagBytes or result > maxTagBytes:
    raise newException(ValueError,
      "cipher suite tag length must be between 16 and 32 bytes")

proc suiteName*(a: CipherSuite): string =
  ## a: which suite. Short stable text name for configs and logs.
  case a
  of csXChaCha20Blake3:            result = "xchacha20-blake3"
  of csXChaCha20Gimli:             result = "xchacha20-gimli"
  of csAesGimli:                   result = "aes-gimli"
  of csXChaCha20AesGimli:          result = "xchacha20-aes-gimli"
  of csXChaCha20AesGimliPoly1305:  result = "xchacha20-aes-gimli-poly1305"
  of csAes256Gcm:                  result = "aes256-gcm"

proc parseCipherSuite*(s: string): CipherSuite =
  ## s: a name produced by `suiteName`. Raises on anything unknown.
  case s
  of "xchacha20-blake3":             result = csXChaCha20Blake3
  of "xchacha20-gimli":              result = csXChaCha20Gimli
  of "aes-gimli":                    result = csAesGimli
  of "xchacha20-aes-gimli":          result = csXChaCha20AesGimli
  of "xchacha20-aes-gimli-poly1305": result = csXChaCha20AesGimliPoly1305
  of "aes256-gcm":                   result = csAes256Gcm
  else: raise newException(ValueError, "unknown cipher suite: " & s)

proc isSinglePrimitive*(a: CipherSuite): bool =
  ## a: which suite. True for a standard AEAD primitive, false for the
  ## composites Tyr layers itself. Use it when a caller needs to know
  ## whether they are getting a named standard or a Tyr construction.
  result = a == csAes256Gcm

## ╭⟢ The state a sealing carries
##
## `AeadState` holds one suite, its keys and ONE nonce. It is deliberately
## not reusable for a second `seal`: the state remembers that its nonce
## has been spent and refuses, which turns the most common catastrophic
## mistake into an exception. Build a fresh state per message.
##
## Opening is unrestricted - checking a tag reveals nothing and can be
## repeated as often as you like.

## ╭⟢ Which algorithm derives what
##
## Two steps inside these suites are performed by a SECOND algorithm, and
## both are swappable - see `tyr/ciphers/chacha/xchacha20_derive` and
## `tyr/macs/poly1305/derive` for what each choice does and does not
## remove.
##
##   cipherSource   derives XChaCha20's subkey       default HChaCha20
##   macSource      derives Poly1305's one-time key  default XChaCha20
##
## The defaults are the standard constructions, so a state built without
## naming them behaves exactly as it always did. A suite that uses
## neither XChaCha20 nor Poly1305 ignores the corresponding field.
##
## ⚠ Both sides must agree. A ciphertext sealed with `sksBlake3` opens
## only under `sksBlake3`. Record the two-letter codes from `sourceName`
## with anything you keep.

type
  ## One suite, its keys, and one nonce that may be sealed with once.
  AeadState* = ref object
    suite*: CipherSuite
    keys*: seq[seq[uint8]]
    nonce*: seq[uint8]
    tagBytes*: uint16
    cipherSource*: SubkeySource
    macSource*: Poly1305KeySource
    sealed: bool

  ## A sealed message: the scrambled bytes plus the tag that proves they
  ## were not altered, and a note of what produced that tag.
  AeadCiphertext* = object
    ciphertext*: seq[uint8]
    auth*: seq[uint8]
    authType*: AuthType

proc initAeadState*(a: CipherSuite, keys: seq[seq[uint8]], nonce: seq[uint8],
    tagBytes: uint16 = 0'u16,
    cipherSource: SubkeySource = sksHChaCha20,
    macSource: Poly1305KeySource = pksXChaCha20): AeadState =
  ## a: which suite.
  ## keys: one 32-byte key per layer, in the order the suite lists them.
  ## nonce: `nonceBytes(a)` bytes, never before used with these keys.
  ## tagBytes: wanted tag length, or 0 for the suite's safe default.
  ## cipherSource/macSource: which algorithm derives XChaCha20's subkey
  ## and Poly1305's one-time key. Both default to the standard route.
  ##
  ## Every length is checked here, so a wrong count or a short key fails
  ## at setup rather than producing a ciphertext nobody can open.
  var i: int = 0
  if keys.len != keyCount(a):
    raise newException(ValueError, "cipher suite key count mismatch")
  for key in keys:
    if key.len != suiteKeyBytes:
      raise newException(ValueError, "cipher suite keys must be 32 bytes")
  if nonce.len != nonceBytes(a):
    raise newException(ValueError, "cipher suite nonce length mismatch")
  new(result)
  result.suite = a
  result.keys = newSeq[seq[uint8]](keys.len)
  while i < keys.len:
    result.keys[i] = keys[i]
    i = i + 1
  result.nonce = nonce
  result.tagBytes = resolveTagBytes(a, tagBytes)
  result.cipherSource = cipherSource
  result.macSource = macSource
  result.sealed = false

proc validateAeadState*(s: AeadState) {.role: {sanitizer}.} =
  ## Reject nil or externally mutated state before any key or nonce access.
  if s == nil:
    raise newException(ValueError, "cipher suite state is not initialized")
  if s.keys.len != keyCount(s.suite):
    raise newException(ValueError, "cipher suite key count mismatch")
  for key in s.keys:
    if key.len != suiteKeyBytes:
      raise newException(ValueError, "cipher suite keys must be 32 bytes")
  if s.nonce.len != nonceBytes(s.suite):
    raise newException(ValueError, "cipher suite nonce length mismatch")
  if s.tagBytes != resolveTagBytes(s.suite, s.tagBytes):
    raise newException(ValueError, "cipher suite state requires a resolved tag length")


proc claimForSeal*(s: AeadState) {.role: {actor}.} =
  ## s: the state about to encrypt. Marks its nonce spent, and raises if
  ## it already was. Call this before doing any work, so a rejected reuse
  ## never touches the cipher.
  validateAeadState(s)
  if s.sealed:
    raise newException(ValueError,
      "cipher suite nonce has already been used for encryption")
  s.sealed = true
