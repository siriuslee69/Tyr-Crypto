## ---------------------------------------------------------------------
## | AES-256-GCM <- the one standard AEAD primitive, from nimcrypto      |
## ---------------------------------------------------------------------
##
## Unlike the composites in `./composite`, this is a single well-studied
## primitive that does encryption and authentication together, in one
## pass, producing its own 16-byte tag. Tyr does not implement it; it
## forwards to nimcrypto.
##
## Availability
## ------------
## Only compiled in with `-d:hasNimcrypto`. Without that flag the procs
## still exist and raise a clear "unavailable" error, so a program that
## selects the suite from a config value fails with a message naming the
## flag instead of failing to build.
##
## ⚠ GCM's nonce is 12 bytes - too short to pick at random for any real
## volume of messages. Keep a counter. Reusing a nonce under one key with
## GCM is worse than with a plain stream cipher: it leaks the
## authentication key, so an attacker can then forge tags at will.
##
## ⚠ The tag is exactly 16 bytes. `resolveTagBytes` rejects any other
## request rather than silently ignoring it.

import tyrPragmas
import ./types
import ../helpers/errors
when defined(hasNimcrypto):
  import ../bindings/nimcrypto

export types

proc gcmAvailable*(): bool =
  ## True when this build can actually run AES-256-GCM.
  result = defined(hasNimcrypto)

proc gcmSeal*(plain: openArray[uint8], s: AeadState): AeadCiphertext {.role: {encryptor}.} =
  ## plain/s: readable bytes and a state whose suite is `csAes256Gcm`.
  ## Returns the ciphertext and the primitive's own 16-byte tag.
  validateAeadState(s)
  if s.suite != csAes256Gcm:
    raise newException(ValueError, "AES-256-GCM requires its own suite state")
  claimForSeal(s)
  when defined(hasNimcrypto):
    var ctx: Aes256GcmContext
    defer:
      ctx.clear()
    ctx.init(s.keys[0], s.nonce)
    result.ciphertext = ctx.encrypt(plain)
    result.auth = @(ctx.tag())
    result.authType = atAeadTag
  else:
    discard plain
    discard s
    raiseUnavailable("AES-256-GCM", "hasNimcrypto")

proc gcmOpen*(c: AeadCiphertext, s: AeadState): seq[uint8] {.role: {decryptor}.} =
  ## c/s: a sealed message and the state that can open it.
  ## Raises if the tag does not match; never returns unverified bytes.
  validateAeadState(s)
  if s.suite != csAes256Gcm:
    raise newException(ValueError, "AES-256-GCM requires its own suite state")
  if c.authType != atAeadTag or c.auth.len != int(gcmTagBytes):
    raise newException(ValueError, "AES-256-GCM authentication tag is invalid")
  when defined(hasNimcrypto):
    var ctx: Aes256GcmContext
    defer:
      ctx.clear()
    ctx.init(s.keys[0], s.nonce)
    result = ctx.decrypt(c.ciphertext, c.auth)
  else:
    discard s
    raiseUnavailable("AES-256-GCM", "hasNimcrypto")
