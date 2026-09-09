## ---------------------------------------------------------------------
## | AEADs <- encrypt AND prove nobody changed it                       |
## ---------------------------------------------------------------------
##
##   import tyr/aeads             <- THIS FILE. seal(msg, state) / open
##   import tyr/aeads/dynamic     <- one-shot, suite named by a value
##   import tyr/aeads/composite   <- the layered suites on their own
##   import tyr/aeads/gcm         <- AES-256-GCM on its own
##
## The usual shape
## ---------------
##
##     var st = initAeadState(csXChaCha20Blake3, @[key, authKey], nonce)
##     var c  = seal(message, st)          # st is now spent
##     var m  = open(c, st)                # raises if anything changed
##
## Build a fresh state per message. `seal` refuses a second call on one
## state, because a repeated nonce is the mistake that breaks these
## ciphers outright. See `types.nim` for the suite table and the rest of
## the warnings - read them before choosing a suite.
##
## `open` never returns unverified bytes. If the tag does not match it
## raises, so there is no code path where a caller accidentally uses data
## that failed its check.
##
## Why there is no `single.nim` here
## ---------------------------------
## Every other module has one, gating a build down to one algorithm. It
## would be theatre here. The five composite suites are not separate
## implementations - they are configurations of one engine in
## `composite.nim`, so there is nothing to leave out. The only suite with
## a real external dependency, AES-256-GCM, is already gated behind
## `-d:hasNimcrypto`, and Nim's dead-code elimination drops the arms a
## program never reaches. A flag would add a layer without removing code.

import runePragmas

import ./aeads/types
import ./aeads/composite
import ./aeads/gcm
import ./helpers/common/ct_compare

export types
export composite, gcm

proc seal*(plain: openArray[uint8], s: AeadState): AeadCiphertext
    {.role: {actor}.} =
  ## plain/s: the readable bytes, and a state that has not sealed yet.
  ## Returns the scrambled bytes plus the tag that proves them.
  ##
  ## Spends the state's nonce first, so a rejected reuse never reaches
  ## the cipher.
  var tag: tuple[kind: AuthType, bytes: seq[uint8]]
  if s.suite == csAes256Gcm:
    return gcmSeal(plain, s)
  claimForSeal(s)
  result.ciphertext = compositeCipher(plain, s)
  tag = compositeTag(result.ciphertext, s)
  result.authType = tag.kind
  result.auth = tag.bytes

proc open*(c: AeadCiphertext, s: AeadState): seq[uint8] {.role: {actor}.} =
  validateAeadState(s)
  ## c/s: a sealed message, and a state built from the same suite, keys
  ## and nonce that sealed it.
  ##
  ## Checks the tag BEFORE decrypting and raises if it fails, so altered
  ## or forged input never gets decrypted at all. The comparison is
  ## constant-time: how long the check takes reveals nothing about how
  ## much of a guessed tag was right.
  if s == nil:
    raise newException(ValueError, "cipher suite state is not initialized")
  if s.suite == csAes256Gcm:
    return gcmOpen(c, s)
  var expected: tuple[kind: AuthType, bytes: seq[uint8]] =
    compositeTag(c.ciphertext, s)
  if c.authType != expected.kind or not bytesEqualCt(c.auth, expected.bytes):
    raise newException(ValueError, "cipher suite authentication failed")
  result = compositeCipher(c.ciphertext, s)
