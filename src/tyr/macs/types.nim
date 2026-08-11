## ---------------------------------------------------------------------
## | MAC Types <- naming the authenticator families                     |
## ---------------------------------------------------------------------
##
## A MAC ("message authentication code") is a fingerprint that only someone
## holding the key can produce:
##
##   hash(message)            -> anyone can compute it
##   mac(key, message)        -> only a key-holder can compute it
##
## The receiver recomputes it with the same key and compares. If the bytes
## match, the message really came from someone holding the key and was not
## altered. Compare with a constant-time check, never with `==` on strings.
##
## A note on the word HMAC
## -----------------------
## HMAC is ONE specific construction (a hash run twice with two padded key
## variants). Only `mfHmacSha3` below is that. The others are different
## constructions that do the same job:
##
##   mfBlake3Keyed   BLAKE3's own built-in keyed mode - not HMAC
##   mfGimli         a sponge absorbing key then message - not HMAC
##   mfPoly1305      a one-time polynomial authenticator - not HMAC
##   mfHmacSha3      genuine HMAC, built on SHA-3
##
## ⚠ mfPoly1305 is ONE-TIME. Its key must never authenticate two different
## messages. Reusing one key lets an attacker solve for it and then forge
## anything. Derive a fresh Poly1305 key per message (that is what the
## AEAD suites do). The other three are safe to use with a long-term key.

type
  MacFamily* = enum
    mfBlake3Keyed,
    mfGimli,
    mfPoly1305,
    mfHmacSha3

proc familyName*(f: MacFamily): string =
  ## f: which MAC family.
  case f
  of mfBlake3Keyed: result = "blake3-keyed"
  of mfGimli:       result = "gimli"
  of mfPoly1305:    result = "poly1305"
  of mfHmacSha3:    result = "hmac-sha3"

proc parseMacFamily*(s: string): MacFamily =
  ## s: a name produced by `familyName`. Raises on anything unknown.
  case s
  of "blake3-keyed": result = mfBlake3Keyed
  of "gimli":        result = mfGimli
  of "poly1305":     result = mfPoly1305
  of "hmac-sha3":    result = mfHmacSha3
  else: raise newException(ValueError, "unknown MAC family: " & s)

proc isOneTime*(f: MacFamily): bool =
  ## f: which MAC family.
  ## True when the key may authenticate only ONE message, ever. Callers
  ## holding a long-term key must derive a fresh per-message key for these.
  result = f == mfPoly1305
