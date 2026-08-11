## ---------------------------------------------------------------------
## | KDF Types <- naming the key-derivation families                    |
## ---------------------------------------------------------------------
##
## A KDF ("key derivation function") turns one secret into key material:
##
##   password + salt  --[ slow, memory-hard KDF ]-->  encryption key
##   shared secret    --[ fast KDF ]-->              several session keys
##
## Two jobs, two speeds
## --------------------
##   kdfArgon2i / kdfArgon2id   DELIBERATELY SLOW and memory-hungry. For
##                              human passwords. The cost is the point: it
##                              is what stops someone testing billions of
##                              guesses against a stolen database.
##
##   kdfBlake3Gimli / kdfCustom FAST. For material that is ALREADY a strong
##                              secret, such as the shared secret from a
##                              KEM. Never feed a human password to these.
##
## ⚠ Picking the fast one for a password is the classic mistake. It leaves
## the password only as strong as the guessing rate allows, which is the
## exact thing Argon2 exists to prevent.
##
## Argon2i vs Argon2id: Argon2id is the general recommendation. Argon2i
## resists side-channel watching but is weaker against custom hardware;
## Argon2id mixes both approaches.

type
  KdfFamily* = enum
    kdfArgon2i,
    kdfArgon2id,
    kdfBlake3Gimli,
    kdfCustom

proc familyName*(f: KdfFamily): string =
  ## f: which KDF family.
  case f
  of kdfArgon2i:     result = "argon2i"
  of kdfArgon2id:    result = "argon2id"
  of kdfBlake3Gimli: result = "blake3-gimli"
  of kdfCustom:      result = "custom"

proc parseKdfFamily*(s: string): KdfFamily =
  ## s: a name produced by `familyName`. Raises on anything unknown.
  case s
  of "argon2i":      result = kdfArgon2i
  of "argon2id":     result = kdfArgon2id
  of "blake3-gimli": result = kdfBlake3Gimli
  of "custom":       result = kdfCustom
  else: raise newException(ValueError, "unknown KDF family: " & s)

proc isPasswordSafe*(f: KdfFamily): bool =
  ## f: which KDF family.
  ## True only for the deliberately slow, memory-hard families. Check this
  ## before feeding anything a human typed into a derivation.
  result = f in {kdfArgon2i, kdfArgon2id}
