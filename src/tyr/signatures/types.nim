## ---------------------------------------------------------------------
## | Signature Types <- the key material every signature family returns |
## | keypair -> (public, secret)    sign -> signature bytes             |
## ---------------------------------------------------------------------
##
## What a signature scheme is, in one picture
## ------------------------------------------
##   Alice                                    anyone
##   -----                                    ------
##   keypair() -> public, secret
##        public --------------------------->
##   sign(secret, message) -> signature
##        message + signature -------------->
##                            verify(public, message, signature)
##                              -> true  (Alice really sent this, unchanged)
##                              -> false (forged, or altered in transit)
##
## Only the holder of `secret` can produce a signature that verifies against
## `public`. Anybody holding `public` can check one.
##
## This file holds only the shapes. It imports no algorithm, so a build that
## uses one scheme does not drag in the rest.

type
  ## Which family produced the material. Read by the runtime tier in
  ## `dynamic.nim` to pick a code path from a stored value.
  SigFamily* = enum
    sfDilithium,
    sfFalcon,
    sfSphincs,
    sfEd25519

  ## A public/secret pair. `public` is safe to publish; `secret` must not
  ## leave the machine that made it.
  SigKeypair* = object
    family*: SigFamily
    public*: seq[byte]
    secret*: seq[byte]

proc familyName*(f: SigFamily): string =
  ## f: which signature family.
  ## Short stable text name, safe to store in a config or log line.
  case f
  of sfDilithium: result = "dilithium"
  of sfFalcon:    result = "falcon"
  of sfSphincs:   result = "sphincs"
  of sfEd25519:   result = "ed25519"

proc parseSigFamily*(s: string): SigFamily =
  ## s: a name produced by `familyName`.
  ## Turn stored text back into a family. Raises on anything unknown, so a
  ## damaged config can never silently select a different algorithm.
  case s
  of "dilithium": result = sfDilithium
  of "falcon":    result = sfFalcon
  of "sphincs":   result = sfSphincs
  of "ed25519":   result = sfEd25519
  else: raise newException(ValueError, "unknown signature family: " & s)
