## ---------------------------------------------------------------------
## | KEM Types <- the key material every KEM family hands back          |
## | keypair -> (public, secret)   encapsulate -> (ciphertext, secret)  |
## ---------------------------------------------------------------------
##
## What a KEM is, in one picture
## -----------------------------
## KEM is short for "key encapsulation mechanism". It is the machine two
## parties use to agree on one shared secret without ever sending it:
##
##   Alice                                        Bob
##   -----                                        ---
##   keypair()  -> public, secret
##        public  ------------------------------>
##                                    encapsulate(public)
##                                      -> ciphertext, sharedSecret
##        <------------------------------  ciphertext
##   decapsulate(secret, ciphertext)
##     -> the SAME sharedSecret
##
## Both sides end up holding identical bytes. Nobody watching the wire can
## work out what those bytes are.
##
## This file holds only the shapes of that material. It deliberately imports
## no algorithm, so a build that uses one KEM does not drag in the rest.

type
  ## Which family produced the material. Used by the runtime tier in
  ## `dynamic.nim` to pick a code path from a stored value.
  KemFamily* = enum
    kfKyber,
    kfMcEliece,
    kfFrodo,
    kfBike,
    kfNtru,
    kfSaber,
    kfHqc

  ## A public/secret pair. `public` is safe to publish; `secret` never
  ## leaves the machine that made it.
  KemKeypair* = object
    family*: KemFamily
    public*: seq[byte]
    secret*: seq[byte]

  ## The result of encapsulating against someone's public key.
  ## `ciphertext` is what you send them; `shared` is what you keep.
  KemCiphertext* = object
    family*: KemFamily
    ciphertext*: seq[byte]
    shared*: seq[byte]

proc familyName*(f: KemFamily): string =
  ## f: which KEM family.
  ## Short stable text name, safe to store in a config or log line.
  case f
  of kfKyber:    result = "kyber"
  of kfMcEliece: result = "mceliece"
  of kfFrodo:    result = "frodo"
  of kfBike:     result = "bike"
  of kfNtru:     result = "ntru"
  of kfSaber:    result = "saber"
  of kfHqc:      result = "hqc"

proc parseKemFamily*(s: string): KemFamily =
  ## s: a name produced by `familyName`.
  ## Turn stored text back into a family. Raises on anything unknown, so a
  ## damaged config can never silently select a different algorithm.
  case s
  of "kyber":    result = kfKyber
  of "mceliece": result = kfMcEliece
  of "frodo":    result = kfFrodo
  of "bike":     result = kfBike
  of "ntru":     result = kfNtru
  of "saber":    result = kfSaber
  of "hqc":      result = kfHqc
  else: raise newException(ValueError, "unknown KEM family: " & s)
