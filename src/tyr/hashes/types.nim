## ---------------------------------------------------------------------
## | Hash Types <- naming the hash families and their digest sizes      |
## ---------------------------------------------------------------------
##
## A hash turns any amount of data into a short fixed-size fingerprint:
##
##   "hello world"  --[ hash ]-->  b94d27b9934d3e08...  (32 bytes)
##   "hello worle"  --[ hash ]-->  9f86d081884c7d65...  (completely different)
##
## One changed bit changes the whole fingerprint. Two different inputs
## producing the same fingerprint is called a collision, and for these
## families nobody knows how to find one.
##
## No key is involved. If you need a fingerprint only a key-holder can
## produce, that is a MAC - see `tyr/macs`.
##
## This file imports no algorithm, so a build using one hash does not drag
## in the rest.

type
  HashFamily* = enum
    hfBlake3,
    hfSha256,
    hfSha512,
    hfSha3

const
  ## Natural digest length in bytes for each family. BLAKE3 and SHA3 can
  ## also produce other lengths on request; these are their defaults.
  defaultDigestBytes*: array[HashFamily, int] = [32, 32, 64, 32]

proc familyName*(f: HashFamily): string =
  ## f: which hash family.
  case f
  of hfBlake3: result = "blake3"
  of hfSha256: result = "sha256"
  of hfSha512: result = "sha512"
  of hfSha3:   result = "sha3"

proc parseHashFamily*(s: string): HashFamily =
  ## s: a name produced by `familyName`. Raises on anything unknown.
  case s
  of "blake3": result = hfBlake3
  of "sha256": result = hfSha256
  of "sha512": result = hfSha512
  of "sha3":   result = hfSha3
  else: raise newException(ValueError, "unknown hash family: " & s)
