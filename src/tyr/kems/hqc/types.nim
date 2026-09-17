## ---------------------------------------------------------------------
## | HQC Types <- the shapes HQC hands back, and its internal vector    |
## ---------------------------------------------------------------------
##
## Two shapes leave this package and two stay inside it.
##
## Leaving:
##
##   HqcTyrKeypair   public key to publish + secret key to keep
##   HqcTyrCipher    ciphertext to send    + shared secret to keep
##
## Staying inside:
##
##   HqcVec          one long bit string, packed 64 bits to a word
##   HqcPkeCipher    the ciphertext before the salt is attached
##
## Why a word and not a byte array. Every expensive HQC step is either a
## bitwise XOR of two long strings or a carry-less multiply of them. Both
## run 64 bits at a time on a 64-bit machine, so the strings are stored
## that way and only converted to bytes at the edges, where they go on
## the wire.

import runePragmas
import ./params

type
  ## One bit string of `n` bits, packed low bit first into 64-bit words.
  ##
  ##   bit 0  -> word 0, bit 0 (the LOWEST bit)
  ##   bit 63 -> word 0, bit 63
  ##   bit 64 -> word 1, bit 0
  ##
  ## Any bits above `n` inside the last word are kept at zero.
  HqcVec* = seq[uint64]

  ## The public-key-encryption half of a ciphertext, before the KEM
  ## wrapper attaches the salt.
  ##
  ##   u   n bits     the masked randomness
  ##   v   n1n2 bits  the masked codeword carrying the message
  HqcPkeCipher* {.expectedCount: [0, 2], lifeCycle: lcScratch.} = object
    u*: HqcVec
    v*: HqcVec

  ## Public/secret pair produced by the pure-Nim HQC backend.
  HqcTyrKeypair* {.expectedCount: [0, 64], lifeCycle: lcSession.} = object
    variant*: HqcVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Detached ciphertext plus the shared secret encapsulation produced.
  ## `ciphertext` goes on the wire; `sharedSecret` never does.
  HqcTyrCipher* {.expectedCount: [0, 64], lifeCycle: lcJob.} = object
    variant*: HqcVariant
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]
