## ---------------------------------------------------------------------
## | HQC Symmetric <- the one random stream and the four hashes         |
## ---------------------------------------------------------------------
##
## HQC uses SHAKE-256 for everything that has to look random, and SHA3
## for everything that has to be a fixed-size fingerprint. Each use is
## given its own trailing tag byte so that two different uses can never
## produce the same output even from the same input:
##
##   tag   used by         what it does
##   ----  --------------  ----------------------------------------
##    0    G               shared secret and encryption randomness
##    1    H               fingerprint of the public key
##    1    XOF             the stretched random stream
##    2    I               splits one seed into two
##    3    J               the rejection key
##
## The tag is appended AFTER the input, never before, and the tag values
## for H and XOF are allowed to coincide because one is SHA3-256 and the
## other is SHAKE-256 - different functions entirely.
##
## The stream
## ----------
## `HqcXof` stretches a 32-byte seed into as many bytes as asked for, and
## remembers where it stopped. Asking for 3 bytes a hundred times gives
## exactly the same 300 bytes as asking for 300 at once, which is what
## makes the sampling reproducible:
##
##   seed -> SHAKE-256 -> [block 0][block 1][block 2]...
##                          ^
##                          `pos` walks along and refills when it runs out
##
## Reference: [HQC-20250822] symmetric primitives and domain separation;
## ported from the reference implementation's `symmetric.c`.

import runePragmas
import ../../hashes/sha3
import ./params

const
  hqcXofDomain* = 1'u8    ## trailing tag for the stretched random stream
  hqcGDomain* = 0'u8      ## trailing tag for G
  hqcHDomain* = 1'u8      ## trailing tag for H
  hqcIDomain* = 2'u8      ## trailing tag for I
  hqcJDomain* = 3'u8      ## trailing tag for J

type
  ## A seeded SHAKE-256 stream that remembers how far it has been read.
  HqcXof* {.expectedCount: [0, 4], lifeCycle: lcScratch.} = object
    state: Sha3State
    buf: array[shake256RateBytes, byte]
    pos: int

## Reference: [HQC-20250822] stretched random stream; stream start for `xofInit`; pitfall: the tag byte belongs after the seed, and the seed is always exactly 32 bytes.
proc xofInit*(X: var HqcXof, seed: openArray[byte])
    {.role: {helper}, raises: [ValueError].} =
  ## X/seed: the stream to start, and the 32-byte seed to start it from.
  var
    input = default(array[hqcSeedBytes + 1, byte])
    i: int = 0
  if seed.len != hqcSeedBytes:
    raise newException(ValueError, "HQC XOF seed must be 32 bytes")
  while i < hqcSeedBytes:
    input[i] = seed[i]
    i = i + 1
  input[hqcSeedBytes] = hqcXofDomain
  shake256AbsorbOnce(X.state, input)
  shake256SqueezeBlocksIntoUnchecked(X.state, X.buf)
  X.pos = 0

## Reference: [HQC-20250822] stretched random stream; stream read for `xofBytes`; pitfall: reads must continue where the last one stopped, not restart at a block edge.
proc xofBytes*(X: var HqcXof, dst: var openArray[byte], o, count: int)
    {.role: {dataFetcher}, raises: [].} =
  ## X/dst/o/count: the stream, the destination, where to write, how much.
  ## Take the next `count` bytes off the stream.
  var
    produced: int = 0
    take: int = 0
    i: int = 0
  while produced < count:
    if X.pos == shake256RateBytes:
      shake256SqueezeBlocksIntoUnchecked(X.state, X.buf)
      X.pos = 0
    take = shake256RateBytes - X.pos
    if take > count - produced:
      take = count - produced
    i = 0
    while i < take:
      dst[o + produced + i] = X.buf[X.pos + i]
      i = i + 1
    X.pos = X.pos + take
    produced = produced + take

## Reference: [HQC-20250822] stretched random stream; stream wiping for `xofClear`; pitfall: the sponge state and the pending block both hold key-derived material.
proc xofClear*(X: var HqcXof) {.role: {helper}, raises: [].} =
  ## X: the stream to forget.
  ## Erase the sponge state and the block still waiting to be read.
  var
    i: int = 0
  while i < X.state.len:
    X.state[i] = 0'u64
    i = i + 1
  i = 0
  while i < X.buf.len:
    X.buf[i] = 0'u8
    i = i + 1
  X.pos = 0

## Reference: [HQC-20250822] hash function I; seed splitting for `hashI`; pitfall: the 64 bytes out are two independent 32-byte seeds, in that order.
proc hashI*(dst: var openArray[byte], seed: openArray[byte])
    {.role: {helper}, raises: [ValueError].} =
  ## dst/seed: 64 bytes out, one 32-byte seed in.
  ## Split one seed into the decryption seed and the encryption seed.
  var
    input = default(array[hqcSeedBytes + 1, byte])
    i: int = 0
  if seed.len != hqcSeedBytes:
    raise newException(ValueError, "HQC hash I seed must be 32 bytes")
  while i < hqcSeedBytes:
    input[i] = seed[i]
    i = i + 1
  input[hqcSeedBytes] = hqcIDomain
  sha3_512Into(dst, input)

## Reference: [HQC-20250822] hash function H; public-key fingerprint for `hashH`; pitfall: the whole encapsulation key is absorbed, seed bytes included.
proc hashH*(dst: var openArray[byte], ek: openArray[byte])
    {.role: {helper}, raises: [ValueError].} =
  ## dst/ek: 32 bytes out, the whole public key in.
  ## Fingerprint the public key, so later hashes can name it cheaply.
  var
    input: seq[byte] = @[]
    i: int = 0
  input = newSeq[byte](ek.len + 1)
  while i < ek.len:
    input[i] = ek[i]
    i = i + 1
  input[ek.len] = hqcHDomain
  sha3_256Into(dst, input)

## Reference: [HQC-20250822] hash function G; shared secret and encryption randomness for `hashG`; pitfall: the four pieces are absorbed in this exact order, and the first 32 bytes out are the shared secret.
proc hashG*(dst: var openArray[byte], hEk, m, salt: openArray[byte])
    {.role: {helper}, raises: [ValueError].} =
  ## dst/hEk/m/salt: 64 bytes out; the public key fingerprint, the
  ## message, and the salt in.
  ##
  ## The 64 bytes out are read as two halves:
  ##
  ##   [0 .. 31]   the shared secret K
  ##   [32 .. 63]  theta, the seed that drives encryption
  var
    input: seq[byte] = @[]
    o: int = 0
    i: int = 0
  input = newSeq[byte](hEk.len + m.len + salt.len + 1)
  while i < hEk.len:
    input[o + i] = hEk[i]
    i = i + 1
  o = o + hEk.len
  i = 0
  while i < m.len:
    input[o + i] = m[i]
    i = i + 1
  o = o + m.len
  i = 0
  while i < salt.len:
    input[o + i] = salt[i]
    i = i + 1
  input[input.len - 1] = hqcGDomain
  sha3_512Into(dst, input)

## Reference: [HQC-20250822] hash function J; rejection key for `hashJ`; pitfall: the ciphertext is absorbed as u then v then salt, and sigma is the secret that makes the result unguessable.
proc hashJ*(dst: var openArray[byte], hEk, sigma, u, v, salt: openArray[byte])
    {.role: {helper}, raises: [ValueError].} =
  ## dst/hEk/sigma/u/v/salt: 32 bytes out; the public key fingerprint, the
  ## secret rejection value, the two ciphertext halves, and the salt in.
  ## Produce the key handed back when a ciphertext turns out to be wrong.
  var
    input: seq[byte] = @[]
    o: int = 0
    i: int = 0
  input = newSeq[byte](hEk.len + sigma.len + u.len + v.len + salt.len + 1)
  while i < hEk.len:
    input[o + i] = hEk[i]
    i = i + 1
  o = o + hEk.len
  i = 0
  while i < sigma.len:
    input[o + i] = sigma[i]
    i = i + 1
  o = o + sigma.len
  i = 0
  while i < u.len:
    input[o + i] = u[i]
    i = i + 1
  o = o + u.len
  i = 0
  while i < v.len:
    input[o + i] = v[i]
    i = i + 1
  o = o + v.len
  i = 0
  while i < salt.len:
    input[o + i] = salt[i]
    i = i + 1
  input[input.len - 1] = hqcJDomain
  sha3_256Into(dst, input)

