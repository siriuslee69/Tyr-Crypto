## ---------------------------------------------------------------------
## | HQC Vector <- picking exactly w bit positions out of n, at random  |
## ---------------------------------------------------------------------
##
## Why this is fiddly
## ------------------
## HQC needs bit strings with an exact number of 1-bits - 66 of them out
## of 17669, say. Picking 66 positions at random is easy; picking them
## without bias, without repeats, and without letting the running time
## reveal which ones were picked is not.
##
## Two different methods are used, on purpose:
##
##   sampleFixedWeightKey   key generation. Draws 24-bit numbers, throws
##                          away any that would bias the result, and
##                          rejects repeats. Unbiased; the number of
##                          draws depends on luck.
##
##   sampleFixedWeightEnc   encryption. Draws a fixed number of values
##                          and then repairs repeats in place. Always the
##                          same number of draws; a vanishingly small
##                          bias is accepted in exchange.
##
## Encryption uses the second because it runs on data an attacker can
## influence, so a fixed amount of work matters more there. Key
## generation uses the first because an unbiased secret matters more.
##
## Turning positions into bits
## ---------------------------
## Once the positions are chosen they are written into the bit string
## without ever indexing memory by a secret. Every output word is
## compared against every chosen position, and a mask decides whether
## anything lands there:
##
##   for each output word i:
##     for each chosen position j:
##       word i gets bit_tab[j], but only if index_tab[j] equals i
##
## That is w*n/64 comparisons instead of w stores, and it leaves no trace
## in the memory access pattern.
##
## Reference: [HQC-20250822] fixed-weight vector sampling; ported from the
## reference implementation's `vector.c`. The encryption sampler is
## Algorithm 5 of https://eprint.iacr.org/2021/1631.

import runePragmas
import ./params
import ./types
import ./masks
import ./symmetric
import ./util

## Reference: [HQC-20250822] uniform sampling below n; Barrett reduction for `barrettReduce`; pitfall: the precomputed multiplier belongs to one parameter set, so it must come from the same record as n.
proc barrettReduce(x: uint32, p: HqcParams): uint32
    {.role: {math}, raises: [].} =
  ## x/p: the value to reduce and the parameter set.
  ## Return `x mod n` without dividing, and without branching.
  ##
  ## Multiplying by the stored floor(2^32 / n) and shifting back down
  ## gives the quotient, give or take one. The last line takes that one
  ## off again when it was there.
  var
    q: uint64 = 0
    r: uint32 = 0
    reduceFlag: uint32 = 0
    mask: uint32 = 0
  q = (uint64(x) * p.barrettMu) shr 32
  r = x - uint32(q * uint64(p.n))
  reduceFlag = ((r - uint32(p.n)) shr 31) xor 1'u32
  mask = 0'u32 - reduceFlag
  result = r - (mask and uint32(p.n))

## Reference: [HQC-20250822] GenerateRandomSupport for key generation; unbiased rejection sampling for `generateRandomSupportKey`; pitfall: the loop length depends on the draws, which is accepted here and only here.
proc generateRandomSupportKey(S: var openArray[uint32], X: var HqcXof,
    weight: int, p: HqcParams) {.role: {dataFetcher}, raises: [].} =
  ## S/X/weight/p: the chosen positions, the random stream, how many are
  ## wanted, and the parameter set.
  ##
  ## Draw a 24-bit number, throw it away if it is large enough to bias
  ## the remainder, fold the rest down to the range 0..n-1, and keep it
  ## if it is new. Repeat until `weight` positions have been collected.
  var
    randBytes = default(array[3, byte])
    candidate: uint32 = 0
    available: bool = false
    i: int = 0
    j: int = 0
  i = 0
  while i < weight:
    xofBytes(X, randBytes, 0, 3)
    candidate = uint32(randBytes[0]) or (uint32(randBytes[1]) shl 8) or
      (uint32(randBytes[2]) shl 16)
    if candidate >= p.rejectThreshold:
      continue
    candidate = barrettReduce(candidate, p)
    available = true
    j = 0
    while j < i:
      if candidate == S[j]:
        available = false
        break
      j = j + 1
    if available:
      S[i] = candidate
      i = i + 1

## Reference: [HQC-20250822] GenerateRandomSupport for encryption, Algorithm 5 of eprint 2021/1631; fixed-cost sampling for `generateRandomSupportEnc`; pitfall: the repair pass must run from the second-to-last position downwards, never upwards.
proc generateRandomSupportEnc(S: var openArray[uint32], X: var HqcXof,
    weight: int, p: HqcParams) {.role: {dataFetcher}, raises: [].} =
  ## S/X/weight/p: the chosen positions, the random stream, how many are
  ## wanted, and the parameter set.
  ##
  ## Position i is drawn from the shrinking range i .. n-1, which already
  ## keeps the positions apart most of the time. The second pass repairs
  ## the rest: if position i also appears later on, it is replaced by i
  ## itself, which nothing later can be using.
  var
    randU32 = default(array[hqcMaxOmegaR, uint32])
    randBytes = default(array[4 * hqcMaxOmegaR, byte])
    buff: uint64 = 0
    found: uint32 = 0
    mask: uint32 = 0
    i: int = 0
    j: int = 0
  xofBytes(X, randBytes, 0, 4 * weight)
  i = 0
  while i < weight:
    randU32[i] = uint32(randBytes[4 * i]) or
      (uint32(randBytes[4 * i + 1]) shl 8) or
      (uint32(randBytes[4 * i + 2]) shl 16) or
      (uint32(randBytes[4 * i + 3]) shl 24)
    i = i + 1
  i = 0
  while i < weight:
    buff = uint64(randU32[i])
    S[i] = uint32(i) + uint32((buff * uint64(p.n - i)) shr 32)
    i = i + 1
  i = weight - 2
  while i >= 0:
    found = 0
    j = i + 1
    while j < weight:
      found = found or (maskEqual32(S[j], S[i]) and 1'u32)
      j = j + 1
    mask = 0'u32 - found
    S[i] = (mask and uint32(i)) xor ((not mask) and S[i])
    i = i - 1
  hqcWipeBytes(randBytes)
  hqcWipeU32(randU32)

## Reference: [HQC-20250822] support-to-vector conversion; branch-free bit placement for `writeSupportToVector`; pitfall: the destination is ORed into, so it must start out zero.
proc writeSupportToVector(V: var HqcVec, S: openArray[uint32], weight: int,
    p: HqcParams) {.role: {truthBuilder}, raises: [].} =
  ## V/S/weight/p: the bit string to fill, the chosen positions, how many,
  ## and the parameter set.
  ## Set one bit per chosen position, without ever indexing by a secret.
  var
    indexTab = default(array[hqcMaxOmegaR, uint32])
    bitTab = default(array[hqcMaxOmegaR, uint64])
    val: uint64 = 0
    mask: uint64 = 0
    i: int = 0
    j: int = 0
  i = 0
  while i < weight:
    indexTab[i] = S[i] shr 6
    bitTab[i] = 1'u64 shl int(S[i] and 0x3f'u32)
    i = i + 1
  i = 0
  while i < p.vecNWords:
    val = 0'u64
    j = 0
    while j < weight:
      mask = uint64(maskEqual32(uint32(i), indexTab[j]))
      mask = mask or (mask shl 32)
      val = val or (bitTab[j] and mask)
      j = j + 1
    V[i] = V[i] or val
    i = i + 1
  hqcWipeWords(bitTab)
  hqcWipeU32(indexTab)

## Reference: [HQC-20250822] fixed-weight sampling for key generation; unbiased sampler for `sampleFixedWeightKey`; pitfall: only key generation may use this sampler.
proc sampleFixedWeightKey*(V: var HqcVec, X: var HqcXof, weight: int,
    p: HqcParams) {.role: {dataFetcher}, raises: [].} =
  ## V/X/weight/p: the bit string to fill, the random stream, how many
  ## 1-bits are wanted, and the parameter set.
  ## Build a bit string with exactly `weight` bits set, without bias.
  var
    support = default(array[hqcMaxOmegaR, uint32])
  generateRandomSupportKey(support, X, weight, p)
  writeSupportToVector(V, support, weight, p)
  hqcWipeU32(support)

## Reference: [HQC-20250822] fixed-weight sampling for encryption; fixed-cost sampler for `sampleFixedWeightEnc`; pitfall: only encryption may use this sampler.
proc sampleFixedWeightEnc*(V: var HqcVec, X: var HqcXof, weight: int,
    p: HqcParams) {.role: {dataFetcher}, raises: [].} =
  ## V/X/weight/p: the bit string to fill, the random stream, how many
  ## 1-bits are wanted, and the parameter set.
  ## Build a bit string with exactly `weight` bits set, at fixed cost.
  ## The positions are r1, r2 or e of one encryption; anyone holding them
  ## can strip the noise and read the message, so they are wiped too.
  var
    support = default(array[hqcMaxOmegaR, uint32])
  generateRandomSupportEnc(support, X, weight, p)
  writeSupportToVector(V, support, weight, p)
  hqcWipeU32(support)

## Reference: [HQC-20250822] uniform vector generation; public-key expansion for `vecSetRandom`; pitfall: the bits above n must be cleared, or the public key stops round-tripping.
proc vecSetRandom*(V: var HqcVec, X: var HqcXof, p: HqcParams)
    {.role: {dataFetcher}, raises: [].} =
  ## V/X/p: the bit string to fill, the random stream, the parameter set.
  ## Fill the whole bit string with stream bytes and clear the spare bits
  ## in the last word.
  var
    bytes: seq[byte] = @[]
    i: int = 0
  bytes = newSeq[byte](p.vecNBytes)
  xofBytes(X, bytes, 0, p.vecNBytes)
  i = 0
  while i < p.vecNWords:
    V[i] = 0'u64
    i = i + 1
  hqcBytesToWords(V, bytes, 0, p.vecNBytes)
  V[p.vecNWords - 1] = V[p.vecNWords - 1] and
    ((1'u64 shl (p.n and 63)) - 1'u64)
  hqcWipeBytes(bytes)

