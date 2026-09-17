## ---------------------------------------------------------------------
## | HQC Reed-Muller <- the inner code that survives very noisy bits    |
## ---------------------------------------------------------------------
##
## What it does
## ------------
## One byte goes in, 128 bits come out, and those 128 bits are then
## repeated a few times to make n2 bits:
##
##   1 byte  ->  128-bit codeword  ->  repeated 3 times  = 384 bits (HQC-1)
##                                     repeated 5 times  = 640 bits (HQC-3/5)
##
## Spending 384 bits on 8 bits of message sounds wasteful, and it is
## exactly the point: about a third of those bits can be flipped and the
## original byte still comes back.
##
## How the 128 bits are chosen (RM(1,7))
## -------------------------------------
## Each of the eight message bits switches one fixed striped pattern on
## or off, and the codeword is all the switched-on stripes combined:
##
##   bit 0  ->  1010 1010 1010 ...   alternating every 1
##   bit 1  ->  1100 1100 1100 ...   alternating every 2
##   bit 2  ->  1111 0000 1111 ...   alternating every 4
##   ...
##   bit 6  ->  first half ones, second half zeros
##   bit 7  ->  all ones
##
## Two different bytes always differ in at least 64 of the 128 positions,
## which is why so much noise can be tolerated.
##
## How decoding works
## -------------------
## Add up the repeated copies, then run a Hadamard transform. The
## transform measures, for all 128 stripe patterns at once, how strongly
## the received bits agree with each one. The pattern with the largest
## reading wins, and its sign supplies the eighth bit.
##
## Reference: [HQC-20250822] duplicated Reed-Muller code RM(1,7); ported
## from the reference implementation's `reed_muller.c`, decoding after
## MacWilliams and Sloane, "The Theory of Error-Correcting Codes".

import runePragmas
import ./params
import ./masks
import ./types
import ./util

const
  rmCodewordBits = 128
  rmLanesPerCodeword = 4     ## 128 bits held as four 32-bit lanes
  rmMaxMultiplicity = 5      ## largest n2 / 128 across the parameter sets

type
  ## One received codeword with every bit widened to a signed number, so
  ## the repeated copies can be added up without overflowing.
  RmExpanded = array[rmCodewordBits, int32]

## Reference: [HQC-20250822] Reed-Muller encoding; single codeword construction for `rmEncodeByte`; pitfall: the four lanes are written out of order on purpose, because each is one exclusive-or away from the last.
proc rmEncodeByte(W: var array[rmLanesPerCodeword, uint32], msg: byte)
    {.role: {encryptor}, raises: [].} =
  ## W/msg: the four 32-bit lanes of one codeword, and the byte to encode.
  ##
  ## Bits 0 to 4 give stripes that repeat inside a single 32-bit lane, so
  ## all four lanes start from the same value. Bits 5 and 6 are what tell
  ## the lanes apart, and bit 7 flips everything.
  var
    lane: uint32 = 0
  lane = 0'u32 - (uint32(msg shr 7) and 1'u32)
  lane = lane xor ((0'u32 - (uint32(msg shr 0) and 1'u32)) and 0xaaaaaaaa'u32)
  lane = lane xor ((0'u32 - (uint32(msg shr 1) and 1'u32)) and 0xcccccccc'u32)
  lane = lane xor ((0'u32 - (uint32(msg shr 2) and 1'u32)) and 0xf0f0f0f0'u32)
  lane = lane xor ((0'u32 - (uint32(msg shr 3) and 1'u32)) and 0xff00ff00'u32)
  lane = lane xor ((0'u32 - (uint32(msg shr 4) and 1'u32)) and 0xffff0000'u32)
  W[0] = lane
  lane = lane xor (0'u32 - (uint32(msg shr 5) and 1'u32))
  W[1] = lane
  lane = lane xor (0'u32 - (uint32(msg shr 6) and 1'u32))
  W[3] = lane
  lane = lane xor (0'u32 - (uint32(msg shr 5) and 1'u32))
  W[2] = lane

## Reference: [HQC-20250822] Reed-Muller decoding; fast Hadamard transform for `hadamard`; pitfall: seven passes with the buffers swapped each time leave the answer in `dst`.
proc hadamard(src: var RmExpanded, dst: var RmExpanded)
    {.role: {math}, raises: [].} =
  ## src/dst: the expanded codeword (destroyed) and the transform.
  ##
  ## Each pass pairs neighbouring entries into their sum and their
  ## difference. Seven passes cover 2^7 = 128 entries, and because the
  ## count is odd the final answer lands in `dst`.
  var
    a = default(RmExpanded)
    b = default(RmExpanded)
    pass: int = 0
    i: int = 0
  a = src
  pass = 0
  while pass < 7:
    i = 0
    while i < 64:
      b[i] = a[2 * i] + a[2 * i + 1]
      b[i + 64] = a[2 * i] - a[2 * i + 1]
      i = i + 1
    a = b
    pass = pass + 1
  dst = a

## Reference: [HQC-20250822] Reed-Muller decoding; copy accumulation for `expandAndSum`; pitfall: the copies are added as 0/1 rather than -1/+1, which shifts the first transform entry and is corrected afterwards.
proc expandAndSum(dst: var RmExpanded, V: openArray[uint64], base, multiplicity: int)
    {.role: {parser}, raises: [].} =
  ## dst/V/base/multiplicity: the widened sum, the received bit string,
  ## which codeword to start at, and how many copies follow it.
  ## Add the repeated copies of one codeword together, bit by bit.
  var
    copyIdx: int = 0
    part: int = 0
    bit: int = 0
    lane: uint32 = 0
  copyIdx = 0
  while copyIdx < multiplicity:
    part = 0
    while part < rmLanesPerCodeword:
      lane = hqcGetU32(V, (base + copyIdx) * rmLanesPerCodeword + part)
      bit = 0
      while bit < 32:
        if copyIdx == 0:
          dst[part * 32 + bit] = int32((lane shr bit) and 1'u32)
        else:
          dst[part * 32 + bit] = dst[part * 32 + bit] +
            int32((lane shr bit) and 1'u32)
        bit = bit + 1
      part = part + 1
    copyIdx = copyIdx + 1

## Reference: [HQC-20250822] Reed-Muller decoding; peak selection for `findPeak`; pitfall: every comparison is masked, and ties must keep the lowest position.
proc findPeak(T: RmExpanded): byte {.role: {parser}, raises: [].} =
  ## T: the Hadamard transform of one received codeword.
  ## Return the message byte: the position of the largest reading, plus
  ## 128 when that reading was positive.
  ##
  ## The position supplies the low seven bits, because the transform is
  ## indexed by stripe pattern. The sign supplies bit 7, because flipping
  ## every bit of a codeword flips the sign of its reading.
  var
    peakAbs: int32 = 0
    peakValue: int32 = 0
    peakPos: int32 = 0
    t: int32 = 0
    absolute: int32 = 0
    signMask: int32 = 0
    gtMask: int32 = 0
    i: int = 0
  i = 0
  while i < rmCodewordBits:
    t = T[i]
    signMask = cast[int32](0'u32 - (cast[uint32](t) shr 31))
    absolute = ((not signMask) and t) or (signMask and (0'i32 - t))
    gtMask = cast[int32](maskLess32(cast[uint32](peakAbs), cast[uint32](absolute)))
    peakValue = (t and gtMask) or (peakValue and not gtMask)
    peakPos = (int32(i) and gtMask) or (peakPos and not gtMask)
    peakAbs = (absolute and gtMask) or (peakAbs and not gtMask)
    i = i + 1
  signMask = cast[int32](0'u32 - (cast[uint32](peakValue) shr 31))
  gtMask = (not signMask) and cast[int32](maskNonZero32(cast[uint32](peakValue)))
  peakPos = peakPos or (128'i32 and gtMask)
  result = byte(peakPos and 0xff'i32)

## Reference: [HQC-20250822] duplicated Reed-Muller encoding; message expansion for `reedMullerEncode`; pitfall: the repeats are identical copies, not independent encodings.
proc reedMullerEncode*(cdw: var HqcVec, msg: openArray[byte], p: HqcParams)
    {.role: {encryptor}, raises: [].} =
  ## cdw/msg/p: the n1n2-bit codeword, the n1 message bytes, the parameters.
  ## Encode each message byte and repeat it `multiplicity` times.
  var
    word = default(array[rmLanesPerCodeword, uint32])
    i: int = 0
    copyIdx: int = 0
    part: int = 0
    base: int = 0
  i = 0
  while i < p.n1:
    base = i * p.multiplicity
    rmEncodeByte(word, msg[i])
    copyIdx = 0
    while copyIdx < p.multiplicity:
      part = 0
      while part < rmLanesPerCodeword:
        hqcSetU32(cdw, (base + copyIdx) * rmLanesPerCodeword + part, word[part])
        part = part + 1
      copyIdx = copyIdx + 1
    i = i + 1

## Reference: [HQC-20250822] duplicated Reed-Muller decoding; transform decoding for `reedMullerDecode`; pitfall: the first transform entry carries a fixed offset that must be removed before the peak search.
proc reedMullerDecode*(msg: var openArray[byte], cdw: HqcVec, p: HqcParams)
    {.role: {decryptor}, raises: [].} =
  ## msg/cdw/p: the n1 recovered bytes, the received bit string, the parameters.
  ## Turn every noisy block back into its most likely message byte.
  var
    expanded = default(RmExpanded)
    transform = default(RmExpanded)
    i: int = 0
  i = 0
  while i < p.n1:
    expandAndSum(expanded, cdw, i * p.multiplicity, p.multiplicity)
    hadamard(expanded, transform)
    ## The copies were summed as 0/1 instead of -1/+1, which leaves entry
    ## zero too high by exactly 64 per copy. Take that back off.
    transform[0] = transform[0] - int32(64 * p.multiplicity)
    msg[i] = findPeak(transform)
    i = i + 1

## Keep the maximum in sight for anyone sizing a buffer by hand.
static:
  doAssert rmMaxMultiplicity * rmCodewordBits >= 640

