## -------------------------------------------------------------------------
## Argon2 SIMD <- packed round/xor helpers for the local Argon2 implementation
## -> Uses SIMD-Nexus for portable 64-bit packed xor/add/rotate operations
## -> Keeps scalar per-lane BlaMka multiplication where SIMD-Nexus has no u64 mul
## -------------------------------------------------------------------------

import simd_nexus/simd/[base_operations, generic_u64]

const
  argon2SimdQwords = 128
  argon2RowBatchOffsets = [0, 1, 16, 17, 32, 33, 48, 49, 64, 65, 80, 81, 96, 97, 112, 113]


when defined(neon) or defined(arm64) or defined(aarch64):
  proc loadLaneVec(vals: array[2, uint64]): uint64x2 {.inline.} =
    result = loadU64x2[uint64x2](vals)

  proc storeLaneVec(v: uint64x2): array[2, uint64] {.inline.} =
    result = storeU64x2(v)
else:
  proc loadLaneVec(vals: array[2, uint64]): u64x2 {.inline.} =
    result = loadU64x2[u64x2](vals)

  proc storeLaneVec(v: u64x2): array[2, uint64] {.inline.} =
    result = storeU64x2(v)

when defined(avx2):
  proc loadLaneVec(vals: array[4, uint64]): u64x4 {.inline.} =
    result = loadU64x4[u64x4](vals)

  proc storeLaneVec(v: u64x4): array[4, uint64] {.inline.} =
    result = storeU64x4(v)


proc validateBlock(A: openArray[uint64]) =
  ## A: block words to validate.
  if A.len != argon2SimdQwords:
    raise newException(ValueError, "Argon2 SIMD block helpers require 128 words")


proc copyBlock(D: var openArray[uint64], A: openArray[uint64]) =
  ## D: destination block words.
  ## A: source block words.
  var
    i: int = 0
  validateBlock(D)
  validateBlock(A)
  i = 0
  while i < argon2SimdQwords:
    D[i] = A[i]
    i = i + 1


proc packLaneVals[T: SimdU64](vals: array[lanesU64[T](), uint64]): T {.inline.} =
  when T is u64x4:
    result = loadLaneVec(vals)
  elif T is uint64x2:
    result = loadLaneVec(vals)
  else:
    result = loadLaneVec(vals)


proc unpackLaneVals[T: SimdU64](v: T): array[lanesU64[T](), uint64] {.inline.} =
  when T is u64x4:
    result = storeLaneVec(v)
  elif T is uint64x2:
    result = storeLaneVec(v)
  else:
    result = storeLaneVec(v)


proc packOffsets[T: SimdU64](A: openArray[uint64],
    offsets: array[lanesU64[T](), int]): T {.inline.} =
  const lanes = lanesU64[T]()
  var
    vals: array[lanes, uint64]
    lane: int = 0
  lane = 0
  while lane < lanes:
    vals[lane] = A[offsets[lane]]
    lane = lane + 1
  result = packLaneVals[T](vals)


proc unpackOffsets[T: SimdU64](A: var openArray[uint64],
    offsets: array[lanesU64[T](), int], v: T) {.inline.} =
  const lanes = lanesU64[T]()
  var
    vals: array[lanes, uint64]
    lane: int = 0
  vals = unpackLaneVals(v)
  lane = 0
  while lane < lanes:
    A[offsets[lane]] = vals[lane]
    lane = lane + 1


proc blaMkaVec[T: SimdU64](A, B: T): T {.inline.} =
  const lanes = lanesU64[T]()
  var
    aVals: array[lanes, uint64]
    bVals: array[lanes, uint64]
    rVals: array[lanes, uint64]
    lane: int = 0
  aVals = unpackLaneVals(A)
  bVals = unpackLaneVals(B)
  lane = 0
  while lane < lanes:
    rVals[lane] = aVals[lane] + bVals[lane] +
      (((aVals[lane] and 0xffffffff'u64) * (bVals[lane] and 0xffffffff'u64)) shl 1)
    lane = lane + 1
  result = packLaneVals[T](rVals)


template argon2GVec(A, B, C, D: untyped) =
  A = blaMkaVec(A, B)
  D = rotr64(D xor A, 32)
  C = blaMkaVec(C, D)
  B = rotr64(B xor C, 24)
  A = blaMkaVec(A, B)
  D = rotr64(D xor A, 16)
  C = blaMkaVec(C, D)
  B = rotr64(B xor C, 63)


proc applyColumnBatch[T: SimdU64](A: var openArray[uint64], groupBase: int) =
  const lanes = lanesU64[T]()
  var
    V: array[16, T]
    offsets: array[lanes, int]
    slot: int = 0
    lane: int = 0
  slot = 0
  while slot < 16:
    lane = 0
    while lane < lanes:
      offsets[lane] = 16 * (groupBase + lane) + slot
      lane = lane + 1
    V[slot] = packOffsets[T](A, offsets)
    slot = slot + 1
  argon2GVec(V[0], V[4], V[8], V[12])
  argon2GVec(V[1], V[5], V[9], V[13])
  argon2GVec(V[2], V[6], V[10], V[14])
  argon2GVec(V[3], V[7], V[11], V[15])
  argon2GVec(V[0], V[5], V[10], V[15])
  argon2GVec(V[1], V[6], V[11], V[12])
  argon2GVec(V[2], V[7], V[8], V[13])
  argon2GVec(V[3], V[4], V[9], V[14])
  slot = 0
  while slot < 16:
    lane = 0
    while lane < lanes:
      offsets[lane] = 16 * (groupBase + lane) + slot
      lane = lane + 1
    unpackOffsets[T](A, offsets, V[slot])
    slot = slot + 1


proc applyRowBatch[T: SimdU64](A: var openArray[uint64], rowBase: int) =
  const lanes = lanesU64[T]()
  var
    V: array[16, T]
    offsets: array[lanes, int]
    slot: int = 0
    lane: int = 0
  slot = 0
  while slot < 16:
    lane = 0
    while lane < lanes:
      offsets[lane] = 2 * (rowBase + lane) + argon2RowBatchOffsets[slot]
      lane = lane + 1
    V[slot] = packOffsets[T](A, offsets)
    slot = slot + 1
  argon2GVec(V[0], V[4], V[8], V[12])
  argon2GVec(V[1], V[5], V[9], V[13])
  argon2GVec(V[2], V[6], V[10], V[14])
  argon2GVec(V[3], V[7], V[11], V[15])
  argon2GVec(V[0], V[5], V[10], V[15])
  argon2GVec(V[1], V[6], V[11], V[12])
  argon2GVec(V[2], V[7], V[8], V[13])
  argon2GVec(V[3], V[4], V[9], V[14])
  slot = 0
  while slot < 16:
    lane = 0
    while lane < lanes:
      offsets[lane] = 2 * (rowBase + lane) + argon2RowBatchOffsets[slot]
      lane = lane + 1
    unpackOffsets[T](A, offsets, V[slot])
    slot = slot + 1


proc applyArgon2RoundsPacked[T: SimdU64](A: var openArray[uint64]) =
  ## A: Argon2 block words to permute in place.
  const lanes = lanesU64[T]()
  var
    groupBase: int = 0
    rowBase: int = 0
  validateBlock(A)
  groupBase = 0
  while groupBase < 8:
    applyColumnBatch[T](A, groupBase)
    groupBase = groupBase + lanes
  rowBase = 0
  while rowBase < 8:
    applyRowBatch[T](A, rowBase)
    rowBase = rowBase + lanes


proc xorBlocksPacked[T: SimdU64](D: var openArray[uint64], A,
    B: openArray[uint64]) =
  ## D: destination block words.
  ## A: left source block words.
  ## B: right source block words.
  const lanes = lanesU64[T]()
  var
    offsets: array[lanes, int]
    lane: int = 0
    i: int = 0
    v: T
  validateBlock(D)
  validateBlock(A)
  validateBlock(B)
  i = 0
  while i < argon2SimdQwords:
    lane = 0
    while lane < lanes:
      offsets[lane] = i + lane
      lane = lane + 1
    v = packOffsets[T](A, offsets) xor packOffsets[T](B, offsets)
    unpackOffsets[T](D, offsets, v)
    i = i + lanes


proc xorIntoPacked[T: SimdU64](D: var openArray[uint64], A: openArray[uint64]) =
  ## D: destination block words to xor into.
  ## A: source block words.
  const lanes = lanesU64[T]()
  var
    offsets: array[lanes, int]
    lane: int = 0
    i: int = 0
    v: T
  validateBlock(D)
  validateBlock(A)
  i = 0
  while i < argon2SimdQwords:
    lane = 0
    while lane < lanes:
      offsets[lane] = i + lane
      lane = lane + 1
    v = packOffsets[T](D, offsets) xor packOffsets[T](A, offsets)
    unpackOffsets[T](D, offsets, v)
    i = i + lanes


when defined(sse2):
  proc applyArgon2RoundsSse2x*(A: var openArray[uint64]) =
    ## A: Argon2 block words to permute with SSE2-width packed lanes.
    applyArgon2RoundsPacked[u64x2](A)

  proc fillArgon2BlockSse2x*(prevBlock, refBlock: openArray[uint64],
      outBlock: var openArray[uint64]) =
    ## prevBlock: previous lane block.
    ## refBlock: referenced block.
    ## outBlock: destination block.
    var
      blockR: array[argon2SimdQwords, uint64]
    xorBlocksPacked[u64x2](blockR, refBlock, prevBlock)
    copyBlock(outBlock, blockR)
    applyArgon2RoundsPacked[u64x2](blockR)
    xorIntoPacked[u64x2](outBlock, blockR)

  proc fillArgon2BlockWithXorSse2x*(prevBlock, refBlock,
      nextBlock: openArray[uint64], outBlock: var openArray[uint64]) =
    ## prevBlock: previous lane block.
    ## refBlock: referenced block.
    ## nextBlock: existing destination block for pass>0 xor mode.
    ## outBlock: destination block.
    var
      blockR: array[argon2SimdQwords, uint64]
    xorBlocksPacked[u64x2](blockR, refBlock, prevBlock)
    copyBlock(outBlock, blockR)
    xorIntoPacked[u64x2](outBlock, nextBlock)
    applyArgon2RoundsPacked[u64x2](blockR)
    xorIntoPacked[u64x2](outBlock, blockR)


when defined(neon) or defined(arm64) or defined(aarch64):
  proc applyArgon2RoundsNeon2x*(A: var openArray[uint64]) =
    ## A: Argon2 block words to permute with NEON-width packed lanes.
    applyArgon2RoundsPacked[uint64x2](A)

  proc fillArgon2BlockNeon2x*(prevBlock, refBlock: openArray[uint64],
      outBlock: var openArray[uint64]) =
    ## prevBlock: previous lane block.
    ## refBlock: referenced block.
    ## outBlock: destination block.
    var
      blockR: array[argon2SimdQwords, uint64]
    xorBlocksPacked[uint64x2](blockR, refBlock, prevBlock)
    copyBlock(outBlock, blockR)
    applyArgon2RoundsPacked[uint64x2](blockR)
    xorIntoPacked[uint64x2](outBlock, blockR)

  proc fillArgon2BlockWithXorNeon2x*(prevBlock, refBlock,
      nextBlock: openArray[uint64], outBlock: var openArray[uint64]) =
    ## prevBlock: previous lane block.
    ## refBlock: referenced block.
    ## nextBlock: existing destination block for pass>0 xor mode.
    ## outBlock: destination block.
    var
      blockR: array[argon2SimdQwords, uint64]
    xorBlocksPacked[uint64x2](blockR, refBlock, prevBlock)
    copyBlock(outBlock, blockR)
    xorIntoPacked[uint64x2](outBlock, nextBlock)
    applyArgon2RoundsPacked[uint64x2](blockR)
    xorIntoPacked[uint64x2](outBlock, blockR)


when defined(avx2):
  proc applyArgon2RoundsAvx4x*(A: var openArray[uint64]) =
    ## A: Argon2 block words to permute with AVX2-width packed lanes.
    applyArgon2RoundsPacked[u64x4](A)

  proc fillArgon2BlockAvx4x*(prevBlock, refBlock: openArray[uint64],
      outBlock: var openArray[uint64]) =
    ## prevBlock: previous lane block.
    ## refBlock: referenced block.
    ## outBlock: destination block.
    var
      blockR: array[argon2SimdQwords, uint64]
    xorBlocksPacked[u64x4](blockR, refBlock, prevBlock)
    copyBlock(outBlock, blockR)
    applyArgon2RoundsPacked[u64x4](blockR)
    xorIntoPacked[u64x4](outBlock, blockR)

  proc fillArgon2BlockWithXorAvx4x*(prevBlock, refBlock,
      nextBlock: openArray[uint64], outBlock: var openArray[uint64]) =
    ## prevBlock: previous lane block.
    ## refBlock: referenced block.
    ## nextBlock: existing destination block for pass>0 xor mode.
    ## outBlock: destination block.
    var
      blockR: array[argon2SimdQwords, uint64]
    xorBlocksPacked[u64x4](blockR, refBlock, prevBlock)
    copyBlock(outBlock, blockR)
    xorIntoPacked[u64x4](outBlock, nextBlock)
    applyArgon2RoundsPacked[u64x4](blockR)
    xorIntoPacked[u64x4](outBlock, blockR)
