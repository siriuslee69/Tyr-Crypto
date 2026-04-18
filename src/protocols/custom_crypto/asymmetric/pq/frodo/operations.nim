## ----------------------------------------------------------------
## Frodo Operations <- pure-Nim FrodoKEM-976-AES key encapsulation
## ----------------------------------------------------------------

import ./params
import ./util
import ./noise
import ../../../../helpers/otter_support
import ../../../aes_core
import ../../../sha3
import ../../../random

when defined(sse2) or defined(avx2):
  import simd_nexus/simd/base_operations
  import simd_nexus/simd/generic_i16
when defined(sse2):
  import nimsimd/sse2 as nsse2
when defined(avx2):
  import nimsimd/avx as navx
  import nimsimd/avx2 as navx2

type
  ## Public/secret keypair emitted by the pure-Nim Frodo backend.
  FrodoTyrKeypair* = object
    variant*: FrodoVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Detached ciphertext plus shared secret emitted by encapsulation.
  FrodoTyrCipher* = object
    variant*: FrodoVariant
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]

const
  frodoRowsPerBlock = 4
  frodoRowsPerWideBlock = 4
  frodoTransposedStripeWords = 976 * 8
  frodoWordsPerFourRows = 4 * 976
  frodoBlocksPerFourRows = frodoWordsPerFourRows div 8
  frodoWordsPerColStripe = 976 * 8
  frodoBlocksPerColStripe = frodoWordsPerColStripe div 8

proc copyByteSeq(A: openArray[byte]): seq[byte] =
  var
    i: int = 0
  result = newSeq[byte](A.len)
  i = 0
  while i < A.len:
    result[i] = A[i]
    i = i + 1

proc prefixedByte(prefix: byte, A: openArray[byte]): seq[byte] =
  result = newSeq[byte](A.len + 1)
  result[0] = prefix
  if A.len > 0:
    copyMem(addr result[1], unsafeAddr A[0], A.len)

proc prefixed24(prefix: byte, A: openArray[byte]): array[25, byte] =
  var
    i: int = 0
  if A.len != 24:
    raise newException(ValueError, "Frodo fixed prefixed input requires 24 bytes")
  result[0] = prefix
  i = 0
  while i < 24:
    result[i + 1] = A[i]
    i = i + 1

proc concat24x2(A, B: openArray[byte]): array[48, byte] =
  var
    i: int = 0
  if A.len != 24 or B.len != 24:
    raise newException(ValueError, "Frodo fixed concat input requires two 24-byte slices")
  i = 0
  while i < 24:
    result[i] = A[i]
    result[i + 24] = B[i]
    i = i + 1

proc mulLo16(a, b: uint16): uint16 {.inline.} =
  result = uint16((uint32(a) * uint32(b)) and 0xffff'u32)

proc dotModQ16Scalar(A, B: openArray[uint16], aOff, bOff, n: int): uint16 =
  var
    i: int = 0
    acc: uint32 = 0
  i = 0
  while i < n:
    acc = acc + uint32(A[aOff + i]) * uint32(B[bOff + i])
    i = i + 1
  result = uint16(acc)

when defined(sse2):
  proc dotModQ16Sse(A, B: openArray[uint16], aOff, bOff, n: int): uint16 =
    var
      i: int = 0
      acc = i16x8(mm_setzero_si128())
      va: i16x8
      vb: i16x8
      lanes: array[8, uint16]
      sum: uint16 = 0
    i = 0
    while i + 8 <= n:
      va = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr A[aOff + i])))
      vb = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr B[bOff + i])))
      acc = acc + mulLoI16(va, vb)
      i = i + 8
    lanes = storeI16x8(acc)
    i = 0
    while i < lanes.len:
      sum = sum + lanes[i]
      i = i + 1
    while i < n:
      sum = sum + mulLo16(A[aOff + i], B[bOff + i])
      i = i + 1
    result = sum

when defined(avx2):
  proc dotModQ16Avx2(A, B: openArray[uint16], aOff, bOff, n: int): uint16 =
    var
      i: int = 0
      laneIdx: int = 0
      acc = i16x16(mm256_setzero_si256())
      va: i16x16
      vb: i16x16
      lanes: array[16, uint16]
      sum: uint16 = 0
    i = 0
    while i + 16 <= n:
      va = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr A[aOff + i])))
      vb = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr B[bOff + i])))
      acc = acc + mulLoI16(va, vb)
      i = i + 16
    lanes = storeI16x16(acc)
    laneIdx = 0
    while laneIdx < lanes.len:
      sum = sum + lanes[laneIdx]
      laneIdx = laneIdx + 1
    while i < n:
      sum = sum + mulLo16(A[aOff + i], B[bOff + i])
      i = i + 1
    result = sum

when defined(sse2):
  proc sumDwords4(v: nsse2.M128i): uint16 =
    var
      lanes: array[4, uint32]
      i: int = 0
      acc: uint32 = 0
    nsse2.mm_storeu_si128(cast[pointer](unsafeAddr lanes[0]), v)
    i = 0
    while i < lanes.len:
      acc = acc + lanes[i]
      i = i + 1
    result = uint16(acc)

  proc sumLanes8(v: i16x8): uint16 =
    var
      lanes: array[8, uint16]
      i: int = 0
    lanes = storeI16x8(v)
    i = 0
    while i < lanes.len:
      result = result + lanes[i]
      i = i + 1

  proc dot4RowsStripe8(rowStripes: openArray[array[8, uint16]], s: openArray[uint16],
      sOff: int, outSums: var array[4, uint16]) =
    var
      sVec: i16x8
      r0: i16x8
      r1: i16x8
      r2: i16x8
      r3: i16x8
    sVec = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr s[sOff])))
    r0 = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr rowStripes[0][0])))
    r1 = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr rowStripes[1][0])))
    r2 = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr rowStripes[2][0])))
    r3 = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr rowStripes[3][0])))
    outSums[0] = sumLanes8(mulLoI16(r0, sVec))
    outSums[1] = sumLanes8(mulLoI16(r1, sVec))
    outSums[2] = sumLanes8(mulLoI16(r2, sVec))
    outSums[3] = sumLanes8(mulLoI16(r3, sVec))

  proc dot4RowsStripe8Vec(rowVecs: openArray[i16x8], s: openArray[uint16],
      sOff: int, outSums: var array[4, uint16]) =
    var
      sVec: i16x8
    sVec = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr s[sOff])))
    outSums[0] = sumLanes8(mulLoI16(rowVecs[0], sVec))
    outSums[1] = sumLanes8(mulLoI16(rowVecs[1], sVec))
    outSums[2] = sumLanes8(mulLoI16(rowVecs[2], sVec))
    outSums[3] = sumLanes8(mulLoI16(rowVecs[3], sVec))

  proc loadSliceI16x8(A: openArray[uint16], off: int): i16x8 =
    result = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr A[off])))

  proc dot4ColsSse(s: openArray[uint16], sOff, strideN, colBase: int,
      aColsT: openArray[uint16], outSums: var array[4, uint16]) =
    var
      acc0 = nsse2.mm_setzero_si128()
      acc1 = nsse2.mm_setzero_si128()
      acc2 = nsse2.mm_setzero_si128()
      acc3 = nsse2.mm_setzero_si128()
      sVec: nsse2.M128i
      a0: nsse2.M128i
      a1: nsse2.M128i
      a2: nsse2.M128i
      a3: nsse2.M128i
      j: int = 0
    j = 0
    while j < strideN:
      sVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr s[sOff + j]))
      a0 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aColsT[(colBase + 0) * strideN + j]))
      a1 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aColsT[(colBase + 1) * strideN + j]))
      a2 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aColsT[(colBase + 2) * strideN + j]))
      a3 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aColsT[(colBase + 3) * strideN + j]))
      acc0 = nsse2.mm_add_epi32(acc0, nsse2.mm_madd_epi16(a0, sVec))
      acc1 = nsse2.mm_add_epi32(acc1, nsse2.mm_madd_epi16(a1, sVec))
      acc2 = nsse2.mm_add_epi32(acc2, nsse2.mm_madd_epi16(a2, sVec))
      acc3 = nsse2.mm_add_epi32(acc3, nsse2.mm_madd_epi16(a3, sVec))
      j = j + 8
    outSums[0] = sumDwords4(acc0)
    outSums[1] = sumDwords4(acc1)
    outSums[2] = sumDwords4(acc2)
    outSums[3] = sumDwords4(acc3)

  proc dot8ColsSse(s: openArray[uint16], sOff, strideN: int,
      aColsT: openArray[uint16], outSums: var array[8, uint16]) =
    var
      first4: array[4, uint16]
      last4: array[4, uint16]
    dot4ColsSse(s, sOff, strideN, 0, aColsT, first4)
    dot4ColsSse(s, sOff, strideN, 4, aColsT, last4)
    outSums[0] = first4[0]
    outSums[1] = first4[1]
    outSums[2] = first4[2]
    outSums[3] = first4[3]
    outSums[4] = last4[0]
    outSums[5] = last4[1]
    outSums[6] = last4[2]
    outSums[7] = last4[3]

  proc dot4RowsSse(aRows: openArray[uint16], s: openArray[uint16], sOff, strideN: int,
      outSums: var array[4, uint16]) =
    var
      acc0 = nsse2.mm_setzero_si128()
      acc1 = nsse2.mm_setzero_si128()
      acc2 = nsse2.mm_setzero_si128()
      acc3 = nsse2.mm_setzero_si128()
      sVec: nsse2.M128i
      r0: nsse2.M128i
      r1: nsse2.M128i
      r2: nsse2.M128i
      r3: nsse2.M128i
      j: int = 0
    j = 0
    while j < strideN:
      sVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr s[sOff + j]))
      r0 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aRows[0 * strideN + j]))
      r1 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aRows[1 * strideN + j]))
      r2 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aRows[2 * strideN + j]))
      r3 = nsse2.mm_load_si128(cast[pointer](unsafeAddr aRows[3 * strideN + j]))
      acc0 = nsse2.mm_add_epi32(acc0, nsse2.mm_madd_epi16(r0, sVec))
      acc1 = nsse2.mm_add_epi32(acc1, nsse2.mm_madd_epi16(r1, sVec))
      acc2 = nsse2.mm_add_epi32(acc2, nsse2.mm_madd_epi16(r2, sVec))
      acc3 = nsse2.mm_add_epi32(acc3, nsse2.mm_madd_epi16(r3, sVec))
      j = j + 8
    outSums[0] = sumDwords4(acc0)
    outSums[1] = sumDwords4(acc1)
    outSums[2] = sumDwords4(acc2)
    outSums[3] = sumDwords4(acc3)

  proc mulStripe8Sse(aCols: openArray[uint16], s: openArray[uint16], sOff, strideN: int,
      outSums: var array[8, uint16]) =
    var
      acc = nsse2.mm_setzero_si128()
      aVec: nsse2.M128i
      sVec: nsse2.M128i
      j: int = 0
    j = 0
    while j < strideN:
      aVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr aCols[j * 8]))
      sVec = nsse2.mm_set1_epi16(s[sOff + j])
      acc = nsse2.mm_add_epi16(acc, nsse2.mm_mullo_epi16(aVec, sVec))
      j = j + 1
    nsse2.mm_storeu_si128(cast[pointer](unsafeAddr outSums[0]), acc)

when defined(avx2):
  proc sumDwords8(v: navx.M256i): uint16 =
    var
      lanes: array[8, uint32]
      i: int = 0
      acc: uint32 = 0
    navx.mm256_storeu_si256(cast[pointer](unsafeAddr lanes[0]), v)
    i = 0
    while i < lanes.len:
      acc = acc + lanes[i]
      i = i + 1
    result = uint16(acc)

  proc dot4ColsAvx2(s: openArray[uint16], sOff, strideN, colBase: int,
      aColsT: openArray[uint16], outSums: var array[4, uint16]) =
    var
      acc0 = navx.mm256_setzero_si256()
      acc1 = navx.mm256_setzero_si256()
      acc2 = navx.mm256_setzero_si256()
      acc3 = navx.mm256_setzero_si256()
      sVec: navx.M256i
      a0: navx.M256i
      a1: navx.M256i
      a2: navx.M256i
      a3: navx.M256i
      j: int = 0
    j = 0
    while j < strideN:
      sVec = navx.mm256_loadu_si256(cast[pointer](unsafeAddr s[sOff + j]))
      a0 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(colBase + 0) * strideN + j]))
      a1 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(colBase + 1) * strideN + j]))
      a2 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(colBase + 2) * strideN + j]))
      a3 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(colBase + 3) * strideN + j]))
      acc0 = navx2.mm256_add_epi32(acc0, navx2.mm256_madd_epi16(a0, sVec))
      acc1 = navx2.mm256_add_epi32(acc1, navx2.mm256_madd_epi16(a1, sVec))
      acc2 = navx2.mm256_add_epi32(acc2, navx2.mm256_madd_epi16(a2, sVec))
      acc3 = navx2.mm256_add_epi32(acc3, navx2.mm256_madd_epi16(a3, sVec))
      j = j + 16
    outSums[0] = sumDwords8(acc0)
    outSums[1] = sumDwords8(acc1)
    outSums[2] = sumDwords8(acc2)
    outSums[3] = sumDwords8(acc3)

  proc dot8ColsAvx2(s: openArray[uint16], sOff, strideN: int,
      aColsT: openArray[uint16], outSums: var array[8, uint16]) =
    var
      first4: array[4, uint16]
      last4: array[4, uint16]
    dot4ColsAvx2(s, sOff, strideN, 0, aColsT, first4)
    dot4ColsAvx2(s, sOff, strideN, 4, aColsT, last4)
    outSums[0] = first4[0]
    outSums[1] = first4[1]
    outSums[2] = first4[2]
    outSums[3] = first4[3]
    outSums[4] = last4[0]
    outSums[5] = last4[1]
    outSums[6] = last4[2]
    outSums[7] = last4[3]

  proc dot4RowsAvx2(aRows: openArray[uint16], s: openArray[uint16], sOff, strideN: int,
      outSums: var array[4, uint16]) =
    var
      acc0 = navx.mm256_setzero_si256()
      acc1 = navx.mm256_setzero_si256()
      acc2 = navx.mm256_setzero_si256()
      acc3 = navx.mm256_setzero_si256()
      sVec: navx.M256i
      r0: navx.M256i
      r1: navx.M256i
      r2: navx.M256i
      r3: navx.M256i
      j: int = 0
    j = 0
    while j < strideN:
      sVec = navx.mm256_loadu_si256(cast[pointer](unsafeAddr s[sOff + j]))
      r0 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[0 * strideN + j]))
      r1 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[1 * strideN + j]))
      r2 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[2 * strideN + j]))
      r3 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[3 * strideN + j]))
      acc0 = navx2.mm256_add_epi32(acc0, navx2.mm256_madd_epi16(r0, sVec))
      acc1 = navx2.mm256_add_epi32(acc1, navx2.mm256_madd_epi16(r1, sVec))
      acc2 = navx2.mm256_add_epi32(acc2, navx2.mm256_madd_epi16(r2, sVec))
      acc3 = navx2.mm256_add_epi32(acc3, navx2.mm256_madd_epi16(r3, sVec))
      j = j + 16
    outSums[0] = sumDwords8(acc0)
    outSums[1] = sumDwords8(acc1)
    outSums[2] = sumDwords8(acc2)
    outSums[3] = sumDwords8(acc3)

proc dotModQ16(A, B: openArray[uint16], aOff, bOff, n: int): uint16 =
  when defined(avx2):
    result = dotModQ16Avx2(A, B, aOff, bOff, n)
  elif defined(sse2):
    result = dotModQ16Sse(A, B, aOff, bOff, n)
  else:
    result = dotModQ16Scalar(A, B, aOff, bOff, n)

{.push boundChecks: off, overflowChecks: off.}
proc initFourRowBlocks(blocksIn: var array[frodoBlocksPerFourRows, AesBlock]) =
  var
    row: int = 0
    blockCol: int = 0
    blockIdx: int = 0
  row = 0
  while row < 4:
    blockCol = 0
    while blockCol < 976:
      blockIdx = row * (976 div 8) + (blockCol div 8)
      blocksIn[blockIdx] = default(AesBlock)
      blocksIn[blockIdx][2] = byte(blockCol and 0xff)
      blocksIn[blockIdx][3] = byte((blockCol shr 8) and 0xff)
      blockCol = blockCol + 8
    row = row + 1

proc initColStripeBlocks(blocksIn: var array[frodoBlocksPerColStripe, AesBlock]) =
  var
    row: int = 0
  row = 0
  while row < frodoBlocksPerColStripe:
    blocksIn[row] = default(AesBlock)
    blocksIn[row][0] = byte(row and 0xff)
    blocksIn[row][1] = byte((row shr 8) and 0xff)
    row = row + 1

proc transposeWords8xN(src: openArray[uint16],
    dst: var array[frodoWordsPerColStripe, uint16]) =
  var
    j: int = 0
    base: int = 0
  j = 0
  while j < 976:
    base = j * 8
    dst[base + 0] = src[0 * 976 + j]
    dst[base + 1] = src[1 * 976 + j]
    dst[base + 2] = src[2 * 976 + j]
    dst[base + 3] = src[3 * 976 + j]
    dst[base + 4] = src[4 * 976 + j]
    dst[base + 5] = src[5 * 976 + j]
    dst[base + 6] = src[6 * 976 + j]
    dst[base + 7] = src[7 * 976 + j]
    j = j + 1

proc transposeColStripe8xN(src: openArray[uint16],
    dstT: var array[frodoWordsPerColStripe, uint16]) =
  var
    row: int = 0
    rowOff: int = 0
  row = 0
  while row < 976:
    rowOff = row * 8
    dstT[0 * 976 + row] = src[rowOff + 0]
    dstT[1 * 976 + row] = src[rowOff + 1]
    dstT[2 * 976 + row] = src[rowOff + 2]
    dstT[3 * 976 + row] = src[rowOff + 3]
    dstT[4 * 976 + row] = src[rowOff + 4]
    dstT[5 * 976 + row] = src[rowOff + 5]
    dstT[6 * 976 + row] = src[rowOff + 6]
    dstT[7 * 976 + row] = src[rowOff + 7]
    row = row + 1

proc generateRowStripe(ctx: Aes128Ctx, row, colStart: int): array[8, uint16] =
  var
    blk: AesBlock
    enc: AesBlock
    i: int = 0
  blk = default(AesBlock)
  blk[0] = byte(row and 0xff)
  blk[1] = byte((row shr 8) and 0xff)
  blk[2] = byte(colStart and 0xff)
  blk[3] = byte((colStart shr 8) and 0xff)
  enc = encryptBlockPublicFast(ctx, blk)
  i = 0
  while i < 8:
    result[i] = loadU16Le(enc, i * 2)
    i = i + 1

when defined(aesni):
  proc generateColStripeBulk(ctx: Aes128NiCtx,
      blocksIn: var array[frodoBlocksPerColStripe, AesBlock],
      blocksOut: var array[frodoBlocksPerColStripe, AesBlock],
      colStart: int, dst: var array[frodoWordsPerColStripe, uint16]) =
    var
      row: int = 0
      lane: int = 0
      rowOff: int = 0
    row = 0
    while row < frodoBlocksPerColStripe:
      blocksIn[row][0] = byte(row and 0xff)
      blocksIn[row][1] = byte((row shr 8) and 0xff)
      blocksIn[row][2] = byte(colStart and 0xff)
      blocksIn[row][3] = byte((colStart shr 8) and 0xff)
      row = row + 1
    encryptBlocks(ctx, blocksIn, blocksOut)
    when cpuEndian == littleEndian:
      copyMem(addr dst[0], unsafeAddr blocksOut[0], frodoWordsPerColStripe * sizeof(uint16))
    else:
      row = 0
      while row < frodoBlocksPerColStripe:
        rowOff = row * 8
        lane = 0
        while lane < 8:
          dst[rowOff + lane] = loadU16Le(blocksOut[row], lane * 2)
          lane = lane + 1
        row = row + 1

  proc generateFourRowsBulk(ctx: Aes128NiCtx,
      blocksIn: var array[frodoBlocksPerFourRows, AesBlock],
      blocksOut: var array[frodoBlocksPerFourRows, AesBlock],
      rowStart: int, dst: var array[frodoWordsPerFourRows, uint16]) =
    var
      row: int = 0
      blockCol: int = 0
      blockIdx: int = 0
      lane: int = 0
    row = 0
    while row < 4:
      blockCol = 0
      while blockCol < 976:
        blockIdx = row * (976 div 8) + (blockCol div 8)
        blocksIn[blockIdx][0] = byte((rowStart + row) and 0xff)
        blocksIn[blockIdx][1] = byte(((rowStart + row) shr 8) and 0xff)
        blockCol = blockCol + 8
      row = row + 1
    encryptBlocks(ctx, blocksIn, blocksOut)
    when cpuEndian == littleEndian:
      copyMem(addr dst[0], unsafeAddr blocksOut[0], frodoWordsPerFourRows * sizeof(uint16))
    else:
      blockIdx = 0
      while blockIdx < frodoBlocksPerFourRows:
        lane = 0
        while lane < 8:
          dst[blockIdx * 8 + lane] = loadU16Le(blocksOut[blockIdx], lane * 2)
          lane = lane + 1
        blockIdx = blockIdx + 1

  proc generateColStripeBulkT(ctx: Aes128NiCtx,
      blocksIn: var array[frodoBlocksPerColStripe, AesBlock],
      blocksOut: var array[frodoBlocksPerColStripe, AesBlock],
      colStart: int, dstT: var array[frodoWordsPerColStripe, uint16]) =
    var
      row: int = 0
      lane: int = 0
      rowBase: int = 0
    row = 0
    while row < frodoBlocksPerColStripe:
      blocksIn[row][0] = byte(row and 0xff)
      blocksIn[row][1] = byte((row shr 8) and 0xff)
      blocksIn[row][2] = byte(colStart and 0xff)
      blocksIn[row][3] = byte((colStart shr 8) and 0xff)
      row = row + 1
    encryptBlocks(ctx, blocksIn, blocksOut)
    row = 0
    while row < frodoBlocksPerColStripe:
      rowBase = row
      lane = 0
      while lane < 8:
        dstT[lane * 976 + rowBase] = loadU16Le(blocksOut[row], lane * 2)
        lane = lane + 1
      row = row + 1

proc generateFourRowsBulk(ctx: Aes128Ctx,
    blocksIn: var array[frodoBlocksPerFourRows, AesBlock],
    blocksOut: var array[frodoBlocksPerFourRows, AesBlock],
    rowStart: int, dst: var array[frodoWordsPerFourRows, uint16]) =
  var
    row: int = 0
    blockCol: int = 0
    blockIdx: int = 0
    lane: int = 0
  row = 0
  while row < 4:
    blockCol = 0
    while blockCol < 976:
      blockIdx = row * (976 div 8) + (blockCol div 8)
      blocksIn[blockIdx][0] = byte((rowStart + row) and 0xff)
      blocksIn[blockIdx][1] = byte(((rowStart + row) shr 8) and 0xff)
      blockCol = blockCol + 8
    row = row + 1
  encryptBlocksPublicFast(ctx, blocksIn, blocksOut)
  when cpuEndian == littleEndian:
    copyMem(addr dst[0], unsafeAddr blocksOut[0], frodoWordsPerFourRows * sizeof(uint16))
  else:
    blockIdx = 0
    while blockIdx < frodoBlocksPerFourRows:
      lane = 0
      while lane < 8:
        dst[blockIdx * 8 + lane] = loadU16Le(blocksOut[blockIdx], lane * 2)
        lane = lane + 1
      blockIdx = blockIdx + 1

proc generateFourRowsBulk(ctx: Aes128OpenSslCtx,
    blocksIn: var array[frodoBlocksPerFourRows, AesBlock],
    blocksOut: var array[frodoBlocksPerFourRows, AesBlock],
    rowStart: int, dst: var array[frodoWordsPerFourRows, uint16]) =
  var
    row: int = 0
    blockCol: int = 0
    blockIdx: int = 0
    lane: int = 0
  row = 0
  while row < 4:
    blockCol = 0
    while blockCol < 976:
      blockIdx = row * (976 div 8) + (blockCol div 8)
      blocksIn[blockIdx][0] = byte((rowStart + row) and 0xff)
      blocksIn[blockIdx][1] = byte(((rowStart + row) shr 8) and 0xff)
      blockCol = blockCol + 8
    row = row + 1
  encryptBlocksPublicFast(ctx, blocksIn, blocksOut)
  when cpuEndian == littleEndian:
    copyMem(addr dst[0], unsafeAddr blocksOut[0], frodoWordsPerFourRows * sizeof(uint16))
  else:
    blockIdx = 0
    while blockIdx < frodoBlocksPerFourRows:
      lane = 0
      while lane < 8:
        dst[blockIdx * 8 + lane] = loadU16Le(blocksOut[blockIdx], lane * 2)
        lane = lane + 1
      blockIdx = blockIdx + 1

proc generateColStripeBulkT(ctx: Aes128Ctx,
    blocksIn: var array[frodoBlocksPerColStripe, AesBlock],
    blocksOut: var array[frodoBlocksPerColStripe, AesBlock],
    colStart: int, dstT: var array[frodoWordsPerColStripe, uint16]) =
  var
    row: int = 0
    lane: int = 0
    rowBase: int = 0
  row = 0
  while row < frodoBlocksPerColStripe:
    blocksIn[row][2] = byte(colStart and 0xff)
    blocksIn[row][3] = byte((colStart shr 8) and 0xff)
    row = row + 1
  encryptBlocksPublicFast(ctx, blocksIn, blocksOut)
  row = 0
  while row < frodoBlocksPerColStripe:
    rowBase = row
    lane = 0
    while lane < 8:
      dstT[lane * 976 + rowBase] = loadU16Le(blocksOut[row], lane * 2)
      lane = lane + 1
    row = row + 1

proc generateColStripeBulkT(ctx: Aes128OpenSslCtx,
    blocksIn: var array[frodoBlocksPerColStripe, AesBlock],
    blocksOut: var array[frodoBlocksPerColStripe, AesBlock],
    colStart: int, dstT: var array[frodoWordsPerColStripe, uint16]) =
  var
    row: int = 0
    lane: int = 0
    rowBase: int = 0
  row = 0
  while row < frodoBlocksPerColStripe:
    blocksIn[row][2] = byte(colStart and 0xff)
    blocksIn[row][3] = byte((colStart shr 8) and 0xff)
    row = row + 1
  encryptBlocksPublicFast(ctx, blocksIn, blocksOut)
  row = 0
  while row < frodoBlocksPerColStripe:
    rowBase = row
    lane = 0
    while lane < 8:
      dstT[lane * 976 + rowBase] = loadU16Le(blocksOut[row], lane * 2)
      lane = lane + 1
    row = row + 1

proc generateColStripeBulk(ctx: Aes128Ctx,
    blocksIn: var array[frodoBlocksPerColStripe, AesBlock],
    blocksOut: var array[frodoBlocksPerColStripe, AesBlock],
    colStart: int, dst: var array[frodoWordsPerColStripe, uint16]) =
  var
    row: int = 0
    lane: int = 0
    rowOff: int = 0
  row = 0
  while row < frodoBlocksPerColStripe:
    blocksIn[row][2] = byte(colStart and 0xff)
    blocksIn[row][3] = byte((colStart shr 8) and 0xff)
    row = row + 1
  encryptBlocksPublicFast(ctx, blocksIn, blocksOut)
  when cpuEndian == littleEndian:
    copyMem(addr dst[0], unsafeAddr blocksOut[0], frodoWordsPerColStripe * sizeof(uint16))
  else:
    row = 0
    while row < frodoBlocksPerColStripe:
      rowOff = row * 8
      lane = 0
      while lane < 8:
        dst[rowOff + lane] = loadU16Le(blocksOut[row], lane * 2)
        lane = lane + 1
      row = row + 1

proc generateColStripeBulk(ctx: Aes128OpenSslCtx,
    blocksIn: var array[frodoBlocksPerColStripe, AesBlock],
    blocksOut: var array[frodoBlocksPerColStripe, AesBlock],
    colStart: int, dst: var array[frodoWordsPerColStripe, uint16]) =
  var
    row: int = 0
    lane: int = 0
    rowOff: int = 0
  row = 0
  while row < frodoBlocksPerColStripe:
    blocksIn[row][2] = byte(colStart and 0xff)
    blocksIn[row][3] = byte((colStart shr 8) and 0xff)
    row = row + 1
  encryptBlocksPublicFast(ctx, blocksIn, blocksOut)
  when cpuEndian == littleEndian:
    copyMem(addr dst[0], unsafeAddr blocksOut[0], frodoWordsPerColStripe * sizeof(uint16))
  else:
    row = 0
    while row < frodoBlocksPerColStripe:
      rowOff = row * 8
      lane = 0
      while lane < 8:
        dst[rowOff + lane] = loadU16Le(blocksOut[row], lane * 2)
        lane = lane + 1
      row = row + 1

when defined(aesni):
  proc generateRowStripe(ctx: Aes128NiCtx, row, colStart: int): array[8, uint16] =
    var
      blk: AesBlock
      enc: AesBlock
      i: int = 0
    blk = default(AesBlock)
    blk[0] = byte(row and 0xff)
    blk[1] = byte((row shr 8) and 0xff)
    blk[2] = byte(colStart and 0xff)
    blk[3] = byte((colStart shr 8) and 0xff)
    enc = encryptBlock(ctx, blk)
    i = 0
    while i < 8:
      result[i] = loadU16Le(enc, i * 2)
      i = i + 1

  proc generateFourRowStripes(ctx: Aes128NiCtx, rowStart, colStart: int): array[4, array[8, uint16]] =
    var
      blocks: array[4, AesBlock]
      encs: array[4, AesBlock]
      rowIdx: int = 0
      lane: int = 0
    rowIdx = 0
    while rowIdx < 4:
      blocks[rowIdx] = default(AesBlock)
      blocks[rowIdx][0] = byte((rowStart + rowIdx) and 0xff)
      blocks[rowIdx][1] = byte(((rowStart + rowIdx) shr 8) and 0xff)
      blocks[rowIdx][2] = byte(colStart and 0xff)
      blocks[rowIdx][3] = byte((colStart shr 8) and 0xff)
      rowIdx = rowIdx + 1
    encs = encryptBlock4(ctx, blocks)
    rowIdx = 0
    while rowIdx < 4:
      lane = 0
      while lane < 8:
        result[rowIdx][lane] = loadU16Le(encs[rowIdx], lane * 2)
        lane = lane + 1
      rowIdx = rowIdx + 1

  proc generateEightRowStripes(ctx: Aes128NiCtx, rowStart, colStart: int): array[8, array[8, uint16]] =
    var
      blocks: array[8, AesBlock]
      encs: array[8, AesBlock]
      rowIdx: int = 0
      lane: int = 0
    rowIdx = 0
    while rowIdx < 8:
      blocks[rowIdx] = default(AesBlock)
      blocks[rowIdx][0] = byte((rowStart + rowIdx) and 0xff)
      blocks[rowIdx][1] = byte(((rowStart + rowIdx) shr 8) and 0xff)
      blocks[rowIdx][2] = byte(colStart and 0xff)
      blocks[rowIdx][3] = byte((colStart shr 8) and 0xff)
      rowIdx = rowIdx + 1
    encs = encryptBlock8(ctx, blocks)
    rowIdx = 0
    while rowIdx < 8:
      lane = 0
      while lane < 8:
        result[rowIdx][lane] = loadU16Le(encs[rowIdx], lane * 2)
        lane = lane + 1
      rowIdx = rowIdx + 1

  proc generateFourRowStripeVecs(ctx: Aes128NiCtx, rowStart, colStart: int): array[4, i16x8] =
    var
      blocks: array[4, AesBlock]
      encs: array[4, AesBlock]
      rowIdx: int = 0
    rowIdx = 0
    while rowIdx < 4:
      blocks[rowIdx] = default(AesBlock)
      blocks[rowIdx][0] = byte((rowStart + rowIdx) and 0xff)
      blocks[rowIdx][1] = byte(((rowStart + rowIdx) shr 8) and 0xff)
      blocks[rowIdx][2] = byte(colStart and 0xff)
      blocks[rowIdx][3] = byte((colStart shr 8) and 0xff)
      rowIdx = rowIdx + 1
    encs = encryptBlock4(ctx, blocks)
    rowIdx = 0
    while rowIdx < 4:
      result[rowIdx] = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr encs[rowIdx][0])))
      rowIdx = rowIdx + 1

when defined(avx2):
  proc accumulateAsBlock4x8Avx2(aRows: openArray[uint16],
      s: openArray[uint16], result: var openArray[uint16], outOff: int) =
    var
      sums {.align: 32.}: array[32, uint32]
      col: int = 0
      sOff: int = 0
      j: int = 0
      sVec: navx.M256i
      r0: navx.M256i
      r1: navx.M256i
      r2: navx.M256i
      r3: navx.M256i
      acc0: navx.M256i
      acc1: navx.M256i
      acc2: navx.M256i
      acc3: navx.M256i
    col = 0
    while col < 8:
      sOff = col * 976
      acc0 = navx.mm256_setzero_si256()
      acc1 = navx.mm256_setzero_si256()
      acc2 = navx.mm256_setzero_si256()
      acc3 = navx.mm256_setzero_si256()
      j = 0
      while j < 976:
        sVec = navx.mm256_loadu_si256(cast[pointer](unsafeAddr s[sOff + j]))
        r0 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[0 * 976 + j]))
        r1 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[1 * 976 + j]))
        r2 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[2 * 976 + j]))
        r3 = navx.mm256_load_si256(cast[pointer](unsafeAddr aRows[3 * 976 + j]))
        acc0 = navx2.mm256_add_epi32(acc0, navx2.mm256_madd_epi16(r0, sVec))
        acc1 = navx2.mm256_add_epi32(acc1, navx2.mm256_madd_epi16(r1, sVec))
        acc2 = navx2.mm256_add_epi32(acc2, navx2.mm256_madd_epi16(r2, sVec))
        acc3 = navx2.mm256_add_epi32(acc3, navx2.mm256_madd_epi16(r3, sVec))
        j = j + 16
      navx.mm256_store_si256(cast[pointer](addr sums[0]), acc0)
      navx.mm256_store_si256(cast[pointer](addr sums[8]), acc1)
      navx.mm256_store_si256(cast[pointer](addr sums[16]), acc2)
      navx.mm256_store_si256(cast[pointer](addr sums[24]), acc3)
      result[outOff + 0 * 8 + col] = result[outOff + 0 * 8 + col] + uint16(
        sums[0] + sums[1] + sums[2] + sums[3] + sums[4] + sums[5] + sums[6] + sums[7])
      result[outOff + 1 * 8 + col] = result[outOff + 1 * 8 + col] + uint16(
        sums[8] + sums[9] + sums[10] + sums[11] + sums[12] + sums[13] + sums[14] + sums[15])
      result[outOff + 2 * 8 + col] = result[outOff + 2 * 8 + col] + uint16(
        sums[16] + sums[17] + sums[18] + sums[19] + sums[20] + sums[21] + sums[22] + sums[23])
      result[outOff + 3 * 8 + col] = result[outOff + 3 * 8 + col] + uint16(
        sums[24] + sums[25] + sums[26] + sums[27] + sums[28] + sums[29] + sums[30] + sums[31])
      col = col + 1

  proc accumulateSaStripe8Avx2(aColsT: openArray[uint16],
      s: openArray[uint16], result: var openArray[uint16], colStart: int) =
    var
      sums {.align: 32.}: array[32, uint32]
      row: int = 0
      sOff: int = 0
      rowOff: int = 0
      col: int = 0
      j: int = 0
      sVec: navx.M256i
      a0: navx.M256i
      a1: navx.M256i
      a2: navx.M256i
      a3: navx.M256i
      acc0: navx.M256i
      acc1: navx.M256i
      acc2: navx.M256i
      acc3: navx.M256i
    row = 0
    while row < 8:
      sOff = row * 976
      rowOff = row * 976 + colStart
      col = 0
      while col < 8:
        acc0 = navx.mm256_setzero_si256()
        acc1 = navx.mm256_setzero_si256()
        acc2 = navx.mm256_setzero_si256()
        acc3 = navx.mm256_setzero_si256()
        j = 0
        while j < 976:
          sVec = navx.mm256_loadu_si256(cast[pointer](unsafeAddr s[sOff + j]))
          a0 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(col + 0) * 976 + j]))
          a1 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(col + 1) * 976 + j]))
          a2 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(col + 2) * 976 + j]))
          a3 = navx.mm256_load_si256(cast[pointer](unsafeAddr aColsT[(col + 3) * 976 + j]))
          acc0 = navx2.mm256_add_epi32(acc0, navx2.mm256_madd_epi16(a0, sVec))
          acc1 = navx2.mm256_add_epi32(acc1, navx2.mm256_madd_epi16(a1, sVec))
          acc2 = navx2.mm256_add_epi32(acc2, navx2.mm256_madd_epi16(a2, sVec))
          acc3 = navx2.mm256_add_epi32(acc3, navx2.mm256_madd_epi16(a3, sVec))
          j = j + 16
        navx.mm256_store_si256(cast[pointer](addr sums[0]), acc0)
        navx.mm256_store_si256(cast[pointer](addr sums[8]), acc1)
        navx.mm256_store_si256(cast[pointer](addr sums[16]), acc2)
        navx.mm256_store_si256(cast[pointer](addr sums[24]), acc3)
        result[rowOff + col + 0] = result[rowOff + col + 0] + uint16(
          sums[0] + sums[1] + sums[2] + sums[3] + sums[4] + sums[5] + sums[6] + sums[7])
        result[rowOff + col + 1] = result[rowOff + col + 1] + uint16(
          sums[8] + sums[9] + sums[10] + sums[11] + sums[12] + sums[13] + sums[14] + sums[15])
        result[rowOff + col + 2] = result[rowOff + col + 2] + uint16(
          sums[16] + sums[17] + sums[18] + sums[19] + sums[20] + sums[21] + sums[22] + sums[23])
        result[rowOff + col + 3] = result[rowOff + col + 3] + uint16(
          sums[24] + sums[25] + sums[26] + sums[27] + sums[28] + sums[29] + sums[30] + sums[31])
        col = col + 4
      row = row + 1

when defined(sse2):
  proc accumulateAsBlock4x8Sse(aRows: openArray[uint16],
      s: openArray[uint16], result: var openArray[uint16], outOff: int) =
    var
      sums: array[4, uint16]
      col: int = 0
      sOff: int = 0
    col = 0
    while col < 8:
      sOff = col * 976
      dot4RowsSse(aRows, s, sOff, 976, sums)
      result[outOff + 0 * 8 + col] = result[outOff + 0 * 8 + col] + sums[0]
      result[outOff + 1 * 8 + col] = result[outOff + 1 * 8 + col] + sums[1]
      result[outOff + 2 * 8 + col] = result[outOff + 2 * 8 + col] + sums[2]
      result[outOff + 3 * 8 + col] = result[outOff + 3 * 8 + col] + sums[3]
      col = col + 1

  proc accumulateSaStripe8Sse(aColsT: openArray[uint16],
      s: openArray[uint16], result: var openArray[uint16], colStart: int) =
    var
      sums: array[8, uint16]
      row: int = 0
      sOff: int = 0
      rowOff: int = 0
    row = 0
    while row < 8:
      sOff = row * 976
      rowOff = row * 976 + colStart
      dot8ColsSse(s, sOff, 976, aColsT, sums)
      result[rowOff + 0] = result[rowOff + 0] + sums[0]
      result[rowOff + 1] = result[rowOff + 1] + sums[1]
      result[rowOff + 2] = result[rowOff + 2] + sums[2]
      result[rowOff + 3] = result[rowOff + 3] + sums[3]
      result[rowOff + 4] = result[rowOff + 4] + sums[4]
      result[rowOff + 5] = result[rowOff + 5] + sums[5]
      result[rowOff + 6] = result[rowOff + 6] + sums[6]
      result[rowOff + 7] = result[rowOff + 7] + sums[7]
      row = row + 1

proc accumulateAsBlock4x8Scalar(aRows: openArray[uint16],
    s: openArray[uint16], result: var openArray[uint16], outOff: int) =
  var
    row: int = 0
    col: int = 0
    rowOff: int = 0
    sOff: int = 0
  row = 0
  while row < 4:
    rowOff = outOff + row * 8
    col = 0
    while col < 8:
      sOff = col * 976
      result[rowOff + col] = result[rowOff + col] +
        dotModQ16(aRows, s, row * 976, sOff, 976)
      col = col + 1
    row = row + 1

proc accumulateSaStripe8Scalar(aColsT: openArray[uint16],
    s: openArray[uint16], result: var openArray[uint16], colStart: int) =
  var
    row: int = 0
    col: int = 0
    rowOff: int = 0
    sOff: int = 0
  row = 0
  while row < 8:
    rowOff = row * 976 + colStart
    sOff = row * 976
    col = 0
    while col < 8:
      result[rowOff + col] = result[rowOff + col] +
        dotModQ16(s, aColsT, sOff, col * 976, 976)
      col = col + 1
    row = row + 1

proc generateMatrixA(p: FrodoParams, seedA: openArray[byte]): seq[uint16] =
  ## Generate the Frodo matrix `A` row-wise via AES-128 ECB blocks.
  otterSpan("frodo.generateMatrixA"):
    var
      ctx: Aes128Ctx
      blk: AesBlock
      enc: AesBlock
      i: int = 0
      j: int = 0
      k: int = 0
      o: int = 0
    if seedA.len != p.bytesSeedA:
      raise newException(ValueError, "invalid Frodo seed_A length")
    ctx.initPublicFast(seedA)
    result = newSeq[uint16](p.n * p.n)
    i = 0
    while i < p.n:
      j = 0
      while j < p.n:
        blk = default(AesBlock)
        blk[0] = byte(i and 0xff)
        blk[1] = byte((i shr 8) and 0xff)
        blk[2] = byte(j and 0xff)
        blk[3] = byte((j shr 8) and 0xff)
        enc = encryptBlockPublicFast(ctx, blk)
        k = 0
        while k < p.stripeStep:
          o = i * p.n + j + k
          if o < result.len:
            result[o] = loadU16Le(enc, k * 2)
          k = k + 1
        j = j + p.stripeStep
      i = i + 1

proc mulAddAsPlusE(p: FrodoParams, A, s, e: openArray[uint16]): seq[uint16] =
  ## Compute `A * s + e` with `A` in row-major order.
  otterSpan("frodo.mulAddAsPlusE"):
    var
      i: int = 0
      k: int = 0
      rowOff: int = 0
      sOff: int = 0
    result = newSeq[uint16](p.n * p.nbar)
    i = 0
    while i < result.len:
      result[i] = e[i]
      i = i + 1
    i = 0
    while i < p.n:
      rowOff = i * p.n
      k = 0
      while k < p.nbar:
        sOff = k * p.n
        result[i * p.nbar + k] = result[i * p.nbar + k] +
          dotModQ16(A, s, rowOff, sOff, p.n)
        k = k + 1
      i = i + 1

proc mulAddAsPlusEStream(p: FrodoParams, seedA: openArray[byte], s, e: openArray[uint16]): seq[uint16] =
  ## Compute `A * s + e` while generating each matrix row on demand.
  otterSpan("frodo.mulAddAsPlusEStream"):
    if seedA.len != p.bytesSeedA:
      raise newException(ValueError, "invalid Frodo seed_A length")
    result = newSeq[uint16](p.n * p.nbar)
    if result.len > 0:
      copyMem(addr result[0], unsafeAddr e[0], result.len * sizeof(uint16))
    block openSslPath:
      var
        ctx: Aes128OpenSslCtx
        blocksIn: array[frodoBlocksPerFourRows, AesBlock]
        blocksOut: array[frodoBlocksPerFourRows, AesBlock]
        aRow {.align: 32.}: array[frodoWordsPerFourRows, uint16]
        i: int = 0
      if not initOpenSslPublicFast(ctx, seedA):
        break openSslPath
      defer:
        clear(ctx)
      initFourRowBlocks(blocksIn)
      i = 0
      while i < p.n:
        generateFourRowsBulk(ctx, blocksIn, blocksOut, i, aRow)
        when defined(avx2):
          accumulateAsBlock4x8Avx2(aRow, s, result, i * p.nbar)
        elif defined(sse2):
          accumulateAsBlock4x8Sse(aRow, s, result, i * p.nbar)
        else:
          accumulateAsBlock4x8Scalar(aRow, s, result, i * p.nbar)
        i = i + 4
      return result
    when defined(aesni):
      var
        ctx: Aes128NiCtx
        blocksIn: array[frodoBlocksPerFourRows, AesBlock]
        blocksOut: array[frodoBlocksPerFourRows, AesBlock]
        aRow {.align: 32.}: array[frodoWordsPerFourRows, uint16]
        i: int = 0
      ctx.initPublicFast(seedA)
      initFourRowBlocks(blocksIn)
      i = 0
      while i < p.n:
        generateFourRowsBulk(ctx, blocksIn, blocksOut, i, aRow)
        when defined(avx2):
          accumulateAsBlock4x8Avx2(aRow, s, result, i * p.nbar)
        elif defined(sse2):
          accumulateAsBlock4x8Sse(aRow, s, result, i * p.nbar)
        else:
          accumulateAsBlock4x8Scalar(aRow, s, result, i * p.nbar)
        i = i + frodoRowsPerWideBlock
    else:
      var
        ctx: Aes128Ctx
        blocksIn: array[frodoBlocksPerFourRows, AesBlock]
        blocksOut: array[frodoBlocksPerFourRows, AesBlock]
        aRow {.align: 32.}: array[frodoWordsPerFourRows, uint16]
        i: int = 0
      ctx.initPublicFast(seedA)
      initFourRowBlocks(blocksIn)
      i = 0
      while i < p.n:
        generateFourRowsBulk(ctx, blocksIn, blocksOut, i, aRow)
        when defined(avx2):
          accumulateAsBlock4x8Avx2(aRow, s, result, i * p.nbar)
        elif defined(sse2):
          accumulateAsBlock4x8Sse(aRow, s, result, i * p.nbar)
        else:
          accumulateAsBlock4x8Scalar(aRow, s, result, i * p.nbar)
        i = i + 4

proc mulAddSaPlusE(p: FrodoParams, A, s, e: openArray[uint16]): seq[uint16] =
  ## Compute `s * A + e` with `A` in row-major order.
  otterSpan("frodo.mulAddSaPlusE"):
    var
      i: int = 0
      j: int = 0
      k: int = 0
      aCol: seq[uint16] = @[]
      sOff: int = 0
    result = newSeq[uint16](p.nbar * p.n)
    i = 0
    while i < result.len:
      result[i] = e[i]
      i = i + 1
    aCol = newSeq[uint16](p.n)
    i = 0
    while i < p.n:
      j = 0
      while j < p.n:
        aCol[j] = A[j * p.n + i]
        j = j + 1
      k = 0
      while k < p.nbar:
        sOff = k * p.n
        result[k * p.n + i] = result[k * p.n + i] +
          dotModQ16(s, aCol, sOff, 0, p.n)
        k = k + 1
      i = i + 1


proc mulAddSaPlusEStream(p: FrodoParams, seedA: openArray[byte], s, e: openArray[uint16]): seq[uint16] =
  ## Compute `s * A + e` while generating each matrix stripe on demand.
  otterSpan("frodo.mulAddSaPlusEStream"):
    if seedA.len != p.bytesSeedA:
      raise newException(ValueError, "invalid Frodo seed_A length")
    result = newSeq[uint16](p.nbar * p.n)
    if result.len > 0:
      copyMem(addr result[0], unsafeAddr e[0], result.len * sizeof(uint16))
    block openSslPath:
      var
        ctx: Aes128OpenSslCtx
        blocksIn: array[frodoBlocksPerColStripe, AesBlock]
        blocksOut: array[frodoBlocksPerColStripe, AesBlock]
        aCols {.align: 32.}: array[frodoWordsPerColStripe, uint16]
        aColsT {.align: 32.}: array[frodoWordsPerColStripe, uint16]
        kk: int = 0
      if not initOpenSslPublicFast(ctx, seedA):
        break openSslPath
      defer:
        clear(ctx)
      initColStripeBlocks(blocksIn)
      kk = 0
      while kk < p.n:
        generateColStripeBulk(ctx, blocksIn, blocksOut, kk, aCols)
        transposeColStripe8xN(aCols, aColsT)
        when defined(avx2):
          accumulateSaStripe8Avx2(aColsT, s, result, kk)
        elif defined(sse2):
          accumulateSaStripe8Sse(aColsT, s, result, kk)
        else:
          accumulateSaStripe8Scalar(aColsT, s, result, kk)
        kk = kk + p.stripeStep
      return result
    when defined(aesni):
      var
        ctx: Aes128NiCtx
        blocksIn: array[frodoBlocksPerColStripe, AesBlock]
        blocksOut: array[frodoBlocksPerColStripe, AesBlock]
        aCols {.align: 32.}: array[frodoWordsPerColStripe, uint16]
        aColsT {.align: 32.}: array[frodoWordsPerColStripe, uint16]
        kk: int = 0
      ctx.initPublicFast(seedA)
      initColStripeBlocks(blocksIn)
      kk = 0
      while kk < p.n:
        generateColStripeBulk(ctx, blocksIn, blocksOut, kk, aCols)
        transposeColStripe8xN(aCols, aColsT)
        when defined(avx2):
          accumulateSaStripe8Avx2(aColsT, s, result, kk)
        elif defined(sse2):
          accumulateSaStripe8Sse(aColsT, s, result, kk)
        else:
          accumulateSaStripe8Scalar(aColsT, s, result, kk)
        kk = kk + p.stripeStep
    else:
      var
        ctx: Aes128Ctx
        blocksIn: array[frodoBlocksPerColStripe, AesBlock]
        blocksOut: array[frodoBlocksPerColStripe, AesBlock]
        aCols {.align: 32.}: array[frodoWordsPerColStripe, uint16]
        aColsT {.align: 32.}: array[frodoWordsPerColStripe, uint16]
        kk: int = 0
      ctx.initPublicFast(seedA)
      initColStripeBlocks(blocksIn)
      kk = 0
      while kk < p.n:
        generateColStripeBulk(ctx, blocksIn, blocksOut, kk, aCols)
        transposeColStripe8xN(aCols, aColsT)
        when defined(avx2):
          accumulateSaStripe8Avx2(aColsT, s, result, kk)
        elif defined(sse2):
          accumulateSaStripe8Sse(aColsT, s, result, kk)
        else:
          accumulateSaStripe8Scalar(aColsT, s, result, kk)
        kk = kk + p.stripeStep

proc mulAddAsPlusEStreamPair(p: FrodoParams, seedA: seq[byte], seWords: seq[uint16],
    sOff, eOff: int): seq[uint16] =
  result = mulAddAsPlusEStream(p, seedA,
    seWords.toOpenArray(sOff, sOff + p.n * p.nbar - 1),
    seWords.toOpenArray(eOff, eOff + p.n * p.nbar - 1))

proc mulAddSaPlusEStreamPair(p: FrodoParams, seedA: seq[byte], seWords: seq[uint16],
    sOff, eOff: int): seq[uint16] =
  result = mulAddSaPlusEStream(p, seedA,
    seWords.toOpenArray(sOff, sOff + p.n * p.nbar - 1),
    seWords.toOpenArray(eOff, eOff + p.n * p.nbar - 1))

proc mulBs(p: FrodoParams, b, s: openArray[uint16]): seq[uint16] =
  ## Compute `b * s`.
  otterSpan("frodo.mulBs"):
    var
      i: int = 0
      j: int = 0
      k: int = 0
      acc: uint32 = 0
    result = newSeq[uint16](p.nbar * p.nbar)
    i = 0
    while i < p.nbar:
      j = 0
      while j < p.nbar:
        k = 0
        acc = 0'u32
        while k < p.n:
          acc = acc + uint32(b[i * p.n + k + 0]) * uint32(s[j * p.n + k + 0])
          acc = acc + uint32(b[i * p.n + k + 1]) * uint32(s[j * p.n + k + 1])
          acc = acc + uint32(b[i * p.n + k + 2]) * uint32(s[j * p.n + k + 2])
          acc = acc + uint32(b[i * p.n + k + 3]) * uint32(s[j * p.n + k + 3])
          acc = acc + uint32(b[i * p.n + k + 4]) * uint32(s[j * p.n + k + 4])
          acc = acc + uint32(b[i * p.n + k + 5]) * uint32(s[j * p.n + k + 5])
          acc = acc + uint32(b[i * p.n + k + 6]) * uint32(s[j * p.n + k + 6])
          acc = acc + uint32(b[i * p.n + k + 7]) * uint32(s[j * p.n + k + 7])
          k = k + 8
        result[i * p.nbar + j] = uint16(acc)
        j = j + 1
      i = i + 1

proc mulAddSbPlusE(p: FrodoParams, b, s, e: openArray[uint16]): seq[uint16] =
  ## Compute `s * b + e`.
  otterSpan("frodo.mulAddSbPlusE"):
    var
      j: int = 0
      k: int = 0
      iBar: int = 0
      acc: uint32 = 0
    result = newSeq[uint16](p.nbar * p.nbar)
    k = 0
    while k < p.nbar:
      iBar = 0
      while iBar < p.nbar:
        acc = 0'u32
        j = 0
        while j < p.n:
          acc = acc + uint32(s[k * p.n + j + 0]) * uint32(b[(j + 0) * p.nbar + iBar])
          acc = acc + uint32(s[k * p.n + j + 1]) * uint32(b[(j + 1) * p.nbar + iBar])
          acc = acc + uint32(s[k * p.n + j + 2]) * uint32(b[(j + 2) * p.nbar + iBar])
          acc = acc + uint32(s[k * p.n + j + 3]) * uint32(b[(j + 3) * p.nbar + iBar])
          acc = acc + uint32(s[k * p.n + j + 4]) * uint32(b[(j + 4) * p.nbar + iBar])
          acc = acc + uint32(s[k * p.n + j + 5]) * uint32(b[(j + 5) * p.nbar + iBar])
          acc = acc + uint32(s[k * p.n + j + 6]) * uint32(b[(j + 6) * p.nbar + iBar])
          acc = acc + uint32(s[k * p.n + j + 7]) * uint32(b[(j + 7) * p.nbar + iBar])
          j = j + 8
        result[k * p.nbar + iBar] = e[k * p.nbar + iBar] + uint16(acc)
        iBar = iBar + 1
      k = k + 1

proc addWords(p: FrodoParams, A, B: openArray[uint16]): seq[uint16] =
  var
    i: int = 0
  result = newSeq[uint16](A.len)
  i = 0
  while i < A.len:
    result[i] = A[i] + B[i]
    i = i + 1

proc subWords(p: FrodoParams, A, B: openArray[uint16]): seq[uint16] =
  var
    i: int = 0
  result = newSeq[uint16](A.len)
  i = 0
  while i < A.len:
    result[i] = A[i] - B[i]
    i = i + 1

proc keyEncode(p: FrodoParams, input: openArray[byte]): seq[uint16] =
  otterSpan("frodo.keyEncode"):
    var
      npiecesWord: int = 8
      nwords: int = (p.nbar * p.nbar) div 8
      mask: uint64 = (1'u64 shl p.extractedBits) - 1'u64
      i: int = 0
      j: int = 0
      temp: uint64 = 0
      pos: int = 0
    result = newSeq[uint16](p.nbar * p.nbar)
    i = 0
    while i < nwords:
      temp = 0'u64
      j = 0
      while j < p.extractedBits:
        temp = temp or (uint64(input[i * p.extractedBits + j]) shl (8 * j))
        j = j + 1
      j = 0
      while j < npiecesWord:
        result[pos] = uint16((temp and mask) shl (p.logQ - p.extractedBits))
        temp = temp shr p.extractedBits
        pos = pos + 1
        j = j + 1
      i = i + 1

proc keyDecode(p: FrodoParams, input: openArray[uint16]): seq[byte] =
  otterSpan("frodo.keyDecode"):
    var
      npiecesWord: int = 8
      nwords: int = (p.nbar * p.nbar) div 8
      index: int = 0
      i: int = 0
      j: int = 0
      temp: uint16 = 0
      maskEx: uint16 = (1'u16 shl p.extractedBits) - 1'u16
      maskQ: uint16 = (1'u16 shl p.logQ) - 1'u16
      tempLong: uint64 = 0
    result = newSeq[byte](p.bytesMu)
    i = 0
    while i < nwords:
      tempLong = 0'u64
      j = 0
      while j < npiecesWord:
        temp = ((input[index] and maskQ) + (1'u16 shl (p.logQ - p.extractedBits - 1))) shr
          (p.logQ - p.extractedBits)
        tempLong = tempLong or (uint64(temp and maskEx) shl (p.extractedBits * j))
        index = index + 1
        j = j + 1
      j = 0
      while j < p.extractedBits:
        result[i * p.extractedBits + j] = byte((tempLong shr (8 * j)) and 0xff'u64)
        j = j + 1
      i = i + 1
{.pop.}

proc frodoTyrKeypairDerand*(v: FrodoVariant, randomness: openArray[byte]): FrodoTyrKeypair =
    ## Generate a pure-Nim FrodoKEM keypair from explicit 64-byte randomness.
    var
      p: FrodoParams = params(v)
      wordCount: int = p.n * p.nbar
      pkSeedA: seq[byte] = @[]
      bWords: seq[uint16] = @[]
      seedSEWords: seq[uint16] = @[]
      pkh: seq[byte] = @[]
    if randomness.len != p.keypairRandomBytes:
      raise newException(ValueError, "Frodo976AES derand keypair requires 64 bytes")
    pkSeedA = newSeq[byte](p.bytesSeedA)
    shake256Into(pkSeedA, randomness.toOpenArray(48, 63))
    let seedSEInput = prefixed24(0x5f'u8, randomness.toOpenArray(24, 47))
    seedSEWords = newSeq[uint16](2 * wordCount)
    shake256WordsLeInto(seedSEWords, seedSEInput)
    frodoSampleN(p, seedSEWords.toOpenArray(0, wordCount - 1))
    frodoSampleN(p, seedSEWords.toOpenArray(wordCount, 2 * wordCount - 1))
    bWords = mulAddAsPlusEStreamPair(p, pkSeedA, seedSEWords, 0, wordCount)
    result.variant = v
    result.publicKey = newSeq[byte](p.publicKeyBytes)
    copyMem(addr result.publicKey[0], unsafeAddr pkSeedA[0], pkSeedA.len)
    frodoPackInto(result.publicKey.toOpenArray(p.bytesSeedA, result.publicKey.len - 1), bWords, p.logQ)
    pkh = newSeq[byte](p.bytesPkHash)
    shake256Into(pkh, result.publicKey)
    result.secretKey = newSeq[byte](p.secretKeyBytes)
    copyMem(addr result.secretKey[0], unsafeAddr randomness[0], p.sharedSecretBytes)
    copyMem(addr result.secretKey[p.sharedSecretBytes], unsafeAddr result.publicKey[0], result.publicKey.len)
    wordsToBytesLeInto(
      result.secretKey.toOpenArray(
        p.sharedSecretBytes + result.publicKey.len,
        p.sharedSecretBytes + result.publicKey.len + 2 * wordCount - 1
      ),
      seedSEWords.toOpenArray(0, wordCount - 1)
    )
    copyMem(addr result.secretKey[p.sharedSecretBytes + result.publicKey.len + 2 * wordCount],
      unsafeAddr pkh[0], pkh.len)
    clearWords(seedSEWords)
    clearWords(bWords)
    clearBytes(pkSeedA)
    clearBytes(pkh)

proc frodoTyrKeypair*(v: FrodoVariant, randomness: seq[byte] = @[]): FrodoTyrKeypair =
  ## Generate a pure-Nim FrodoKEM keypair.
  var
    material: seq[byte] = @[]
    i: int = 0
  if randomness.len > 0 and randomness.len != params(v).keypairRandomBytes:
    raise newException(ValueError, "Frodo976AES seeded keypair requires 64 bytes")
  if randomness.len == 0:
    material = cryptoRandomBytes(params(v).keypairRandomBytes)
  else:
    material = @randomness
  result = frodoTyrKeypairDerand(v, material)
  i = 0
  while i < material.len:
    material[i] = 0'u8
    i = i + 1

proc frodoTyrEncapsDerand*(v: FrodoVariant, pk: openArray[byte], mu: openArray[byte]): FrodoTyrCipher =
  ## Encapsulate against a pure-Nim Frodo public key from explicit `mu` randomness.
  var
    p: FrodoParams = params(v)
    wordCount: int = p.n * p.nbar
    noiseWordCount: int = (2 * p.n + p.nbar) * p.nbar
    ctC1Len: int = (p.logQ * p.n * p.nbar) div 8
    pkh: seq[byte] = @[]
    g2Out: seq[byte] = @[]
    noiseWords: seq[uint16] = @[]
    bpWords: seq[uint16] = @[]
    bWords: seq[uint16] = @[]
    vWords: seq[uint16] = @[]
    cWords: seq[uint16] = @[]
    fin: seq[byte] = @[]
  if pk.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid Frodo public key length")
  if mu.len != p.bytesMu:
    raise newException(ValueError, "Frodo encaps randomness must be 24 bytes")
  pkh = newSeq[byte](p.bytesPkHash)
  shake256Into(pkh, pk)
  let g2Input = concat24x2(pkh, mu)
  g2Out = newSeq[byte](2 * p.sharedSecretBytes)
  shake256Into(g2Out, g2Input)
  let spInput = prefixed24(0x96'u8, g2Out.toOpenArray(0, p.sharedSecretBytes - 1))
  noiseWords = newSeq[uint16](noiseWordCount)
  shake256WordsLeInto(noiseWords, spInput)
  frodoSampleN(p, noiseWords.toOpenArray(0, wordCount - 1))
  frodoSampleN(p, noiseWords.toOpenArray(wordCount, 2 * wordCount - 1))
  frodoSampleN(p, noiseWords.toOpenArray(2 * wordCount, noiseWordCount - 1))
  var
    pkSeedA: seq[byte] = copyByteSeq(pk.toOpenArray(0, p.bytesSeedA - 1))
  bpWords = mulAddSaPlusEStreamPair(p, pkSeedA, noiseWords, 0, wordCount)
  bWords = frodoUnpack(wordCount, pk.toOpenArray(p.bytesSeedA, pk.len - 1), p.logQ)
  vWords = mulAddSbPlusE(p, bWords,
    noiseWords.toOpenArray(0, wordCount - 1),
    noiseWords.toOpenArray(2 * wordCount, noiseWordCount - 1))
  cWords = keyEncode(p, mu)
  cWords = addWords(p, vWords, cWords)
  result.variant = v
  result.ciphertext = newSeq[byte](p.ciphertextBytes)
  frodoPackInto(result.ciphertext.toOpenArray(0, ctC1Len - 1), bpWords, p.logQ)
  frodoPackInto(result.ciphertext.toOpenArray(ctC1Len, result.ciphertext.len - 1), cWords, p.logQ)
  fin = newSeq[byte](result.ciphertext.len + p.sharedSecretBytes)
  copyMem(addr fin[0], unsafeAddr result.ciphertext[0], result.ciphertext.len)
  copyMem(addr fin[result.ciphertext.len], unsafeAddr g2Out[p.sharedSecretBytes], p.sharedSecretBytes)
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  shake256Into(result.sharedSecret, fin)
  clearBytes(pkh)
  clearBytes(pkSeedA)
  clearBytes(g2Out)
  clearBytes(fin)
  clearWords(noiseWords)
  clearWords(bpWords)
  clearWords(bWords)
  clearWords(vWords)
  clearWords(cWords)

proc frodoTyrEncaps*(v: FrodoVariant, pk: openArray[byte], randomness: seq[byte] = @[]): FrodoTyrCipher =
  ## Encapsulate against a pure-Nim Frodo public key.
  var
    mu: seq[byte] = @[]
    i: int = 0
  if randomness.len > 0 and randomness.len != params(v).encapsRandomBytes:
    raise newException(ValueError, "Frodo976AES seeded encaps requires 24 bytes")
  if randomness.len == 0:
    mu = cryptoRandomBytes(params(v).encapsRandomBytes)
  else:
    mu = @randomness
  result = frodoTyrEncapsDerand(v, pk, mu)
  i = 0
  while i < mu.len:
    mu[i] = 0'u8
    i = i + 1

proc frodoTyrDecaps*(v: FrodoVariant, sk, ct: openArray[byte]): seq[byte] =
  ## Decapsulate a Frodo ciphertext and return the shared secret.
  var
    p: FrodoParams = params(v)
    wordCount: int = p.n * p.nbar
    noiseWordCount: int = (2 * p.n + p.nbar) * p.nbar
    ctC1Len = (p.logQ * p.n * p.nbar) div 8
    bpWords: seq[uint16] = @[]
    cWords: seq[uint16] = @[]
    sWords: seq[uint16] = @[]
    wWords: seq[uint16] = @[]
    muPrime: seq[byte] = @[]
    g2Out: seq[byte] = @[]
    noiseWords: seq[uint16] = @[]
    bbpWords: seq[uint16] = @[]
    bWords: seq[uint16] = @[]
    ccWords: seq[uint16] = @[]
    skSOff = p.sharedSecretBytes + p.publicKeyBytes
    skPkOff = p.sharedSecretBytes
    skPkhOff = p.sharedSecretBytes + p.publicKeyBytes + 2 * p.n * p.nbar
    fin: seq[byte] = @[]
    selector: int8 = 0
    selected: seq[byte] = @[]
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid Frodo secret key length")
  if ct.len != p.ciphertextBytes:
    raise newException(ValueError, "invalid Frodo ciphertext length")
  bpWords = frodoUnpack(wordCount, ct.toOpenArray(0, ctC1Len - 1), p.logQ)
  cWords = frodoUnpack(p.nbar * p.nbar, ct.toOpenArray(ctC1Len, ct.len - 1), p.logQ)
  sWords = bytesToWordsLe(sk.toOpenArray(skSOff, skSOff + 2 * p.n * p.nbar - 1))
  wWords = mulBs(p, bpWords, sWords)
  wWords = subWords(p, cWords, wWords)
  muPrime = keyDecode(p, wWords)
  let g2Input = concat24x2(sk.toOpenArray(skPkhOff, skPkhOff + p.bytesPkHash - 1), muPrime)
  g2Out = newSeq[byte](2 * p.sharedSecretBytes)
  shake256Into(g2Out, g2Input)
  let spInput = prefixed24(0x96'u8, g2Out.toOpenArray(0, p.sharedSecretBytes - 1))
  noiseWords = newSeq[uint16](noiseWordCount)
  shake256WordsLeInto(noiseWords, spInput)
  frodoSampleN(p, noiseWords.toOpenArray(0, wordCount - 1))
  frodoSampleN(p, noiseWords.toOpenArray(wordCount, 2 * wordCount - 1))
  frodoSampleN(p, noiseWords.toOpenArray(2 * wordCount, noiseWordCount - 1))
  var
    decSeedA: seq[byte] = copyByteSeq(sk.toOpenArray(skPkOff, skPkOff + p.bytesSeedA - 1))
  bbpWords = mulAddSaPlusEStreamPair(p, decSeedA, noiseWords, 0, wordCount)
  bWords = frodoUnpack(wordCount,
    sk.toOpenArray(skPkOff + p.bytesSeedA, skPkOff + p.publicKeyBytes - 1), p.logQ)
  wWords = mulAddSbPlusE(p, bWords,
    noiseWords.toOpenArray(0, wordCount - 1),
    noiseWords.toOpenArray(2 * wordCount, noiseWordCount - 1))
  ccWords = addWords(p, wWords, keyEncode(p, muPrime))
  selector = ctVerifyWords(bpWords, bbpWords) or ctVerifyWords(cWords, ccWords)
  selected = newSeq[byte](p.sharedSecretBytes)
  ctSelectBytes(selected, g2Out.toOpenArray(p.sharedSecretBytes, g2Out.len - 1),
    sk.toOpenArray(0, p.sharedSecretBytes - 1), selector)
  fin = newSeq[byte](ct.len + selected.len)
  copyMem(addr fin[0], unsafeAddr ct[0], ct.len)
  copyMem(addr fin[ct.len], unsafeAddr selected[0], selected.len)
  result = newSeq[byte](p.sharedSecretBytes)
  shake256Into(result, fin)
  clearBytes(muPrime)
  clearBytes(decSeedA)
  clearBytes(g2Out)
  clearBytes(fin)
  clearBytes(selected)
  clearWords(bpWords)
  clearWords(cWords)
  clearWords(sWords)
  clearWords(wWords)
  clearWords(noiseWords)
  clearWords(bbpWords)
  clearWords(bWords)
  clearWords(ccWords)
