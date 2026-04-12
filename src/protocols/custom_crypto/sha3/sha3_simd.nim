## --------------------------------------------------------
## SHA3 SIMD <- batched Keccak-f[1600] via SIMD-Nexus lanes
## --------------------------------------------------------

import simd_nexus/simd/base_operations
import protocols/simd/generic_u64

when not declared(Sha3Variant):
  type
    Sha3Variant = enum
      svSha3_224,
      svSha3_256,
      svSha3_384,
      svSha3_512

when not declared(Sha3State):
  type
    Sha3State = array[25, uint64]

const
  sha3SimdDomainSuffix = 0x06'u8
  sha3SimdLaneBytes = 8
  keccakRoundConstantsSimd: array[24, uint64] = [
    0x0000000000000001'u64, 0x0000000000008082'u64,
    0x800000000000808a'u64, 0x8000000080008000'u64,
    0x000000000000808b'u64, 0x0000000080000001'u64,
    0x8000000080008081'u64, 0x8000000000008009'u64,
    0x000000000000008a'u64, 0x0000000000000088'u64,
    0x0000000080008009'u64, 0x000000008000000a'u64,
    0x000000008000808b'u64, 0x800000000000008b'u64,
    0x8000000000008089'u64, 0x8000000000008003'u64,
    0x8000000000008002'u64, 0x8000000000000080'u64,
    0x000000000000800a'u64, 0x800000008000000a'u64,
    0x8000000080008081'u64, 0x8000000000008080'u64,
    0x0000000080000001'u64, 0x8000000080008008'u64
  ]
  keccakRhoOffsetsSimd: array[25, int32] = [
    0'i32, 1'i32, 62'i32, 28'i32, 27'i32,
    36'i32, 44'i32, 6'i32, 55'i32, 20'i32,
    3'i32, 10'i32, 43'i32, 25'i32, 39'i32,
    41'i32, 45'i32, 15'i32, 21'i32, 8'i32,
    18'i32, 2'i32, 61'i32, 56'i32, 14'i32
  ]

proc sha3DigestBytesSimd(v: Sha3Variant): int =
  case v
  of svSha3_224:
    result = 28
  of svSha3_256:
    result = 32
  of svSha3_384:
    result = 48
  of svSha3_512:
    result = 64

proc sha3RateBytesSimd(v: Sha3Variant): int =
  case v
  of svSha3_224:
    result = 144
  of svSha3_256:
    result = 136
  of svSha3_384:
    result = 104
  of svSha3_512:
    result = 72

proc sha3VariantFromOutLenSimd(outLen: int): Sha3Variant =
  case outLen
  of 28:
    result = svSha3_224
  of 32:
    result = svSha3_256
  of 48:
    result = svSha3_384
  of 64:
    result = svSha3_512
  else:
    raise newException(ValueError,
      "sha3 output length must be one of 28, 32, 48, or 64")

proc laneIdx(x, y: int): int {.inline.} =
  result = x + y * 5

proc load64Le(A: openArray[byte], o: int): uint64 {.inline.} =
  result =
    uint64(A[o]) or
    (uint64(A[o + 1]) shl 8) or
    (uint64(A[o + 2]) shl 16) or
    (uint64(A[o + 3]) shl 24) or
    (uint64(A[o + 4]) shl 32) or
    (uint64(A[o + 5]) shl 40) or
    (uint64(A[o + 6]) shl 48) or
    (uint64(A[o + 7]) shl 56)

proc store64Le(A: var openArray[byte], o: int, v: uint64) {.inline.} =
  A[o] = byte(v and 0xff'u64)
  A[o + 1] = byte((v shr 8) and 0xff'u64)
  A[o + 2] = byte((v shr 16) and 0xff'u64)
  A[o + 3] = byte((v shr 24) and 0xff'u64)
  A[o + 4] = byte((v shr 32) and 0xff'u64)
  A[o + 5] = byte((v shr 40) and 0xff'u64)
  A[o + 6] = byte((v shr 48) and 0xff'u64)
  A[o + 7] = byte((v shr 56) and 0xff'u64)

proc absorbBlock(S: var Sha3State, A: openArray[byte], o, rateBytes: int) =
  var
    lane: int = 0
    laneCount: int = 0
  laneCount = rateBytes div sha3SimdLaneBytes
  lane = 0
  while lane < laneCount:
    S[lane] = S[lane] xor load64Le(A, o + lane * sha3SimdLaneBytes)
    lane = lane + 1

proc absorbFinalBlock(S: var Sha3State, A: openArray[byte], o, rateBytes: int) =
  var
    blk: seq[byte] = @[]
    take: int = 0
    i: int = 0
  blk = newSeq[byte](rateBytes)
  take = A.len - o
  if take < 0:
    take = 0
  i = 0
  while i < take:
    blk[i] = A[o + i]
    i = i + 1
  blk[take] = blk[take] xor sha3SimdDomainSuffix
  blk[rateBytes - 1] = blk[rateBytes - 1] xor 0x80'u8
  absorbBlock(S, blk, 0, rateBytes)

proc squeezeBlock(S: Sha3State, outLen: int): seq[byte] =
  var
    i: int = 0
    laneBytes: array[8, byte]
    produced: int = 0
    take: int = 0
  result = newSeq[byte](outLen)
  while produced < outLen:
    store64Le(laneBytes, 0, S[i])
    take = outLen - produced
    if take > 8:
      take = 8
    for j in 0 ..< take:
      result[produced + j] = laneBytes[j]
    produced = produced + take
    i = i + 1

proc packState2(ss: array[2, Sha3State]): array[25, u64x2] =
  var
    i: int = 0
    laneVals: array[2, uint64]
  while i < 25:
    laneVals[0] = ss[0][i]
    laneVals[1] = ss[1][i]
    result[i] = loadU64x2[u64x2](laneVals)
    i = i + 1

proc unpackState2(vs: array[25, u64x2]): array[2, Sha3State] =
  var
    i: int = 0
    laneVals: array[2, uint64]
  while i < 25:
    laneVals = storeU64x2(vs[i])
    result[0][i] = laneVals[0]
    result[1][i] = laneVals[1]
    i = i + 1

proc keccakF1600Sse2x*(ss: var array[2, Sha3State]) =
  ## Apply Keccak-f[1600] to two independent states in parallel.
  var
    s = packState2(ss)
    b: array[25, u64x2]
    c: array[5, u64x2]
    d: array[5, u64x2]
    round: int = 0
    x: int = 0
    y: int = 0
  while round < keccakRoundConstantsSimd.len:
    x = 0
    while x < 5:
      c[x] = s[laneIdx(x, 0)] xor s[laneIdx(x, 1)] xor s[laneIdx(x, 2)] xor
        s[laneIdx(x, 3)] xor s[laneIdx(x, 4)]
      x = x + 1
    x = 0
    while x < 5:
      d[x] = c[(x + 4) mod 5] xor rotl64(c[(x + 1) mod 5], 1)
      x = x + 1
    y = 0
    while y < 5:
      x = 0
      while x < 5:
        s[laneIdx(x, y)] = s[laneIdx(x, y)] xor d[x]
        x = x + 1
      y = y + 1
    y = 0
    while y < 5:
      x = 0
      while x < 5:
        b[laneIdx(y, (2 * x + 3 * y) mod 5)] =
          rotl64(s[laneIdx(x, y)], keccakRhoOffsetsSimd[laneIdx(x, y)])
        x = x + 1
      y = y + 1
    y = 0
    while y < 5:
      x = 0
      while x < 5:
        s[laneIdx(x, y)] = b[laneIdx(x, y)] xor
          ((not b[laneIdx((x + 1) mod 5, y)]) and b[laneIdx((x + 2) mod 5, y)])
        x = x + 1
      y = y + 1
    s[0] = s[0] xor set1U64[u64x2](keccakRoundConstantsSimd[round])
    round = round + 1
  ss = unpackState2(s)

proc sha3HashSse2x*(msgs: array[2, seq[byte]], outLen: int = 32): array[2, seq[byte]] =
  ## Hash two equal-length messages in parallel with the same SHA3 output length.
  var
    states: array[2, Sha3State]
    variant = sha3VariantFromOutLenSimd(outLen)
    rateBytes: int = sha3RateBytesSimd(variant)
    msgLen: int = msgs[0].len
    offset: int = 0
    lane: int = 0
  if msgs[1].len != msgLen:
    raise newException(ValueError, "sha3 SIMD batch requires equal-length messages")
  while offset + rateBytes <= msgLen:
    lane = 0
    while lane < 2:
      absorbBlock(states[lane], msgs[lane], offset, rateBytes)
      lane = lane + 1
    keccakF1600Sse2x(states)
    offset = offset + rateBytes
  lane = 0
  while lane < 2:
    absorbFinalBlock(states[lane], msgs[lane], offset, rateBytes)
    lane = lane + 1
  keccakF1600Sse2x(states)
  lane = 0
  while lane < 2:
    result[lane] = squeezeBlock(states[lane], sha3DigestBytesSimd(variant))
    lane = lane + 1

when defined(avx2):
  proc packState4(ss: array[4, Sha3State]): array[25, u64x4] =
    var
      i: int = 0
      laneVals: array[4, uint64]
    while i < 25:
      laneVals[0] = ss[0][i]
      laneVals[1] = ss[1][i]
      laneVals[2] = ss[2][i]
      laneVals[3] = ss[3][i]
      result[i] = loadU64x4[u64x4](laneVals)
      i = i + 1

  proc unpackState4(vs: array[25, u64x4]): array[4, Sha3State] =
    var
      i: int = 0
      laneVals: array[4, uint64]
    while i < 25:
      laneVals = storeU64x4(vs[i])
      result[0][i] = laneVals[0]
      result[1][i] = laneVals[1]
      result[2][i] = laneVals[2]
      result[3][i] = laneVals[3]
      i = i + 1

  proc keccakF1600Avx4x*(ss: var array[4, Sha3State]) =
    ## Apply Keccak-f[1600] to four independent states in parallel.
    var
      s = packState4(ss)
      b: array[25, u64x4]
      c: array[5, u64x4]
      d: array[5, u64x4]
      round: int = 0
      x: int = 0
      y: int = 0
    while round < keccakRoundConstantsSimd.len:
      x = 0
      while x < 5:
        c[x] = s[laneIdx(x, 0)] xor s[laneIdx(x, 1)] xor s[laneIdx(x, 2)] xor
          s[laneIdx(x, 3)] xor s[laneIdx(x, 4)]
        x = x + 1
      x = 0
      while x < 5:
        d[x] = c[(x + 4) mod 5] xor rotl64(c[(x + 1) mod 5], 1)
        x = x + 1
      y = 0
      while y < 5:
        x = 0
        while x < 5:
          s[laneIdx(x, y)] = s[laneIdx(x, y)] xor d[x]
          x = x + 1
        y = y + 1
      y = 0
      while y < 5:
        x = 0
        while x < 5:
          b[laneIdx(y, (2 * x + 3 * y) mod 5)] =
            rotl64(s[laneIdx(x, y)], keccakRhoOffsetsSimd[laneIdx(x, y)])
          x = x + 1
        y = y + 1
      y = 0
      while y < 5:
        x = 0
        while x < 5:
          s[laneIdx(x, y)] = b[laneIdx(x, y)] xor
            ((not b[laneIdx((x + 1) mod 5, y)]) and b[laneIdx((x + 2) mod 5, y)])
          x = x + 1
        y = y + 1
      s[0] = s[0] xor set1U64[u64x4](keccakRoundConstantsSimd[round])
      round = round + 1
    ss = unpackState4(s)

  proc sha3HashAvx4x*(msgs: array[4, seq[byte]], outLen: int = 32): array[4, seq[byte]] =
    ## Hash four equal-length messages in parallel with the same SHA3 output length.
    var
      states: array[4, Sha3State]
      variant = sha3VariantFromOutLenSimd(outLen)
      rateBytes: int = sha3RateBytesSimd(variant)
      msgLen: int = msgs[0].len
      offset: int = 0
      lane: int = 0
    lane = 1
    while lane < 4:
      if msgs[lane].len != msgLen:
        raise newException(ValueError, "sha3 SIMD batch requires equal-length messages")
      lane = lane + 1
    while offset + rateBytes <= msgLen:
      lane = 0
      while lane < 4:
        absorbBlock(states[lane], msgs[lane], offset, rateBytes)
        lane = lane + 1
      keccakF1600Avx4x(states)
      offset = offset + rateBytes
    lane = 0
    while lane < 4:
      absorbFinalBlock(states[lane], msgs[lane], offset, rateBytes)
      lane = lane + 1
    keccakF1600Avx4x(states)
    lane = 0
    while lane < 4:
      result[lane] = squeezeBlock(states[lane], sha3DigestBytesSimd(variant))
      lane = lane + 1
