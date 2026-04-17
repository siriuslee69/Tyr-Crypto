## --------------------------------------------------------
## SHA3 SIMD <- batched Keccak-f[1600] via SIMD-Nexus lanes
## --------------------------------------------------------

import simd_nexus/simd/base_operations
import protocols/simd/generic_u64

when defined(avx2):
  {.passC: "-mavx2".}

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
  ## Shared with Kyber's batched SHAKE-based matrix/noise generation.
  shakeSimdDomainSuffix = 0x1f'u8
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

proc absorbFinalBlockFixed(S: var Sha3State, A: openArray[byte], o, rateBytes: int, domain: byte) =
  var
    blk: array[168, byte]
    take: int = 0
    i: int = 0
  doAssert rateBytes > 0 and rateBytes <= blk.len,
    "SHA3 SIMD fixed absorb requires a supported rate"
  take = A.len - o
  if take < 0:
    take = 0
  doAssert take < rateBytes,
    "SHA3 SIMD fixed absorb requires input shorter than the rate"
  i = 0
  while i < take:
    blk[i] = A[o + i]
    i = i + 1
  blk[take] = blk[take] xor domain
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

proc packMsgU64x2[INBYTES: static[int]](msgs: array[2, array[INBYTES, byte]], o: int): u64x2 {.inline.} =
  result = u64x2(mm_set_epi64x(
    cast[int64](load64Le(msgs[1], o)),
    cast[int64](load64Le(msgs[0], o))
  ))

proc keccakF1600Packed[T](s: var array[25, T]) =
  template chiRow(x0, x1, x2, x3, x4, y0, y1, y2, y3, y4: untyped) =
    x0 = y0 xor ((not y1) and y2)
    x1 = y1 xor ((not y2) and y3)
    x2 = y2 xor ((not y3) and y4)
    x3 = y3 xor ((not y4) and y0)
    x4 = y4 xor ((not y0) and y1)

  template rotLane(x: untyped, k: static[int32]): untyped =
    (x shl k) or (x shr (64 - k))

  var
    a0: T = s[0]
    a1: T = s[1]
    a2: T = s[2]
    a3: T = s[3]
    a4: T = s[4]
    a5: T = s[5]
    a6: T = s[6]
    a7: T = s[7]
    a8: T = s[8]
    a9: T = s[9]
    a10: T = s[10]
    a11: T = s[11]
    a12: T = s[12]
    a13: T = s[13]
    a14: T = s[14]
    a15: T = s[15]
    a16: T = s[16]
    a17: T = s[17]
    a18: T = s[18]
    a19: T = s[19]
    a20: T = s[20]
    a21: T = s[21]
    a22: T = s[22]
    a23: T = s[23]
    a24: T = s[24]
    c0: T = a0
    c1: T = a1
    c2: T = a2
    c3: T = a3
    c4: T = a4
    d0: T = a0
    d1: T = a1
    d2: T = a2
    d3: T = a3
    d4: T = a4
    b0: T = a0
    b1: T = a1
    b2: T = a2
    b3: T = a3
    b4: T = a4
    b5: T = a5
    b6: T = a6
    b7: T = a7
    b8: T = a8
    b9: T = a9
    b10: T = a10
    b11: T = a11
    b12: T = a12
    b13: T = a13
    b14: T = a14
    b15: T = a15
    b16: T = a16
    b17: T = a17
    b18: T = a18
    b19: T = a19
    b20: T = a20
    b21: T = a21
    b22: T = a22
    b23: T = a23
    b24: T = a24
    round: int = 0
  while round < keccakRoundConstantsSimd.len:
    c0 = a0 xor a5 xor a10 xor a15 xor a20
    c1 = a1 xor a6 xor a11 xor a16 xor a21
    c2 = a2 xor a7 xor a12 xor a17 xor a22
    c3 = a3 xor a8 xor a13 xor a18 xor a23
    c4 = a4 xor a9 xor a14 xor a19 xor a24

    d0 = c4 xor rotLane(c1, 1)
    d1 = c0 xor rotLane(c2, 1)
    d2 = c1 xor rotLane(c3, 1)
    d3 = c2 xor rotLane(c4, 1)
    d4 = c3 xor rotLane(c0, 1)

    a0 = a0 xor d0
    a5 = a5 xor d0
    a10 = a10 xor d0
    a15 = a15 xor d0
    a20 = a20 xor d0
    a1 = a1 xor d1
    a6 = a6 xor d1
    a11 = a11 xor d1
    a16 = a16 xor d1
    a21 = a21 xor d1
    a2 = a2 xor d2
    a7 = a7 xor d2
    a12 = a12 xor d2
    a17 = a17 xor d2
    a22 = a22 xor d2
    a3 = a3 xor d3
    a8 = a8 xor d3
    a13 = a13 xor d3
    a18 = a18 xor d3
    a23 = a23 xor d3
    a4 = a4 xor d4
    a9 = a9 xor d4
    a14 = a14 xor d4
    a19 = a19 xor d4
    a24 = a24 xor d4

    b0 = a0
    b10 = rotLane(a1, 1)
    b20 = rotLane(a2, 62)
    b5 = rotLane(a3, 28)
    b15 = rotLane(a4, 27)
    b16 = rotLane(a5, 36)
    b1 = rotLane(a6, 44)
    b11 = rotLane(a7, 6)
    b21 = rotLane(a8, 55)
    b6 = rotLane(a9, 20)
    b7 = rotLane(a10, 3)
    b17 = rotLane(a11, 10)
    b2 = rotLane(a12, 43)
    b12 = rotLane(a13, 25)
    b22 = rotLane(a14, 39)
    b23 = rotLane(a15, 41)
    b8 = rotLane(a16, 45)
    b18 = rotLane(a17, 15)
    b3 = rotLane(a18, 21)
    b13 = rotLane(a19, 8)
    b14 = rotLane(a20, 18)
    b24 = rotLane(a21, 2)
    b9 = rotLane(a22, 61)
    b19 = rotLane(a23, 56)
    b4 = rotLane(a24, 14)

    chiRow(a0, a1, a2, a3, a4, b0, b1, b2, b3, b4)
    chiRow(a5, a6, a7, a8, a9, b5, b6, b7, b8, b9)
    chiRow(a10, a11, a12, a13, a14, b10, b11, b12, b13, b14)
    chiRow(a15, a16, a17, a18, a19, b15, b16, b17, b18, b19)
    chiRow(a20, a21, a22, a23, a24, b20, b21, b22, b23, b24)

    a0 = a0 xor set1U64[T](keccakRoundConstantsSimd[round])
    round = round + 1

  s[0] = a0
  s[1] = a1
  s[2] = a2
  s[3] = a3
  s[4] = a4
  s[5] = a5
  s[6] = a6
  s[7] = a7
  s[8] = a8
  s[9] = a9
  s[10] = a10
  s[11] = a11
  s[12] = a12
  s[13] = a13
  s[14] = a14
  s[15] = a15
  s[16] = a16
  s[17] = a17
  s[18] = a18
  s[19] = a19
  s[20] = a20
  s[21] = a21
  s[22] = a22
  s[23] = a23
  s[24] = a24

proc keccakF1600Sse2x*(ss: var array[2, Sha3State]) =
  ## Apply Keccak-f[1600] to two independent states in parallel.
  var
    s = packState2(ss)
  keccakF1600Packed(s)
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

proc shake128AbsorbOnceSse2x*[INBYTES: static[int]](states: var array[2, Sha3State],
    msgs: array[2, array[INBYTES, byte]]) =
  ## Absorb two short equal-length messages into SHAKE128 states and permute them once in parallel.
  var
    lane: int = 0
  static:
    doAssert INBYTES < 168
  lane = 0
  while lane < 2:
    absorbFinalBlockFixed(states[lane], msgs[lane], 0, 168, shakeSimdDomainSuffix)
    lane = lane + 1
  keccakF1600Sse2x(states)

proc shake128SqueezeBlocksSse2x*[OUTBYTES: static[int]](states: var array[2, Sha3State],
    dst: var array[2, array[OUTBYTES, byte]]) {.raises: [].} =
  ## Squeeze a whole number of SHAKE128 blocks from two states in parallel.
  var
    produced: int = 0
    lane: int = 0
  static:
    doAssert OUTBYTES mod 168 == 0
  while produced < OUTBYTES:
    lane = 0
    while lane < 2:
      store64Le(dst[lane], produced + 0, states[lane][0])
      store64Le(dst[lane], produced + 8, states[lane][1])
      store64Le(dst[lane], produced + 16, states[lane][2])
      store64Le(dst[lane], produced + 24, states[lane][3])
      store64Le(dst[lane], produced + 32, states[lane][4])
      store64Le(dst[lane], produced + 40, states[lane][5])
      store64Le(dst[lane], produced + 48, states[lane][6])
      store64Le(dst[lane], produced + 56, states[lane][7])
      store64Le(dst[lane], produced + 64, states[lane][8])
      store64Le(dst[lane], produced + 72, states[lane][9])
      store64Le(dst[lane], produced + 80, states[lane][10])
      store64Le(dst[lane], produced + 88, states[lane][11])
      store64Le(dst[lane], produced + 96, states[lane][12])
      store64Le(dst[lane], produced + 104, states[lane][13])
      store64Le(dst[lane], produced + 112, states[lane][14])
      store64Le(dst[lane], produced + 120, states[lane][15])
      store64Le(dst[lane], produced + 128, states[lane][16])
      store64Le(dst[lane], produced + 136, states[lane][17])
      store64Le(dst[lane], produced + 144, states[lane][18])
      store64Le(dst[lane], produced + 152, states[lane][19])
      store64Le(dst[lane], produced + 160, states[lane][20])
      lane = lane + 1
    produced = produced + 168
    keccakF1600Sse2x(states)

proc shake256Sse2xInto*[OUTBYTES: static[int], INBYTES: static[int]](
    dst: var array[2, array[OUTBYTES, byte]], msgs: array[2, array[INBYTES, byte]]) =
  ## SHAKE256 over two short equal-length inputs in parallel.
  var
    states: array[2, Sha3State]
    produced: int = 0
    lane: int = 0
    blockBytes: int = 0
    i: int = 0
    take: int = 0
    laneBytes: array[8, byte]
  static:
    doAssert INBYTES < 136
  lane = 0
  while lane < 2:
    absorbFinalBlockFixed(states[lane], msgs[lane], 0, 136, shakeSimdDomainSuffix)
    lane = lane + 1
  keccakF1600Sse2x(states)
  while produced < OUTBYTES:
    blockBytes = 136
    if blockBytes > OUTBYTES - produced:
      blockBytes = OUTBYTES - produced
    lane = 0
    while lane < 2:
      i = 0
      while i * sha3SimdLaneBytes < blockBytes:
        store64Le(laneBytes, 0, states[lane][i])
        take = blockBytes - i * sha3SimdLaneBytes
        if take > sha3SimdLaneBytes:
          take = sha3SimdLaneBytes
        for j in 0 ..< take:
          dst[lane][produced + i * sha3SimdLaneBytes + j] = laneBytes[j]
        i = i + 1
      lane = lane + 1
    produced = produced + blockBytes
    if produced < OUTBYTES:
      keccakF1600Sse2x(states)

proc squeezeFirst16Sse2x[OUTBYTES: static[int]](
    dst: var array[2, array[OUTBYTES, byte]], s: array[25, u64x2]) =
  static:
    doAssert OUTBYTES == 16
  var
    lo = storeU64x2(s[0])
    hi = storeU64x2(s[1])
    lane: int = 0
  lane = 0
  while lane < 2:
    store64Le(dst[lane], 0, lo[lane])
    store64Le(dst[lane], 8, hi[lane])
    lane = lane + 1

proc shake256OneBlock64Sse2xLanesInto*[OUTBYTES: static[int]](
    dst: var array[2, array[OUTBYTES, byte]], l0, l1, l2, l3, l4, l5, l6, l7: u64x2) =
  ## Fixed 64-byte SHAKE256 absorb path for SPHINCS-style batched hashes.
  static:
    doAssert OUTBYTES == 16
  var
    s: array[25, u64x2]
  s[0] = l0
  s[1] = l1
  s[2] = l2
  s[3] = l3
  s[4] = l4
  s[5] = l5
  s[6] = l6
  s[7] = l7
  s[8] = set1U64[u64x2](uint64(shakeSimdDomainSuffix))
  s[(136 - 1) div sha3SimdLaneBytes] =
    set1U64[u64x2](0x80'u64 shl (8 * ((136 - 1) mod sha3SimdLaneBytes)))
  keccakF1600Packed(s)
  squeezeFirst16Sse2x(dst, s)

proc shake256OneBlockAlignedSse2xInto*[OUTBYTES: static[int], INBYTES: static[int]](
    dst: var array[2, array[OUTBYTES, byte]], msgs: array[2, array[INBYTES, byte]]) =
  ## SPHINCS-style one-block SHAKE256 over two aligned inputs without unpacking full states.
  static:
    doAssert OUTBYTES == 16
    doAssert INBYTES > 0
    doAssert INBYTES < 136
    doAssert (INBYTES mod sha3SimdLaneBytes) == 0
  var
    s: array[25, u64x2]
  when INBYTES == 64:
    s[0] = packMsgU64x2(msgs, 0)
    s[1] = packMsgU64x2(msgs, 8)
    s[2] = packMsgU64x2(msgs, 16)
    s[3] = packMsgU64x2(msgs, 24)
    s[4] = packMsgU64x2(msgs, 32)
    s[5] = packMsgU64x2(msgs, 40)
    s[6] = packMsgU64x2(msgs, 48)
    s[7] = packMsgU64x2(msgs, 56)
    s[8] = set1U64[u64x2](uint64(shakeSimdDomainSuffix))
  elif INBYTES == 80:
    s[0] = packMsgU64x2(msgs, 0)
    s[1] = packMsgU64x2(msgs, 8)
    s[2] = packMsgU64x2(msgs, 16)
    s[3] = packMsgU64x2(msgs, 24)
    s[4] = packMsgU64x2(msgs, 32)
    s[5] = packMsgU64x2(msgs, 40)
    s[6] = packMsgU64x2(msgs, 48)
    s[7] = packMsgU64x2(msgs, 56)
    s[8] = packMsgU64x2(msgs, 64)
    s[9] = packMsgU64x2(msgs, 72)
    s[10] = set1U64[u64x2](uint64(shakeSimdDomainSuffix))
  else:
    var lane: int = 0
    while lane * sha3SimdLaneBytes < INBYTES:
      s[lane] = packMsgU64x2(msgs, lane * sha3SimdLaneBytes)
      lane = lane + 1
    s[INBYTES div sha3SimdLaneBytes] =
      s[INBYTES div sha3SimdLaneBytes] xor set1U64[u64x2](uint64(shakeSimdDomainSuffix))
  s[(136 - 1) div sha3SimdLaneBytes] =
    s[(136 - 1) div sha3SimdLaneBytes] xor
    set1U64[u64x2](0x80'u64 shl (8 * ((136 - 1) mod sha3SimdLaneBytes)))
  keccakF1600Packed(s)
  squeezeFirst16Sse2x(dst, s)

when defined(avx2):
  proc packMsgU64x4[INBYTES: static[int]](msgs: array[4, array[INBYTES, byte]], o: int): u64x4 {.inline.} =
    result = u64x4(mm256_set_epi64x(
      cast[int64](load64Le(msgs[3], o)),
      cast[int64](load64Le(msgs[2], o)),
      cast[int64](load64Le(msgs[1], o)),
      cast[int64](load64Le(msgs[0], o))
    ))

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
    keccakF1600Packed(s)
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

  proc shake128AbsorbOnceAvx4x*[INBYTES: static[int]](states: var array[4, Sha3State],
      msgs: array[4, array[INBYTES, byte]]) {.raises: [].} =
    ## Absorb four short equal-length messages into SHAKE128 states and permute them once in parallel.
    var
      lane: int = 0
    static:
      doAssert INBYTES < 168
    lane = 0
    while lane < 4:
      absorbFinalBlockFixed(states[lane], msgs[lane], 0, 168, shakeSimdDomainSuffix)
      lane = lane + 1
    keccakF1600Avx4x(states)

  proc shake128SqueezeBlocksAvx4x*[OUTBYTES: static[int]](states: var array[4, Sha3State],
      dst: var array[4, array[OUTBYTES, byte]]) {.raises: [].} =
    ## Squeeze a whole number of SHAKE128 blocks from four states in parallel.
    var
      produced: int = 0
      lane: int = 0
    static:
      doAssert OUTBYTES mod 168 == 0
    while produced < OUTBYTES:
      lane = 0
      while lane < 4:
        store64Le(dst[lane], produced + 0, states[lane][0])
        store64Le(dst[lane], produced + 8, states[lane][1])
        store64Le(dst[lane], produced + 16, states[lane][2])
        store64Le(dst[lane], produced + 24, states[lane][3])
        store64Le(dst[lane], produced + 32, states[lane][4])
        store64Le(dst[lane], produced + 40, states[lane][5])
        store64Le(dst[lane], produced + 48, states[lane][6])
        store64Le(dst[lane], produced + 56, states[lane][7])
        store64Le(dst[lane], produced + 64, states[lane][8])
        store64Le(dst[lane], produced + 72, states[lane][9])
        store64Le(dst[lane], produced + 80, states[lane][10])
        store64Le(dst[lane], produced + 88, states[lane][11])
        store64Le(dst[lane], produced + 96, states[lane][12])
        store64Le(dst[lane], produced + 104, states[lane][13])
        store64Le(dst[lane], produced + 112, states[lane][14])
        store64Le(dst[lane], produced + 120, states[lane][15])
        store64Le(dst[lane], produced + 128, states[lane][16])
        store64Le(dst[lane], produced + 136, states[lane][17])
        store64Le(dst[lane], produced + 144, states[lane][18])
        store64Le(dst[lane], produced + 152, states[lane][19])
        store64Le(dst[lane], produced + 160, states[lane][20])
        lane = lane + 1
      produced = produced + 168
      keccakF1600Avx4x(states)

  proc shake256AbsorbOnceAvx4x*[INBYTES: static[int]](states: var array[4, Sha3State],
      msgs: array[4, array[INBYTES, byte]]) {.raises: [].} =
    ## Stateful SHAKE256 x4 entry point for Dilithium's batched rejection samplers.
    var
      lane: int = 0
    static:
      doAssert INBYTES < 136
    lane = 0
    while lane < 4:
      absorbFinalBlockFixed(states[lane], msgs[lane], 0, 136, shakeSimdDomainSuffix)
      lane = lane + 1
    keccakF1600Avx4x(states)

  proc shake256SqueezeBlocksAvx4x*[OUTBYTES: static[int]](states: var array[4, Sha3State],
      dst: var array[4, array[OUTBYTES, byte]]) {.raises: [].} =
    ## Squeeze a whole number of SHAKE256 blocks from four states in parallel.
    var
      produced: int = 0
      lane: int = 0
    static:
      doAssert OUTBYTES mod 136 == 0
    while produced < OUTBYTES:
      lane = 0
      while lane < 4:
        store64Le(dst[lane], produced + 0, states[lane][0])
        store64Le(dst[lane], produced + 8, states[lane][1])
        store64Le(dst[lane], produced + 16, states[lane][2])
        store64Le(dst[lane], produced + 24, states[lane][3])
        store64Le(dst[lane], produced + 32, states[lane][4])
        store64Le(dst[lane], produced + 40, states[lane][5])
        store64Le(dst[lane], produced + 48, states[lane][6])
        store64Le(dst[lane], produced + 56, states[lane][7])
        store64Le(dst[lane], produced + 64, states[lane][8])
        store64Le(dst[lane], produced + 72, states[lane][9])
        store64Le(dst[lane], produced + 80, states[lane][10])
        store64Le(dst[lane], produced + 88, states[lane][11])
        store64Le(dst[lane], produced + 96, states[lane][12])
        store64Le(dst[lane], produced + 104, states[lane][13])
        store64Le(dst[lane], produced + 112, states[lane][14])
        store64Le(dst[lane], produced + 120, states[lane][15])
        store64Le(dst[lane], produced + 128, states[lane][16])
        lane = lane + 1
      produced = produced + 136
      keccakF1600Avx4x(states)

  proc shake256Avx4xInto*[OUTBYTES: static[int], INBYTES: static[int]](
      dst: var array[4, array[OUTBYTES, byte]], msgs: array[4, array[INBYTES, byte]]) =
    ## SHAKE256 over four short equal-length inputs in parallel.
    var
      states: array[4, Sha3State]
      produced: int = 0
      lane: int = 0
      blockBytes: int = 0
      i: int = 0
      take: int = 0
      laneBytes: array[8, byte]
    static:
      doAssert INBYTES < 136
    lane = 0
    while lane < 4:
      absorbFinalBlockFixed(states[lane], msgs[lane], 0, 136, shakeSimdDomainSuffix)
      lane = lane + 1
    keccakF1600Avx4x(states)
    while produced < OUTBYTES:
      blockBytes = 136
      if blockBytes > OUTBYTES - produced:
        blockBytes = OUTBYTES - produced
      lane = 0
      while lane < 4:
        i = 0
        while i * sha3SimdLaneBytes < blockBytes:
          store64Le(laneBytes, 0, states[lane][i])
          take = blockBytes - i * sha3SimdLaneBytes
          if take > sha3SimdLaneBytes:
            take = sha3SimdLaneBytes
          for j in 0 ..< take:
            dst[lane][produced + i * sha3SimdLaneBytes + j] = laneBytes[j]
          i = i + 1
        lane = lane + 1
      produced = produced + blockBytes
      if produced < OUTBYTES:
        keccakF1600Avx4x(states)

  proc squeezeFirst16Avx4x[OUTBYTES: static[int]](
      dst: var array[4, array[OUTBYTES, byte]], s: array[25, u64x4]) =
    static:
      doAssert OUTBYTES == 16
    var
      lo = storeU64x4(s[0])
      hi = storeU64x4(s[1])
      lane: int = 0
    lane = 0
    while lane < 4:
      store64Le(dst[lane], 0, lo[lane])
      store64Le(dst[lane], 8, hi[lane])
      lane = lane + 1

  proc shake256OneBlock64Avx4xLanesInto*[OUTBYTES: static[int]](
      dst: var array[4, array[OUTBYTES, byte]], l0, l1, l2, l3, l4, l5, l6, l7: u64x4) =
    ## Fixed 64-byte SHAKE256 absorb path for SPHINCS-style batched hashes.
    static:
      doAssert OUTBYTES == 16
    var
      s: array[25, u64x4]
    s[0] = l0
    s[1] = l1
    s[2] = l2
    s[3] = l3
    s[4] = l4
    s[5] = l5
    s[6] = l6
    s[7] = l7
    s[8] = set1U64[u64x4](uint64(shakeSimdDomainSuffix))
    s[(136 - 1) div sha3SimdLaneBytes] =
      set1U64[u64x4](0x80'u64 shl (8 * ((136 - 1) mod sha3SimdLaneBytes)))
    keccakF1600Packed(s)
    squeezeFirst16Avx4x(dst, s)

  proc shake256OneBlockAlignedAvx4xInto*[OUTBYTES: static[int], INBYTES: static[int]](
      dst: var array[4, array[OUTBYTES, byte]], msgs: array[4, array[INBYTES, byte]]) =
    ## SPHINCS-style one-block SHAKE256 over four aligned inputs without unpacking full states.
    static:
      doAssert OUTBYTES == 16
      doAssert INBYTES > 0
      doAssert INBYTES < 136
      doAssert (INBYTES mod sha3SimdLaneBytes) == 0
    var
      s: array[25, u64x4]
    when INBYTES == 64:
      s[0] = packMsgU64x4(msgs, 0)
      s[1] = packMsgU64x4(msgs, 8)
      s[2] = packMsgU64x4(msgs, 16)
      s[3] = packMsgU64x4(msgs, 24)
      s[4] = packMsgU64x4(msgs, 32)
      s[5] = packMsgU64x4(msgs, 40)
      s[6] = packMsgU64x4(msgs, 48)
      s[7] = packMsgU64x4(msgs, 56)
      s[8] = set1U64[u64x4](uint64(shakeSimdDomainSuffix))
    elif INBYTES == 80:
      s[0] = packMsgU64x4(msgs, 0)
      s[1] = packMsgU64x4(msgs, 8)
      s[2] = packMsgU64x4(msgs, 16)
      s[3] = packMsgU64x4(msgs, 24)
      s[4] = packMsgU64x4(msgs, 32)
      s[5] = packMsgU64x4(msgs, 40)
      s[6] = packMsgU64x4(msgs, 48)
      s[7] = packMsgU64x4(msgs, 56)
      s[8] = packMsgU64x4(msgs, 64)
      s[9] = packMsgU64x4(msgs, 72)
      s[10] = set1U64[u64x4](uint64(shakeSimdDomainSuffix))
    else:
      var lane: int = 0
      while lane * sha3SimdLaneBytes < INBYTES:
        s[lane] = packMsgU64x4(msgs, lane * sha3SimdLaneBytes)
        lane = lane + 1
      s[INBYTES div sha3SimdLaneBytes] =
        s[INBYTES div sha3SimdLaneBytes] xor set1U64[u64x4](uint64(shakeSimdDomainSuffix))
    s[(136 - 1) div sha3SimdLaneBytes] =
      s[(136 - 1) div sha3SimdLaneBytes] xor
      set1U64[u64x4](0x80'u64 shl (8 * ((136 - 1) mod sha3SimdLaneBytes)))
    keccakF1600Packed(s)
    squeezeFirst16Avx4x(dst, s)
