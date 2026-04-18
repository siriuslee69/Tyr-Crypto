## ---------------------------------------------------------------
## Poly1305 SIMD <- same-length batched Poly1305 using SIMD-Nexus
## ---------------------------------------------------------------

import simd_nexus/simd/base_operations
import protocols/simd/generic_u64

when not declared(Poly1305Tag):
  const
    poly1305KeyBytes = 32
    poly1305TagBytes = 16
    poly1305BlockBytes = 16
    poly1305Mask26 = 0x3ffffff'u64
    poly1305Hibit = 1'u64 shl 24
  type
    Poly1305Tag = array[poly1305TagBytes, byte]

proc load32Le(A: openArray[byte], o: int): uint32 {.inline.} =
  result =
    uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or
    (uint32(A[o + 3]) shl 24)

proc store32Le(A: var openArray[byte], o: int, v: uint32) {.inline.} =
  A[o] = byte(v and 0xff'u32)
  A[o + 1] = byte((v shr 8) and 0xff'u32)
  A[o + 2] = byte((v shr 16) and 0xff'u32)
  A[o + 3] = byte((v shr 24) and 0xff'u32)

proc finalizeTag(h0In, h1In, h2In, h3In, h4In: uint64,
    pad0, pad1, pad2, pad3: uint32): Poly1305Tag =
  var
    h0 = h0In
    h1 = h1In
    h2 = h2In
    h3 = h3In
    h4 = h4In
    c: uint64 = 0
    g0: uint64 = 0
    g1: uint64 = 0
    g2: uint64 = 0
    g3: uint64 = 0
    g4: uint64 = 0
    mask: uint64 = 0
    f: uint64 = 0
    w0: uint32 = 0
    w1: uint32 = 0
    w2: uint32 = 0
    w3: uint32 = 0
  c = h1 shr 26
  h1 = h1 and poly1305Mask26
  h2 = h2 + c
  c = h2 shr 26
  h2 = h2 and poly1305Mask26
  h3 = h3 + c
  c = h3 shr 26
  h3 = h3 and poly1305Mask26
  h4 = h4 + c
  c = h4 shr 26
  h4 = h4 and poly1305Mask26
  h0 = h0 + c * 5'u64
  c = h0 shr 26
  h0 = h0 and poly1305Mask26
  h1 = h1 + c

  g0 = h0 + 5'u64
  c = g0 shr 26
  g0 = g0 and poly1305Mask26
  g1 = h1 + c
  c = g1 shr 26
  g1 = g1 and poly1305Mask26
  g2 = h2 + c
  c = g2 shr 26
  g2 = g2 and poly1305Mask26
  g3 = h3 + c
  c = g3 shr 26
  g3 = g3 and poly1305Mask26
  g4 = h4 + c - (1'u64 shl 26)

  mask = (g4 shr 63) - 1'u64
  g0 = g0 and mask
  g1 = g1 and mask
  g2 = g2 and mask
  g3 = g3 and mask
  g4 = g4 and mask
  mask = not mask
  h0 = (h0 and mask) or g0
  h1 = (h1 and mask) or g1
  h2 = (h2 and mask) or g2
  h3 = (h3 and mask) or g3
  h4 = (h4 and mask) or g4

  w0 = uint32((h0 or (h1 shl 26)) and 0xffffffff'u64)
  w1 = uint32(((h1 shr 6) or (h2 shl 20)) and 0xffffffff'u64)
  w2 = uint32(((h2 shr 12) or (h3 shl 14)) and 0xffffffff'u64)
  w3 = uint32(((h3 shr 18) or (h4 shl 8)) and 0xffffffff'u64)

  f = uint64(w0) + uint64(pad0)
  w0 = uint32(f and 0xffffffff'u64)
  f = uint64(w1) + uint64(pad1) + (f shr 32)
  w1 = uint32(f and 0xffffffff'u64)
  f = uint64(w2) + uint64(pad2) + (f shr 32)
  w2 = uint32(f and 0xffffffff'u64)
  f = uint64(w3) + uint64(pad3) + (f shr 32)
  w3 = uint32(f and 0xffffffff'u64)

  store32Le(result, 0, w0)
  store32Le(result, 4, w1)
  store32Le(result, 8, w2)
  store32Le(result, 12, w3)

proc poly1305MacBatchImpl[T: SimdU64](
    keys: openArray[array[poly1305KeyBytes, byte]],
    msgs: openArray[seq[byte]]
  ): seq[Poly1305Tag] =
  const lanes = lanesU64[T]()

  template pack(vals: untyped): untyped =
    when lanes == 2:
      loadU64x2[u64x2](vals)
    else:
      loadU64x4[u64x4](vals)

  template unpack(v: untyped): untyped =
    when lanes == 2:
      storeU64x2(v)
    else:
      storeU64x4(v)

  var
    msgLen: int = 0
    offset: int = 0
    rem: int = 0
    lane: int = 0
    cVec: T
    mask26Vec = set1U64[T](poly1305Mask26)
    r0Vals: array[lanes, uint64]
    r1Vals: array[lanes, uint64]
    r2Vals: array[lanes, uint64]
    r3Vals: array[lanes, uint64]
    r4Vals: array[lanes, uint64]
    s1Vals: array[lanes, uint64]
    s2Vals: array[lanes, uint64]
    s3Vals: array[lanes, uint64]
    s4Vals: array[lanes, uint64]
    pad0Vals: array[lanes, uint32]
    pad1Vals: array[lanes, uint32]
    pad2Vals: array[lanes, uint32]
    pad3Vals: array[lanes, uint32]
    h0Vals: array[lanes, uint64]
    h1Vals: array[lanes, uint64]
    h2Vals: array[lanes, uint64]
    h3Vals: array[lanes, uint64]
    h4Vals: array[lanes, uint64]
    d0Vals: array[lanes, uint64]
    d1Vals: array[lanes, uint64]
    d2Vals: array[lanes, uint64]
    d3Vals: array[lanes, uint64]
    d4Vals: array[lanes, uint64]
    blk: array[lanes, array[poly1305BlockBytes, byte]]
    hibit: uint64 = 0
    h0, h1, h2, h3, h4: T
  if keys.len != lanes or msgs.len != lanes:
    raise newException(ValueError, "poly1305 SIMD batch requires exactly " & $lanes & " lanes")
  msgLen = msgs[0].len
  lane = 1
  while lane < lanes:
    if msgs[lane].len != msgLen:
      raise newException(ValueError, "poly1305 SIMD batch requires equal-length messages")
    lane = lane + 1
  lane = 0
  while lane < lanes:
    r0Vals[lane] = uint64(load32Le(keys[lane], 0) and 0x3ffffff'u32)
    r1Vals[lane] = uint64((load32Le(keys[lane], 3) shr 2) and 0x3ffff03'u32)
    r2Vals[lane] = uint64((load32Le(keys[lane], 6) shr 4) and 0x3ffc0ff'u32)
    r3Vals[lane] = uint64((load32Le(keys[lane], 9) shr 6) and 0x3f03fff'u32)
    r4Vals[lane] = uint64((load32Le(keys[lane], 12) shr 8) and 0x00fffff'u32)
    s1Vals[lane] = r1Vals[lane] * 5'u64
    s2Vals[lane] = r2Vals[lane] * 5'u64
    s3Vals[lane] = r3Vals[lane] * 5'u64
    s4Vals[lane] = r4Vals[lane] * 5'u64
    pad0Vals[lane] = load32Le(keys[lane], 16)
    pad1Vals[lane] = load32Le(keys[lane], 20)
    pad2Vals[lane] = load32Le(keys[lane], 24)
    pad3Vals[lane] = load32Le(keys[lane], 28)
    lane = lane + 1
  h0 = pack(h0Vals)
  h1 = pack(h1Vals)
  h2 = pack(h2Vals)
  h3 = pack(h3Vals)
  h4 = pack(h4Vals)

  offset = 0
  while offset + poly1305BlockBytes <= msgLen:
    lane = 0
    hibit = poly1305Hibit
    while lane < lanes:
      h0Vals[lane] = uint64(load32Le(msgs[lane], offset + 0) and 0x3ffffff'u32)
      h1Vals[lane] = uint64((load32Le(msgs[lane], offset + 3) shr 2) and 0x3ffffff'u32)
      h2Vals[lane] = uint64((load32Le(msgs[lane], offset + 6) shr 4) and 0x3ffffff'u32)
      h3Vals[lane] = uint64((load32Le(msgs[lane], offset + 9) shr 6) and 0x3ffffff'u32)
      h4Vals[lane] = uint64(load32Le(msgs[lane], offset + 12) shr 8) + hibit
      lane = lane + 1
    h0 = h0 + pack(h0Vals)
    h1 = h1 + pack(h1Vals)
    h2 = h2 + pack(h2Vals)
    h3 = h3 + pack(h3Vals)
    h4 = h4 + pack(h4Vals)

    h0Vals = unpack(h0)
    h1Vals = unpack(h1)
    h2Vals = unpack(h2)
    h3Vals = unpack(h3)
    h4Vals = unpack(h4)
    lane = 0
    while lane < lanes:
      d0Vals[lane] = h0Vals[lane] * r0Vals[lane] + h1Vals[lane] * s4Vals[lane] +
        h2Vals[lane] * s3Vals[lane] + h3Vals[lane] * s2Vals[lane] + h4Vals[lane] * s1Vals[lane]
      d1Vals[lane] = h0Vals[lane] * r1Vals[lane] + h1Vals[lane] * r0Vals[lane] +
        h2Vals[lane] * s4Vals[lane] + h3Vals[lane] * s3Vals[lane] + h4Vals[lane] * s2Vals[lane]
      d2Vals[lane] = h0Vals[lane] * r2Vals[lane] + h1Vals[lane] * r1Vals[lane] +
        h2Vals[lane] * r0Vals[lane] + h3Vals[lane] * s4Vals[lane] + h4Vals[lane] * s3Vals[lane]
      d3Vals[lane] = h0Vals[lane] * r3Vals[lane] + h1Vals[lane] * r2Vals[lane] +
        h2Vals[lane] * r1Vals[lane] + h3Vals[lane] * r0Vals[lane] + h4Vals[lane] * s4Vals[lane]
      d4Vals[lane] = h0Vals[lane] * r4Vals[lane] + h1Vals[lane] * r3Vals[lane] +
        h2Vals[lane] * r2Vals[lane] + h3Vals[lane] * r1Vals[lane] + h4Vals[lane] * r0Vals[lane]
      lane = lane + 1
    h0 = pack(d0Vals)
    h1 = pack(d1Vals)
    h2 = pack(d2Vals)
    h3 = pack(d3Vals)
    h4 = pack(d4Vals)

    cVec = h0 shr 26
    h0 = h0 and mask26Vec
    h1 = h1 + cVec
    cVec = h1 shr 26
    h1 = h1 and mask26Vec
    h2 = h2 + cVec
    cVec = h2 shr 26
    h2 = h2 and mask26Vec
    h3 = h3 + cVec
    cVec = h3 shr 26
    h3 = h3 and mask26Vec
    h4 = h4 + cVec
    cVec = h4 shr 26
    h4 = h4 and mask26Vec
    h0 = h0 + cVec + (cVec shl 2)
    cVec = h0 shr 26
    h0 = h0 and mask26Vec
    h1 = h1 + cVec
    offset = offset + poly1305BlockBytes
  rem = msgLen - offset
  if rem > 0:
    lane = 0
    while lane < lanes:
      for i in 0 ..< rem:
        blk[lane][i] = msgs[lane][offset + i]
      blk[lane][rem] = 1'u8
      h0Vals[lane] = uint64(load32Le(blk[lane], 0) and 0x3ffffff'u32)
      h1Vals[lane] = uint64((load32Le(blk[lane], 3) shr 2) and 0x3ffffff'u32)
      h2Vals[lane] = uint64((load32Le(blk[lane], 6) shr 4) and 0x3ffffff'u32)
      h3Vals[lane] = uint64((load32Le(blk[lane], 9) shr 6) and 0x3ffffff'u32)
      h4Vals[lane] = uint64(load32Le(blk[lane], 12) shr 8)
      lane = lane + 1
    h0 = h0 + pack(h0Vals)
    h1 = h1 + pack(h1Vals)
    h2 = h2 + pack(h2Vals)
    h3 = h3 + pack(h3Vals)
    h4 = h4 + pack(h4Vals)

    h0Vals = unpack(h0)
    h1Vals = unpack(h1)
    h2Vals = unpack(h2)
    h3Vals = unpack(h3)
    h4Vals = unpack(h4)
    lane = 0
    while lane < lanes:
      d0Vals[lane] = h0Vals[lane] * r0Vals[lane] + h1Vals[lane] * s4Vals[lane] +
        h2Vals[lane] * s3Vals[lane] + h3Vals[lane] * s2Vals[lane] + h4Vals[lane] * s1Vals[lane]
      d1Vals[lane] = h0Vals[lane] * r1Vals[lane] + h1Vals[lane] * r0Vals[lane] +
        h2Vals[lane] * s4Vals[lane] + h3Vals[lane] * s3Vals[lane] + h4Vals[lane] * s2Vals[lane]
      d2Vals[lane] = h0Vals[lane] * r2Vals[lane] + h1Vals[lane] * r1Vals[lane] +
        h2Vals[lane] * r0Vals[lane] + h3Vals[lane] * s4Vals[lane] + h4Vals[lane] * s3Vals[lane]
      d3Vals[lane] = h0Vals[lane] * r3Vals[lane] + h1Vals[lane] * r2Vals[lane] +
        h2Vals[lane] * r1Vals[lane] + h3Vals[lane] * r0Vals[lane] + h4Vals[lane] * s4Vals[lane]
      d4Vals[lane] = h0Vals[lane] * r4Vals[lane] + h1Vals[lane] * r3Vals[lane] +
        h2Vals[lane] * r2Vals[lane] + h3Vals[lane] * r1Vals[lane] + h4Vals[lane] * r0Vals[lane]
      lane = lane + 1
    h0 = pack(d0Vals)
    h1 = pack(d1Vals)
    h2 = pack(d2Vals)
    h3 = pack(d3Vals)
    h4 = pack(d4Vals)

    cVec = h0 shr 26
    h0 = h0 and mask26Vec
    h1 = h1 + cVec
    cVec = h1 shr 26
    h1 = h1 and mask26Vec
    h2 = h2 + cVec
    cVec = h2 shr 26
    h2 = h2 and mask26Vec
    h3 = h3 + cVec
    cVec = h3 shr 26
    h3 = h3 and mask26Vec
    h4 = h4 + cVec
    cVec = h4 shr 26
    h4 = h4 and mask26Vec
    h0 = h0 + cVec + (cVec shl 2)
    cVec = h0 shr 26
    h0 = h0 and mask26Vec
    h1 = h1 + cVec
  h0Vals = unpack(h0)
  h1Vals = unpack(h1)
  h2Vals = unpack(h2)
  h3Vals = unpack(h3)
  h4Vals = unpack(h4)
  result = newSeq[Poly1305Tag](lanes)
  lane = 0
  while lane < lanes:
    result[lane] = finalizeTag(
      h0Vals[lane], h1Vals[lane], h2Vals[lane], h3Vals[lane], h4Vals[lane],
      pad0Vals[lane], pad1Vals[lane], pad2Vals[lane], pad3Vals[lane]
    )
    lane = lane + 1

proc poly1305MacSse2x*(keys: array[2, array[poly1305KeyBytes, byte]],
    msgs: array[2, seq[byte]]): array[2, Poly1305Tag] =
  ## Compute two equal-length Poly1305 tags in a batched SSE2-friendly lane layout.
  var tags = poly1305MacBatchImpl[u64x2](keys, msgs)
  result[0] = tags[0]
  result[1] = tags[1]

when defined(avx2):
  proc poly1305MacAvx4x*(keys: array[4, array[poly1305KeyBytes, byte]],
      msgs: array[4, seq[byte]]): array[4, Poly1305Tag] =
    ## Compute four equal-length Poly1305 tags in a batched AVX2-friendly lane layout.
    var tags = poly1305MacBatchImpl[u64x4](keys, msgs)
    for i in 0 ..< 4:
      result[i] = tags[i]
