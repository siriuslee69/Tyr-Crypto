## Polynomial evaluation helpers for Classic McEliece.

import ./params
import ./util
import ./gf

when defined(avx2) and not defined(mcelieceScalarRoot):
  import nimsimd/avx2
when defined(sse2) and not defined(avx2) and not defined(mcelieceScalarRoot):
  import nimsimd/sse2
when (defined(neon) or defined(arm64) or defined(aarch64)) and
    not defined(mcelieceScalarRoot):
  import nimsimd/neon

when (defined(avx2) or defined(sse2) or defined(neon) or defined(arm64) or
    defined(aarch64)) and not defined(mcelieceScalarRoot):
  const
    gfVectorBits = 13
    gfVectorMask = 0x1fff'u32

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `evalPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc evalPoly*(p: McElieceParams; f: openArray[GF]; a: GF): GF

when defined(avx2) and not defined(mcelieceScalarRoot):
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `gfMulAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc gfMulAvx2(a, b: M256i): M256i {.inline.} =
    ## Carryless GF(2^13) multiplication in eight independent lanes.
    var
      t: M256i = mm256_setzero_si256()
      x: M256i = mm256_setzero_si256()
      bit: M256i = mm256_setzero_si256()
      mask: M256i = mm256_setzero_si256()
      i: int = 0
      one: M256i = mm256_set1_epi32(1)
    i = 0
    while i < gfVectorBits:
      bit = mm256_and_si256(mm256_srli_epi32(b, int32(i)), one)
      mask = mm256_sub_epi32(mm256_setzero_si256(), bit)
      t = mm256_xor_si256(t, mm256_and_si256(mm256_slli_epi32(a, int32(i)), mask))
      i = i + 1
    x = mm256_and_si256(t, mm256_set1_epi32(0x1ff0000))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 9))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 10))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 12))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 13))
    x = mm256_and_si256(t, mm256_set1_epi32(0x000e000))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 9))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 10))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 12))
    t = mm256_xor_si256(t, mm256_srli_epi32(x, 13))
    result = mm256_and_si256(t, mm256_set1_epi32(int32(gfVectorMask)))

  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `rootEvalAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc rootEvalAvx2(p: McElieceParams, f: openArray[GF], L: openArray[GF],
      outVals: var seq[GF]) =
    var
      points: array[8, uint32]
      values: array[8, uint32]
      a: M256i
      r: M256i
      i: int = 0
      j: int = 0
      lane: int = 0
    while i + 8 <= p.sysN:
      lane = 0
      while lane < 8:
        points[lane] = uint32(L[i + lane])
        lane = lane + 1
      a = mm256_loadu_si256(cast[pointer](unsafeAddr points[0]))
      r = mm256_set1_epi32(int32(f[p.sysT]))
      j = p.sysT - 1
      while j >= 0:
        r = mm256_xor_si256(gfMulAvx2(r, a), mm256_set1_epi32(int32(f[j])))
        j = j - 1
      mm256_storeu_si256(cast[pointer](unsafeAddr values[0]), r)
      lane = 0
      while lane < 8:
        outVals[i + lane] = GF(values[lane])
        lane = lane + 1
      i = i + 8
    while i < p.sysN:
      outVals[i] = evalPoly(p, f, L[i])
      i = i + 1

when defined(sse2) and not defined(avx2) and not defined(mcelieceScalarRoot):
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `gfMulSse2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc gfMulSse2(a, b: M128i): M128i {.inline.} =
    ## Carryless GF(2^13) multiplication in four independent lanes.
    var
      t: M128i = mm_setzero_si128()
      x: M128i = mm_setzero_si128()
      bit: M128i = mm_setzero_si128()
      mask: M128i = mm_setzero_si128()
      i: int = 0
      one: M128i = mm_set1_epi32(1)
    i = 0
    while i < gfVectorBits:
      bit = mm_and_si128(mm_srli_epi32(b, int32(i)), one)
      mask = mm_sub_epi32(mm_setzero_si128(), bit)
      t = mm_xor_si128(t, mm_and_si128(mm_slli_epi32(a, int32(i)), mask))
      i = i + 1
    x = mm_and_si128(t, mm_set1_epi32(0x1ff0000))
    t = mm_xor_si128(t, mm_srli_epi32(x, 9))
    t = mm_xor_si128(t, mm_srli_epi32(x, 10))
    t = mm_xor_si128(t, mm_srli_epi32(x, 12))
    t = mm_xor_si128(t, mm_srli_epi32(x, 13))
    x = mm_and_si128(t, mm_set1_epi32(0x000e000))
    t = mm_xor_si128(t, mm_srli_epi32(x, 9))
    t = mm_xor_si128(t, mm_srli_epi32(x, 10))
    t = mm_xor_si128(t, mm_srli_epi32(x, 12))
    t = mm_xor_si128(t, mm_srli_epi32(x, 13))
    result = mm_and_si128(t, mm_set1_epi32(int32(gfVectorMask)))

  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `rootEvalSse2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc rootEvalSse2(p: McElieceParams, f: openArray[GF], L: openArray[GF],
      outVals: var seq[GF]) =
    var
      points: array[4, uint32]
      values: array[4, uint32]
      a: M128i
      r: M128i
      i: int = 0
      j: int = 0
      lane: int = 0
    while i + 4 <= p.sysN:
      lane = 0
      while lane < 4:
        points[lane] = uint32(L[i + lane])
        lane = lane + 1
      a = mm_loadu_si128(cast[pointer](unsafeAddr points[0]))
      r = mm_set1_epi32(int32(f[p.sysT]))
      j = p.sysT - 1
      while j >= 0:
        r = mm_xor_si128(gfMulSse2(r, a), mm_set1_epi32(int32(f[j])))
        j = j - 1
      mm_storeu_si128(cast[pointer](unsafeAddr values[0]), r)
      lane = 0
      while lane < 4:
        outVals[i + lane] = GF(values[lane])
        lane = lane + 1
      i = i + 4
    while i < p.sysN:
      outVals[i] = evalPoly(p, f, L[i])
      i = i + 1

when (defined(neon) or defined(arm64) or defined(aarch64)) and
    not defined(mcelieceScalarRoot):
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `gfMulNeon`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc gfMulNeon(a, b: uint32x4): uint32x4 {.inline.} =
    ## Carryless GF(2^13) multiplication in four independent lanes.
    var
      t: uint32x4 = vmovq_n_u32(0)
      x: uint32x4 = vmovq_n_u32(0)
      bit: uint32x4 = vmovq_n_u32(0)
      mask: uint32x4 = vmovq_n_u32(0)
      i: int = 0
      one: uint32x4 = vmovq_n_u32(1)
    i = 0
    while i < gfVectorBits:
      bit = vandq_u32(vshlq_u32(b, cast[uint32x4](vmovq_n_s32(int32(-i)))), one)
      mask = vsubq_u32(vmovq_n_u32(0), bit)
      t = veorq_u32(t, vandq_u32(vshlq_u32(a,
        cast[uint32x4](vmovq_n_s32(int32(i)))), mask))
      i = i + 1
    x = vandq_u32(t, vmovq_n_u32(0x1ff0000))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-9))))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-10))))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-12))))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-13))))
    x = vandq_u32(t, vmovq_n_u32(0x000e000))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-9))))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-10))))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-12))))
    t = veorq_u32(t, vshlq_u32(x, cast[uint32x4](vmovq_n_s32(-13))))
    result = vandq_u32(t, vmovq_n_u32(gfVectorMask))

  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `rootEvalNeon`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc rootEvalNeon(p: McElieceParams, f: openArray[GF], L: openArray[GF],
      outVals: var seq[GF]) =
    var
      points: array[4, uint32]
      values: array[4, uint32]
      a: uint32x4
      r: uint32x4
      i: int = 0
      j: int = 0
      lane: int = 0
    while i + 4 <= p.sysN:
      lane = 0
      while lane < 4:
        points[lane] = uint32(L[i + lane])
        lane = lane + 1
      a = vld1q_u32(cast[pointer](unsafeAddr points[0]))
      r = vmovq_n_u32(uint32(f[p.sysT]))
      j = p.sysT - 1
      while j >= 0:
        r = veorq_u32(gfMulNeon(r, a), vmovq_n_u32(uint32(f[j])))
        j = j - 1
      vst1q_u32(cast[pointer](unsafeAddr values[0]), r)
      lane = 0
      while lane < 4:
        outVals[i + lane] = GF(values[lane])
        lane = lane + 1
      i = i + 4
    while i < p.sysN:
      outVals[i] = evalPoly(p, f, L[i])
      i = i + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `evalPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc evalPoly*(p: McElieceParams; f: openArray[GF]; a: GF): GF =
  ## Evaluate polynomial f at point a (f[0] is constant term).
  assert f.len >= p.sysT + 1
  var r = f[p.sysT]
  var i = p.sysT - 1
  while i >= 0:
    r = gfMul(r, a)
    r = gfAdd(r, f[i])
    if i == 0: break
    dec i
  r

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Goppa decoding and syndrome algorithms for `rootEval`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc rootEval*(p: McElieceParams; f: openArray[GF]; L: openArray[GF]; outVals: var seq[GF]) =
  ## Evaluate polynomial f at every support element in L.
  assert f.len >= p.sysT + 1
  assert L.len >= p.sysN
  outVals.setLen(p.sysN)
  when defined(mcelieceScalarRoot):
    for i in 0 ..< p.sysN:
      outVals[i] = evalPoly(p, f, L[i])
  elif defined(avx2):
    rootEvalAvx2(p, f, L, outVals)
  elif defined(sse2):
    rootEvalSse2(p, f, L, outVals)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    rootEvalNeon(p, f, L, outVals)
  else:
    for i in 0 ..< p.sysN:
      outVals[i] = evalPoly(p, f, L[i])
