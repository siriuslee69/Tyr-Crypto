## ------------------------------------------------------------
## BIKE SIMD Words <- 128-bit qword helpers for SSE2 / NEON
## ------------------------------------------------------------

when defined(sse2):
  import nimsimd/sse2 as nsse2
when defined(neon) or defined(arm64) or defined(aarch64):
  import nimsimd/neon

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  proc xorWords128*(dst: var openArray[uint64], A, B: openArray[uint64],
      n: int): int {.inline.} =
    ## XOR qwords in 128-bit lanes and return the first scalar tail index.
    var
      i: int = 0
    when defined(neon) or defined(arm64) or defined(aarch64):
      var
        va: uint64x2
        vb: uint64x2
      while i + 2 <= n:
        va = vld1q_u64(cast[pointer](unsafeAddr A[i]))
        vb = vld1q_u64(cast[pointer](unsafeAddr B[i]))
        vst1q_u64(cast[pointer](unsafeAddr dst[i]), veorq_u64(va, vb))
        i = i + 2
    else:
      var
        va: nsse2.M128i
        vb: nsse2.M128i
      while i + 2 <= n:
        va = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr A[i]))
        vb = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr B[i]))
        nsse2.mm_storeu_si128(cast[pointer](unsafeAddr dst[i]),
          nsse2.mm_xor_si128(va, vb))
        i = i + 2
    result = i

  proc addBitSliceWords128*(U: var openArray[uint64],
      rotated: var openArray[uint64], n: int): int {.inline.} =
    ## Apply one BIKE bit-sliced adder step in 128-bit qword lanes.
    var
      i: int = 0
    when defined(neon) or defined(arm64) or defined(aarch64):
      var
        uVec: uint64x2
        rVec: uint64x2
        carryVec: uint64x2
      while i + 2 <= n:
        uVec = vld1q_u64(cast[pointer](unsafeAddr U[i]))
        rVec = vld1q_u64(cast[pointer](unsafeAddr rotated[i]))
        carryVec = vandq_u64(uVec, rVec)
        vst1q_u64(cast[pointer](unsafeAddr U[i]), veorq_u64(uVec, rVec))
        vst1q_u64(cast[pointer](unsafeAddr rotated[i]), carryVec)
        i = i + 2
    else:
      var
        uVec: nsse2.M128i
        rVec: nsse2.M128i
        carryVec: nsse2.M128i
      while i + 2 <= n:
        uVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr U[i]))
        rVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr rotated[i]))
        carryVec = nsse2.mm_and_si128(uVec, rVec)
        nsse2.mm_storeu_si128(cast[pointer](unsafeAddr U[i]),
          nsse2.mm_xor_si128(uVec, rVec))
        nsse2.mm_storeu_si128(cast[pointer](unsafeAddr rotated[i]), carryVec)
        i = i + 2
    result = i

  proc fullSubtractWords128*(U: var openArray[uint64],
      br: var openArray[uint64], lsbMask: uint64, n: int): int {.inline.} =
    ## Apply one BIKE full-subtractor bit-slice in 128-bit qword lanes.
    var
      i: int = 0
    when defined(neon) or defined(arm64) or defined(aarch64):
      var
        maskVec: uint64x2 = vmovq_n_u64(lsbMask)
        onesVec: uint64x2 = vmovq_n_u64(not 0'u64)
        aVec: uint64x2
        brVec: uint64x2
        notA: uint64x2
        notBr: uint64x2
        tmpVec: uint64x2
        uOut: uint64x2
      while i + 2 <= n:
        aVec = vld1q_u64(cast[pointer](unsafeAddr U[i]))
        brVec = vld1q_u64(cast[pointer](unsafeAddr br[i]))
        notA = veorq_u64(aVec, onesVec)
        notBr = veorq_u64(brVec, onesVec)
        tmpVec = vorrq_u64(
          vandq_u64(vandq_u64(notA, maskVec), notBr),
          vandq_u64(vorrq_u64(notA, maskVec), brVec)
        )
        uOut = veorq_u64(veorq_u64(aVec, maskVec), brVec)
        vst1q_u64(cast[pointer](unsafeAddr U[i]), uOut)
        vst1q_u64(cast[pointer](unsafeAddr br[i]), tmpVec)
        i = i + 2
    else:
      var
        maskVec: nsse2.M128i = nsse2.mm_set1_epi64x(cast[int64](lsbMask))
        onesVec: nsse2.M128i = nsse2.mm_set1_epi64x(cast[int64](not 0'u64))
        aVec: nsse2.M128i
        brVec: nsse2.M128i
        notA: nsse2.M128i
        notBr: nsse2.M128i
        tmpVec: nsse2.M128i
        uOut: nsse2.M128i
      while i + 2 <= n:
        aVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr U[i]))
        brVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr br[i]))
        notA = nsse2.mm_xor_si128(aVec, onesVec)
        notBr = nsse2.mm_xor_si128(brVec, onesVec)
        tmpVec = nsse2.mm_or_si128(
          nsse2.mm_and_si128(nsse2.mm_and_si128(notA, maskVec), notBr),
          nsse2.mm_and_si128(nsse2.mm_or_si128(notA, maskVec), brVec)
        )
        uOut = nsse2.mm_xor_si128(nsse2.mm_xor_si128(aVec, maskVec), brVec)
        nsse2.mm_storeu_si128(cast[pointer](unsafeAddr U[i]), uOut)
        nsse2.mm_storeu_si128(cast[pointer](unsafeAddr br[i]), tmpVec)
        i = i + 2
    result = i
