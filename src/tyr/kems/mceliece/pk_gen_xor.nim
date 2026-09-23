proc xorRowMasked(mat: var seq[byte], dstStart, srcStart, fullRowBytes: int,
    mask: byte) {.inline.} =
  ## Paper note: Gaussian elimination uses masked row XORs, matching the
  ## constant-time public-key generation style from the Classic McEliece guide.
  var
    maskWord: uint64 = 0'u64 - uint64(mask and 1'u8)

  when defined(avx2):
    var
      maskVec = mm256_set1_epi8(cast[int8](mask))
      vecBytes: int = fullRowBytes and (not 31)
      c: int = 0
      dstVec0 = maskVec
      srcVec0 = maskVec
      dstVec1 = maskVec
      srcVec1 = maskVec
      dstVec2 = maskVec
      srcVec2 = maskVec
      dstVec3 = maskVec
      srcVec3 = maskVec
      dstVec = maskVec
      srcVec = maskVec
      srcMasked = maskVec
    c = 0
    while c + 128 <= vecBytes:
      dstVec0 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[dstStart + c]))
      srcVec0 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[srcStart + c]))
      dstVec1 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[dstStart + c + 32]))
      srcVec1 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[srcStart + c + 32]))
      dstVec2 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[dstStart + c + 64]))
      srcVec2 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[srcStart + c + 64]))
      dstVec3 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[dstStart + c + 96]))
      srcVec3 = mm256_loadu_si256(cast[pointer](unsafeAddr mat[srcStart + c + 96]))
      mm256_storeu_si256(cast[pointer](unsafeAddr mat[dstStart + c]),
        mm256_xor_si256(dstVec0, mm256_and_si256(srcVec0, maskVec)))
      mm256_storeu_si256(cast[pointer](unsafeAddr mat[dstStart + c + 32]),
        mm256_xor_si256(dstVec1, mm256_and_si256(srcVec1, maskVec)))
      mm256_storeu_si256(cast[pointer](unsafeAddr mat[dstStart + c + 64]),
        mm256_xor_si256(dstVec2, mm256_and_si256(srcVec2, maskVec)))
      mm256_storeu_si256(cast[pointer](unsafeAddr mat[dstStart + c + 96]),
        mm256_xor_si256(dstVec3, mm256_and_si256(srcVec3, maskVec)))
      c = c + 128
    while c < vecBytes:
      dstVec = mm256_loadu_si256(cast[pointer](unsafeAddr mat[dstStart + c]))
      srcVec = mm256_loadu_si256(cast[pointer](unsafeAddr mat[srcStart + c]))
      srcMasked = mm256_and_si256(srcVec, maskVec)
      mm256_storeu_si256(cast[pointer](unsafeAddr mat[dstStart + c]), mm256_xor_si256(dstVec, srcMasked))
      c = c + 32
    xorRowMaskedWords(mat, dstStart, srcStart, c, fullRowBytes, mask, maskWord)
  elif defined(sse2):
    var
      maskVec = nsse2.mm_set1_epi8(cast[int8](mask))
      vecBytesSse = fullRowBytes and (not 15)
      cSse: int = 0
      dstVec0 = maskVec
      srcVec0 = maskVec
      dstVec1 = maskVec
      srcVec1 = maskVec
      dstVec2 = maskVec
      srcVec2 = maskVec
      dstVec3 = maskVec
      srcVec3 = maskVec
      dstVec = maskVec
      srcVec = maskVec
      srcMasked = maskVec
    cSse = 0
    while cSse + 64 <= vecBytesSse:
      dstVec0 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse]))
      srcVec0 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[srcStart + cSse]))
      dstVec1 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse + 16]))
      srcVec1 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[srcStart + cSse + 16]))
      dstVec2 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse + 32]))
      srcVec2 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[srcStart + cSse + 32]))
      dstVec3 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse + 48]))
      srcVec3 = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[srcStart + cSse + 48]))
      nsse2.mm_storeu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse]),
        nsse2.mm_xor_si128(dstVec0, nsse2.mm_and_si128(srcVec0, maskVec)))
      nsse2.mm_storeu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse + 16]),
        nsse2.mm_xor_si128(dstVec1, nsse2.mm_and_si128(srcVec1, maskVec)))
      nsse2.mm_storeu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse + 32]),
        nsse2.mm_xor_si128(dstVec2, nsse2.mm_and_si128(srcVec2, maskVec)))
      nsse2.mm_storeu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse + 48]),
        nsse2.mm_xor_si128(dstVec3, nsse2.mm_and_si128(srcVec3, maskVec)))
      cSse = cSse + 64
    while cSse < vecBytesSse:
      dstVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse]))
      srcVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr mat[srcStart + cSse]))
      srcMasked = nsse2.mm_and_si128(srcVec, maskVec)
      nsse2.mm_storeu_si128(cast[pointer](unsafeAddr mat[dstStart + cSse]), nsse2.mm_xor_si128(dstVec, srcMasked))
      cSse = cSse + 16
    xorRowMaskedWords(mat, dstStart, srcStart, cSse, fullRowBytes, mask, maskWord)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    var
      maskVec = vmovq_n_u8(mask)
      vecBytesNeon = fullRowBytes and (not 15)
      cNeon: int = 0
      dstVec0: uint8x16 = maskVec
      srcVec0: uint8x16 = maskVec
      dstVec1: uint8x16 = maskVec
      srcVec1: uint8x16 = maskVec
      dstVec2: uint8x16 = maskVec
      srcVec2: uint8x16 = maskVec
      dstVec3: uint8x16 = maskVec
      srcVec3: uint8x16 = maskVec
      dstVec: uint8x16 = maskVec
      srcVec: uint8x16 = maskVec
      srcMasked: uint8x16 = maskVec
    cNeon = 0
    while cNeon + 64 <= vecBytesNeon:
      dstVec0 = vld1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon]))
      srcVec0 = vld1q_u8(cast[pointer](unsafeAddr mat[srcStart + cNeon]))
      dstVec1 = vld1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon + 16]))
      srcVec1 = vld1q_u8(cast[pointer](unsafeAddr mat[srcStart + cNeon + 16]))
      dstVec2 = vld1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon + 32]))
      srcVec2 = vld1q_u8(cast[pointer](unsafeAddr mat[srcStart + cNeon + 32]))
      dstVec3 = vld1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon + 48]))
      srcVec3 = vld1q_u8(cast[pointer](unsafeAddr mat[srcStart + cNeon + 48]))
      vst1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon]),
        veorq_u8(dstVec0, vandq_u8(srcVec0, maskVec)))
      vst1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon + 16]),
        veorq_u8(dstVec1, vandq_u8(srcVec1, maskVec)))
      vst1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon + 32]),
        veorq_u8(dstVec2, vandq_u8(srcVec2, maskVec)))
      vst1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon + 48]),
        veorq_u8(dstVec3, vandq_u8(srcVec3, maskVec)))
      cNeon = cNeon + 64
    while cNeon < vecBytesNeon:
      dstVec = vld1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon]))
      srcVec = vld1q_u8(cast[pointer](unsafeAddr mat[srcStart + cNeon]))
      srcMasked = vandq_u8(srcVec, maskVec)
      vst1q_u8(cast[pointer](unsafeAddr mat[dstStart + cNeon]), veorq_u8(dstVec, srcMasked))
      cNeon = cNeon + 16
    xorRowMaskedWords(mat, dstStart, srcStart, cNeon, fullRowBytes, mask, maskWord)
  else:
    xorRowMaskedWords(mat, dstStart, srcStart, 0, fullRowBytes, mask, maskWord)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `movColumns`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
