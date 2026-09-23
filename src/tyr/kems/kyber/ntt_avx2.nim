when defined(avx2):
  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `nttButterflyChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc nttButterflyChunk8(aPtr, bPtr: ptr int16, zeta: int16) {.inline.} =
    var
      aVec: navx.M256i = loadI16x8AsI32x8(aPtr)
      bVec: navx.M256i = loadI16x8AsI32x8(bPtr)
      zetaVec: navx.M256i = navx.mm256_set1_epi32(int32(zeta))
      tVec: navx.M256i = montgomeryReduceVec8(navx2.mm256_mullo_epi32(bVec, zetaVec))
    packStoreI32x8ToI16x8(aPtr, navx2.mm256_add_epi32(aVec, tVec))
    packStoreI32x8ToI16x8(bPtr, navx2.mm256_sub_epi32(aVec, tVec))

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `nttButterflyInterleavedChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc nttButterflyInterleavedChunk8(aPtr, bPtr, cPtr, dPtr: ptr int16,
      zetaUpper, zetaLower0, zetaLower1: int16) {.inline.} =
    var
      aVec: navx.M256i = loadI16x8AsI32x8(aPtr)
      bVec: navx.M256i = loadI16x8AsI32x8(bPtr)
      cVec: navx.M256i = loadI16x8AsI32x8(cPtr)
      dVec: navx.M256i = loadI16x8AsI32x8(dPtr)
      zetaUpperVec: navx.M256i = navx.mm256_set1_epi32(int32(zetaUpper))
      zetaLower0Vec: navx.M256i = navx.mm256_set1_epi32(int32(zetaLower0))
      zetaLower1Vec: navx.M256i = navx.mm256_set1_epi32(int32(zetaLower1))
      upper0: navx.M256i = default(navx.M256i)
      upper1: navx.M256i = default(navx.M256i)
      lo0: navx.M256i = default(navx.M256i)
      hi0: navx.M256i = default(navx.M256i)
      lo1: navx.M256i = default(navx.M256i)
      hi1: navx.M256i = default(navx.M256i)
      lower0: navx.M256i = default(navx.M256i)
      lower1: navx.M256i = default(navx.M256i)
    upper0 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(cVec, zetaUpperVec))
    upper1 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(dVec, zetaUpperVec))
    lo0 = navx2.mm256_add_epi32(aVec, upper0)
    hi0 = navx2.mm256_sub_epi32(aVec, upper0)
    lo1 = navx2.mm256_add_epi32(bVec, upper1)
    hi1 = navx2.mm256_sub_epi32(bVec, upper1)
    lower0 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(lo1, zetaLower0Vec))
    lower1 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(hi1, zetaLower1Vec))
    packStoreI32x8ToI16x8(aPtr, navx2.mm256_add_epi32(lo0, lower0))
    packStoreI32x8ToI16x8(bPtr, navx2.mm256_sub_epi32(lo0, lower0))
    packStoreI32x8ToI16x8(cPtr, navx2.mm256_add_epi32(hi0, lower1))
    packStoreI32x8ToI16x8(dPtr, navx2.mm256_sub_epi32(hi0, lower1))

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `invNttButterflyChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc invNttButterflyChunk8(aPtr, bPtr: ptr int16, zeta: int16) {.inline.} =
    var
      aVec: navx.M256i = loadI16x8AsI32x8(aPtr)
      bVec: navx.M256i = loadI16x8AsI32x8(bPtr)
      zetaVec: navx.M256i = navx.mm256_set1_epi32(int32(zeta))
      sumVec: navx.M256i = barrettReduceVec8(navx2.mm256_add_epi32(aVec, bVec))
      diffVec: navx.M256i = navx2.mm256_sub_epi32(bVec, aVec)
    diffVec = montgomeryReduceVec8(navx2.mm256_mullo_epi32(diffVec, zetaVec))
    packStoreI32x8ToI16x8(aPtr, sumVec)
    packStoreI32x8ToI16x8(bPtr, diffVec)

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `invNttButterflyInterleavedChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc invNttButterflyInterleavedChunk8(aPtr, bPtr, cPtr, dPtr: ptr int16,
      zetaLower0, zetaLower1, zetaUpper: int16) {.inline.} =
    var
      aVec: navx.M256i = loadI16x8AsI32x8(aPtr)
      bVec: navx.M256i = loadI16x8AsI32x8(bPtr)
      cVec: navx.M256i = loadI16x8AsI32x8(cPtr)
      dVec: navx.M256i = loadI16x8AsI32x8(dPtr)
      zetaLower0Vec: navx.M256i = navx.mm256_set1_epi32(int32(zetaLower0))
      zetaLower1Vec: navx.M256i = navx.mm256_set1_epi32(int32(zetaLower1))
      zetaUpperVec: navx.M256i = navx.mm256_set1_epi32(int32(zetaUpper))
      lowerSum0: navx.M256i = default(navx.M256i)
      lowerSum1: navx.M256i = default(navx.M256i)
      lowerDiff0: navx.M256i = default(navx.M256i)
      lowerDiff1: navx.M256i = default(navx.M256i)
      upperSum0: navx.M256i = default(navx.M256i)
      upperSum1: navx.M256i = default(navx.M256i)
      upperDiff0: navx.M256i = default(navx.M256i)
      upperDiff1: navx.M256i = default(navx.M256i)
    lowerSum0 = barrettReduceVec8(navx2.mm256_add_epi32(aVec, bVec))
    lowerSum1 = barrettReduceVec8(navx2.mm256_add_epi32(cVec, dVec))
    lowerDiff0 = navx2.mm256_sub_epi32(bVec, aVec)
    lowerDiff1 = navx2.mm256_sub_epi32(dVec, cVec)
    lowerDiff0 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(lowerDiff0, zetaLower0Vec))
    lowerDiff1 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(lowerDiff1, zetaLower1Vec))
    upperSum0 = barrettReduceVec8(navx2.mm256_add_epi32(lowerSum0, lowerSum1))
    upperSum1 = navx2.mm256_sub_epi32(lowerSum1, lowerSum0)
    upperDiff0 = barrettReduceVec8(navx2.mm256_add_epi32(lowerDiff0, lowerDiff1))
    upperDiff1 = navx2.mm256_sub_epi32(lowerDiff1, lowerDiff0)
    upperSum1 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(upperSum1, zetaUpperVec))
    upperDiff1 = montgomeryReduceVec8(navx2.mm256_mullo_epi32(upperDiff1, zetaUpperVec))
    packStoreI32x8ToI16x8(aPtr, upperSum0)
    packStoreI32x8ToI16x8(bPtr, upperDiff0)
    packStoreI32x8ToI16x8(cPtr, upperSum1)
    packStoreI32x8ToI16x8(dPtr, upperDiff1)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `ntt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
