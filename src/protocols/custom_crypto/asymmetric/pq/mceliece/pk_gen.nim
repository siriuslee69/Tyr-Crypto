## Public-key generation for the pure-Nim Classic McEliece backend.

import std/bitops

import ./params
import ./util
import ./gf
import ./root
import ./sort
import ../../../../helpers/otter_support

when defined(sse2) and not defined(avx2):
  import nimsimd/sse2 as nsse2
when defined(avx2):
  {.passC: "-mavx2".}
  import simd_nexus/simd/base_operations
  import ./transpose
when defined(neon) or defined(arm64) or defined(aarch64):
  import nimsimd/neon

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `ctMaskEqualU64`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc ctMaskEqualU64(a, b: uint64): uint64 {.inline.} =
  var x = a xor b
  x = x - 1'u64
  x = x shr 63
  result = 0'u64 - x

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `load64At`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load64At(mat: openArray[byte], offset: int): uint64 {.inline.} =
  result = load8(mat.toOpenArray(offset, offset + 7))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `store64At`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc store64At(mat: var openArray[byte], offset: int, v: uint64) {.inline.} =
  store8(mat.toOpenArray(offset, offset + 7), v)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `load64Copy`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load64Copy(mat: openArray[byte], offset: int): uint64 {.inline.} =
  result = load64At(mat, offset)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `store64Copy`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc store64Copy(mat: var openArray[byte], offset: int, v: uint64) {.inline.} =
  store64At(mat, offset, v)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `xorRowMaskedWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc xorRowMaskedWords(mat: var seq[byte], dstStart, srcStart, startByte, fullRowBytes: int,
    mask: byte, maskWord: uint64) {.inline.} =
  var
    c: int = startByte
    v: uint64 = 0
    wordCount: int = 0
    dstWords: ptr UncheckedArray[uint64] = nil
    srcWords: ptr UncheckedArray[uint64] = nil
    w: int = 0
  if c + 8 <= fullRowBytes:
    if ((cast[uint](unsafeAddr mat[dstStart + c]) or cast[uint](unsafeAddr mat[srcStart + c])) and 7'u) == 0'u:
      wordCount = (fullRowBytes - c) shr 3
      dstWords = cast[ptr UncheckedArray[uint64]](unsafeAddr mat[dstStart + c])
      srcWords = cast[ptr UncheckedArray[uint64]](unsafeAddr mat[srcStart + c])
      w = 0
      while w < wordCount:
        dstWords[w] = dstWords[w] xor (srcWords[w] and maskWord)
        w = w + 1
      c = c + (wordCount shl 3)
  while c + 8 <= fullRowBytes:
    v = load64Copy(mat, dstStart + c) xor (load64Copy(mat, srcStart + c) and maskWord)
    store64Copy(mat, dstStart + c, v)
    c = c + 8
  while c < fullRowBytes:
    mat[dstStart + c] = mat[dstStart + c] xor (mat[srcStart + c] and mask)
    c = c + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `loadColumnBlock`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc loadColumnBlock(mat: openArray[byte], rowStart, blockIdx, tail: int): uint64 {.inline.} =
  if tail == 0:
    return load64At(mat, rowStart + blockIdx)

  var tmp: array[9, byte]
  for j in 0 ..< 9:
    tmp[j] = mat[rowStart + blockIdx + j]
  for j in 0 ..< 8:
    tmp[j] = byte(((int(tmp[j]) shr tail) or (int(tmp[j + 1]) shl (8 - tail))) and 0xFF)
  result = load8(tmp.toOpenArray(0, 7))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `storeColumnBlock`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc storeColumnBlock(mat: var openArray[byte], rowStart, blockIdx, tail: int, v: uint64) {.inline.} =
  if tail == 0:
    store64At(mat, rowStart + blockIdx, v)
    return

  var tmp: array[9, byte]
  for j in 0 ..< 9:
    tmp[j] = mat[rowStart + blockIdx + j]
  for j in 0 ..< 8:
    tmp[j] = byte(((int(tmp[j]) shr tail) or (int(tmp[j + 1]) shl (8 - tail))) and 0xFF)

  store8(tmp.toOpenArray(0, 7), v)
  mat[rowStart + blockIdx + 8] = byte(
    (((int(mat[rowStart + blockIdx + 8]) shr tail) shl tail) or
    (int(tmp[7]) shr (8 - tail))) and 0xFF)
  mat[rowStart + blockIdx] = byte(
    ((int(tmp[0]) shl tail) or
    (((int(mat[rowStart + blockIdx]) shl (8 - tail)) shr (8 - tail)))) and 0xFF)
  for j in countdown(7, 1):
    mat[rowStart + blockIdx + j] = byte(
      ((int(tmp[j]) shl tail) or (int(tmp[j - 1]) shr (8 - tail))) and 0xFF)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `batchInvertNonZero`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc batchInvertNonZero(vals: var seq[GF], prefix: var seq[GF], n: int) {.inline.} =
  ## Paper note: the Classic McEliece implementation guide uses Montgomery's
  ## trick here: one inversion plus prefix/suffix products replaces many GF inversions.
  if n <= 0:
    return

  prefix[0] = vals[0]
  for i in 1 ..< n:
    prefix[i] = gfMul(prefix[i - 1], vals[i])

  var
    invAcc: GF = gfInv(prefix[n - 1])
    i: int = n - 1
    cur: GF = 0
  while i > 0:
    cur = vals[i]
    vals[i] = gfMul(invAcc, prefix[i - 1])
    invAcc = gfMul(invAcc, cur)
    i = i - 1
  vals[0] = invAcc

when defined(avx2):
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `fillMatrixTransposedAvx`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc fillMatrixTransposedAvx(p: McElieceParams; L: openArray[GF];
      inv: var seq[GF]; mat: var seq[byte]; fullRowBytes: int) =
    ## Paper note: public-key generation follows the Classic McEliece bit-matrix
    ## layout, but AVX2 fills 64 support positions through a 64x64 transpose.
    var
      inRows: array[64, uint64]
      outRows: array[64, uint64]
      tailBytes: array[8, byte]
      blockCount: int = p.sysN div 64
      rem: int = p.sysN mod 64
      i: int = 0
      chunkIdx: int = 0
      matBase: int = 0
      base: int = 0
      byteOffset: int = 0
      k: int = 0
      lane: int = 0
      storeBytes: int = 0
      rowOffset: int = 0
      bIdx: int = 0
    defer:
      clearSensitiveWords(inRows)
      clearSensitiveWords(outRows)
      clearSensitiveWords(tailBytes)

    i = 0
    while i < p.sysT:
      matBase = i * p.gfBits * fullRowBytes

      chunkIdx = 0
      while chunkIdx < blockCount:
        base = chunkIdx * 64
        lane = 0
        while lane < 64:
          inRows[lane] = uint64(inv[base + lane])
          lane = lane + 1
        transpose64x64(outRows, inRows)
        byteOffset = base shr 3
        k = 0
        while k < p.gfBits:
          store64At(mat, matBase + (k * fullRowBytes) + byteOffset, outRows[k])
          k = k + 1
        lane = 0
        while lane < 64:
          inv[base + lane] = gfMul(inv[base + lane], L[base + lane])
          lane = lane + 1
        chunkIdx = chunkIdx + 1

      if rem != 0:
        base = blockCount * 64
        lane = 0
        while lane < rem:
          inRows[lane] = uint64(inv[base + lane])
          lane = lane + 1
        lane = rem
        while lane < 64:
          inRows[lane] = 0'u64
          lane = lane + 1
        transpose64x64(outRows, inRows)
        byteOffset = base shr 3
        storeBytes = rem shr 3
        k = 0
        while k < p.gfBits:
          store8(tailBytes.toOpenArray(0, 7), outRows[k])
          rowOffset = matBase + (k * fullRowBytes) + byteOffset
          bIdx = 0
          while bIdx < storeBytes:
            mat[rowOffset + bIdx] = tailBytes[bIdx]
            bIdx = bIdx + 1
          k = k + 1
        lane = 0
        while lane < rem:
          inv[base + lane] = gfMul(inv[base + lane], L[base + lane])
          lane = lane + 1
      i = i + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `xorRowMasked`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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
proc movColumns(mat: var seq[byte], pi: var seq[int16], pivots: var uint64,
    p: McElieceParams, fullRowBytes: int): bool =
  var
    buf: array[32, uint64]
    ctzList: array[32, int]
    t: uint64 = 0
    d: int16 = 0
    mask: uint64 = 0
    row = p.pkNRows - 32
    blockIdx = row div 8
    tail = row mod 8
    j: int = 0
    k: int = 0
  defer:
    clearSensitiveWords(buf)
    clearSensitiveWords(ctzList)

  for i in 0 ..< 32:
    buf[i] = loadColumnBlock(mat, (row + i) * fullRowBytes, blockIdx, tail)

  var
    i: int = 0
    rowStart: int = 0
    delta: uint64 = 0
    matchMask: int16 = 0
  pivots = 0'u64
  i = 0
  while i < 32:
    t = buf[i]
    j = i + 1
    while j < 32:
      t = t or buf[j]
      j = j + 1
    if t == 0'u64:
      return false
    ctzList[i] = countTrailingZeroBits(t)
    pivots = pivots or (1'u64 shl ctzList[i])

    j = i + 1
    while j < 32:
      mask = (buf[i] shr ctzList[i]) and 1'u64
      mask = mask - 1'u64
      buf[i] = buf[i] xor (buf[j] and mask)
      j = j + 1
    j = i + 1
    while j < 32:
      mask = (buf[j] shr ctzList[i]) and 1'u64
      mask = 0'u64 - mask
      buf[j] = buf[j] xor (buf[i] and mask)
      j = j + 1
    i = i + 1

  j = 0
  while j < 32:
    k = j + 1
    while k < 64:
      d = pi[row + j] xor pi[row + k]
      matchMask = int16(ctMaskEqualU64(uint64(k), uint64(ctzList[j])) and 1'u64)
      d = d and (0'i16 - matchMask)
      pi[row + j] = pi[row + j] xor d
      pi[row + k] = pi[row + k] xor d
      k = k + 1
    j = j + 1

  i = 0
  while i < p.pkNRows:
    rowStart = i * fullRowBytes
    t = loadColumnBlock(mat, rowStart, blockIdx, tail)
    j = 0
    while j < 32:
      delta = ((t shr j) xor (t shr ctzList[j])) and 1'u64
      t = t xor (delta shl ctzList[j])
      t = t xor (delta shl j)
      j = j + 1
    storeColumnBlock(mat, rowStart, blockIdx, tail, t)
    i = i + 1

  result = true

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `pkGen`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc pkGen*(p: McElieceParams, g: openArray[GF], perm: openArray[uint32],
    pi: var seq[int16], pk: var seq[byte], pivots: var uint64): bool =
  ## Generate a systematic public key from a Goppa polynomial and permutation.
  var
    buf = newSeq[uint64](1 shl p.gfBits)
    L = newSeq[GF](p.sysN)
    inv = newSeq[GF](p.sysN)
    invPrefix = newSeq[GF](p.sysN)
    fullRowBytes = p.sysN div 8
    mat = newSeq[byte](p.pkNRows * fullRowBytes)
    row: int = 0
    i: int = 0
    j: int = 0
    k: int = 0
    mask: byte = 0
    tail: int = 0
    pkPtr: int = 0
    rowStart: int = 0
    kStart: int = 0
  defer:
    clearSensitiveWords(buf)
    clearSensitiveWords(L)
    clearSensitiveWords(inv)
    clearSensitiveWords(invPrefix)
    clearSensitiveWords(mat)
  if g.len < p.sysT + 1:
    raise newException(ValueError, "goppa polynomial length mismatch")
  if perm.len < (1 shl p.gfBits):
    raise newException(ValueError, "permutation length mismatch")
  if pi.len < (1 shl p.gfBits):
    pi.setLen(1 shl p.gfBits)

  otterSpan("mceliece.pkGen.sortPerm"):
    for i in 0 ..< buf.len:
      buf[i] = (uint64(perm[i]) shl 31) or uint64(i)
    uint64Sort(buf)
    for i in 1 ..< buf.len:
      if (buf[i - 1] shr 31) == (buf[i] shr 31):
        return false
    for i in 0 ..< pi.len:
      pi[i] = int16(buf[i] and uint64(p.gfMask))
    for i in 0 ..< p.sysN:
      L[i] = bitrev(GF(uint16(pi[i])))

  otterSpan("mceliece.pkGen.rootEval"):
    rootEval(p, g, L, inv)
  otterSpan("mceliece.pkGen.batchInvert"):
    ## Paper note: this is the pkGen call site for the batched GF inverse step.
    batchInvertNonZero(inv, invPrefix, p.sysN)

  otterSpan("mceliece.pkGen.fillMatrix"):
    when defined(avx2):
      ## Paper note: the AVX2 fill path writes the systematic matrix bits via
      ## 64x64 transpose blocks instead of scalar bit extraction.
      fillMatrixTransposedAvx(p, L, inv, mat, fullRowBytes)
    else:
      var b: byte = 0
      i = 0
      while i < p.sysT:
        j = 0
        while j < p.sysN:
          k = 0
          while k < p.gfBits:
            b = byte((inv[j + 7] shr k) and 1'u16)
            b = (b shl 1) or byte((inv[j + 6] shr k) and 1'u16)
            b = (b shl 1) or byte((inv[j + 5] shr k) and 1'u16)
            b = (b shl 1) or byte((inv[j + 4] shr k) and 1'u16)
            b = (b shl 1) or byte((inv[j + 3] shr k) and 1'u16)
            b = (b shl 1) or byte((inv[j + 2] shr k) and 1'u16)
            b = (b shl 1) or byte((inv[j + 1] shr k) and 1'u16)
            b = (b shl 1) or byte((inv[j + 0] shr k) and 1'u16)
            mat[((i * p.gfBits + k) * fullRowBytes) + (j div 8)] = b
            k = k + 1
          j = j + 8
        j = 0
        while j < p.sysN:
          inv[j] = gfMul(inv[j], L[j])
          j = j + 1
        i = i + 1

  otterSpan("mceliece.pkGen.eliminate"):
    ## Paper note: elimination below calls `xorRowMasked`, so row swaps/XORs are
    ## masked and lane-packed where the target ISA supports it.
    i = 0
    while i < (p.pkNRows + 7) div 8:
      j = 0
      while j < 8:
        row = i * 8 + j
        if row >= p.pkNRows:
          break
        if row == p.pkNRows - 32:
          if not movColumns(mat, pi, pivots, p, fullRowBytes):
            return false
        rowStart = row * fullRowBytes
        k = row + 1
        while k < p.pkNRows:
          kStart = k * fullRowBytes
          mask = byte((((mat[rowStart + i] xor mat[kStart + i]) shr j) and 1'u8))
          mask = 0'u8 - mask
          xorRowMasked(mat, rowStart, kStart, fullRowBytes, mask)
          k = k + 1
        if (((mat[rowStart + i] shr j) and 1'u8) == 0'u8):
          return false
        k = 0
        while k < row:
          kStart = k * fullRowBytes
          mask = byte((mat[kStart + i] shr j) and 1'u8)
          mask = 0'u8 - mask
          xorRowMasked(mat, kStart, rowStart, fullRowBytes, mask)
          k = k + 1
        k = row + 1
        while k < p.pkNRows:
          kStart = k * fullRowBytes
          mask = byte((mat[kStart + i] shr j) and 1'u8)
          mask = 0'u8 - mask
          xorRowMasked(mat, kStart, rowStart, fullRowBytes, mask)
          k = k + 1
        j = j + 1
      i = i + 1

  otterSpan("mceliece.pkGen.packPk"):
    pk.setLen(p.pkNRows * p.pkRowBytes)
    tail = p.pkNRows mod 8
    pkPtr = 0
    i = 0
    while i < p.pkNRows:
      rowStart = i * fullRowBytes
      if tail == 0:
        j = 0
        while j < p.pkRowBytes:
          pk[pkPtr] = mat[rowStart + (p.pkNRows div 8) + j]
          pkPtr = pkPtr + 1
          j = j + 1
      else:
        j = (p.pkNRows - 1) div 8
        while j < fullRowBytes - 1:
          pk[pkPtr] = byte(
            ((int(mat[rowStart + j]) shr tail) or
            (int(mat[rowStart + j + 1]) shl (8 - tail))) and 0xFF)
          pkPtr = pkPtr + 1
          j = j + 1
        pk[pkPtr] = byte((int(mat[rowStart + j]) shr tail) and 0xFF)
        pkPtr = pkPtr + 1
      i = i + 1
  result = true
