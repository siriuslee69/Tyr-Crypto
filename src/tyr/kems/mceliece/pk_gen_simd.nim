when defined(avx2):
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `fillMatrixTransposedAvx`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc fillMatrixTransposedAvx(p: McElieceParams; L: openArray[GF];
      inv: var seq[GF]; mat: var seq[byte]; fullRowBytes: int) =
    ## Paper note: public-key generation follows the Classic McEliece bit-matrix
    ## layout, but AVX2 fills 64 support positions through a 64x64 transpose.
    var
      inRows: array[64, uint64] = default(array[64, uint64])
      outRows: array[64, uint64] = default(array[64, uint64])
      tailBytes: array[8, byte] = default(array[8, byte])
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
