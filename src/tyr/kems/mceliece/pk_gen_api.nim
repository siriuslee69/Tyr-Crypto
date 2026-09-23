proc fillMatrixScalarRow(p: McElieceParams, L, inv: var seq[GF],
    mat: var seq[byte], fullRowBytes, rowIndex: int) =
  var
    j: int = 0
    k: int = 0
    b: byte = 0
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
      mat[((rowIndex * p.gfBits + k) * fullRowBytes) + (j div 8)] = b
      k = k + 1
    j = j + 8
  j = 0
  while j < p.sysN:
    inv[j] = gfMul(inv[j], L[j])
    j = j + 1

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
      i = 0
      while i < p.sysT:
        fillMatrixScalarRow(p, L, inv, mat, fullRowBytes, i)
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
