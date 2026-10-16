## Reference: [FIPS-203] algorithm 10 NTT^-1; pitfall: keep the zeta order and the final Montgomery factor exact.
proc invNtt*(R: var array[mlkemN, int16]) {.inline.} =
  ## Inverse NTT back to standard order and Montgomery scale factor.
  var
    start: int = 0
    len: int = 2
    j: int = 0
    k: int = 127
    t: int16 = 0
    zeta: int16 = 0
    blockIdx: int = 0   ## AVX2 path: which 32- or 128-coefficient block
    zetaUpper: int16 = 0
    zetaLower0: int16 = 0
    zetaLower1: int16 = 0
  const f = 1441'i16 ## mont^2 / 128
  when defined(avx2):
    j = 0
    while j + 8 <= mlkemN:
      montgomeryMulChunk8(unsafeAddr R[j], unsafeAddr R[j], f)
      j = j + 8
    while j < mlkemN:
      R[j] = fqMul(R[j], f)
      j = j + 1
    len = 2
    while len <= 4:
      start = 0
      while start < mlkemN:
        zeta = zetas[k]
        k = k - 1
        j = start
        while j < start + len:
          t = R[j]
          R[j] = barrettReduce(t + R[j + len])
          R[j + len] = R[j + len] - t
          R[j + len] = fqMul(zeta, R[j + len])
          j = j + 1
        start = j + len
      len = len shl 1
    start = 0
    while start < mlkemN:
      blockIdx = start shr 5
      zetaUpper = zetas[15 - blockIdx]
      zetaLower0 = zetas[31 - 2 * blockIdx]
      zetaLower1 = zetas[30 - 2 * blockIdx]
      invNttButterflyInterleavedChunk8(
        unsafeAddr R[start],
        unsafeAddr R[start + 8],
        unsafeAddr R[start + 16],
        unsafeAddr R[start + 24],
        zetaLower0, zetaLower1, zetaUpper)
      start = start + 32
    start = 0
    while start < mlkemN:
      blockIdx = start shr 7
      zetaUpper = zetas[3 - blockIdx]
      zetaLower0 = zetas[7 - 2 * blockIdx]
      zetaLower1 = zetas[6 - 2 * blockIdx]
      j = start
      while j < start + 32:
        invNttButterflyInterleavedChunk8(
          unsafeAddr R[j],
          unsafeAddr R[j + 32],
          unsafeAddr R[j + 64],
          unsafeAddr R[j + 96],
          zetaLower0, zetaLower1, zetaUpper)
        j = j + 8
      start = start + 128
    zeta = zetas[1]
    j = 0
    while j + 8 <= 128:
      invNttButterflyChunk8(unsafeAddr R[j], unsafeAddr R[j + 128], zeta)
      j = j + 8
    while j < 128:
      t = R[j]
      R[j] = barrettReduce(t + R[j + 128])
      R[j + 128] = R[j + 128] - t
      R[j + 128] = fqMul(zeta, R[j + 128])
      j = j + 1
  else:
    j = 0
    while j < mlkemN:
      R[j] = fqMul(R[j], f)
      j = j + 1
    len = 2
    while len <= 128:
      start = 0
      while start < mlkemN:
        zeta = zetas[k]
        k = k - 1
        j = start
        while j < start + len:
          t = R[j]
          R[j] = barrettReduce(t + R[j + len])
          R[j + len] = R[j + len] - t
          R[j + len] = fqMul(zeta, R[j + len])
          j = j + 1
        start = j + len
      len = len shl 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; finite-field, ring, and transform arithmetic for `baseMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc baseMul*(R: var array[2, int16], A, B: array[2, int16], zeta: int16) {.inline.} =
  ## Multiply two degree-1 polynomials in Z_q[X]/(X^2 - zeta).
  R[0] = fqMul(A[1], B[1])
  R[0] = fqMul(R[0], zeta)
  R[0] = R[0] + fqMul(A[0], B[0])
  R[1] = fqMul(A[0], B[1])
  R[1] = R[1] + fqMul(A[1], B[0])

{.pop.}
