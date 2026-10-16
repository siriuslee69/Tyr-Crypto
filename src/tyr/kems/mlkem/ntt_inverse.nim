## Reference: [FIPS-203] algorithm 10 NTT^-1; pitfall: keep the zeta order and the final Montgomery factor exact.
proc invNttLayer(R: var array[mlkemN, int16], len: int, k: var int) {.inline.} =
  ## R: polynomial. len: butterfly distance of this layer. k: next zeta index
  ## (counts DOWN, the forward order reversed).
  var
    start: int = 0
    j: int = 0
    t: int16 = 0
    zeta: int16 = 0
  while start < mlkemN:
    zeta = zetas[k]
    k = k - 1
    j = start
    while j < start + len:
      t = R[j]
      R[j] = barrettReduce(t + R[j + len])
      R[j + len] = fqMul(zeta, R[j + len] - t)
      j = j + 1
    start = j + len

when defined(avx2):
  ## Reference: [FIPS-203] algorithm 10 NTT^-1, layers 32 and 64 fused for one 128-block; pitfall: keep the zeta order exact.
  proc invNttBlock128Avx2(R: var array[mlkemN, int16], start: int,
      zetaLo0, zetaLo1, zetaUp: int16) {.inline.} =
    ## R/start: polynomial and first index of the 128-coefficient block.
    var
      j: int = start
    while j < start + 32:
      invNttButterflyInterleavedChunk8(unsafeAddr R[j], unsafeAddr R[j + 32],
        unsafeAddr R[j + 64], unsafeAddr R[j + 96], zetaLo0, zetaLo1, zetaUp)
      j = j + 8

## Reference: [FIPS-203] algorithm 10 NTT^-1; pitfall: keep the zeta order and the final Montgomery factor exact.
proc invNtt*(R: var array[mlkemN, int16]) {.inline.} =
  ## Inverse NTT back to standard order and Montgomery scale factor.
  ##   scalar:  scale by f, then layers 2 4 8 ... 128, one invNttLayer each
  ##   AVX2:    scale, layers 2 4 scalar | 8+16 fused | 32+64 fused | 128
  const f = 1441'i16 ## mont^2 / 128
  var
    start: int = 0
    len: int = 2
    j: int = 0
    k: int = 127
    b: int = 0   ## AVX2 path: which 32- or 128-coefficient block
  when defined(avx2):
    while j + 8 <= mlkemN:
      montgomeryMulChunk8(unsafeAddr R[j], unsafeAddr R[j], f)
      j = j + 8
    while len <= 4:
      invNttLayer(R, len, k)
      len = len shl 1
    while start < mlkemN:
      b = start shr 5
      invNttButterflyInterleavedChunk8(unsafeAddr R[start], unsafeAddr R[start + 8],
        unsafeAddr R[start + 16], unsafeAddr R[start + 24],
        zetas[31 - 2 * b], zetas[30 - 2 * b], zetas[15 - b])
      start = start + 32
    start = 0
    while start < mlkemN:
      b = start shr 7
      invNttBlock128Avx2(R, start, zetas[7 - 2 * b], zetas[6 - 2 * b], zetas[3 - b])
      start = start + 128
    j = 0
    while j < 128:
      invNttButterflyChunk8(unsafeAddr R[j], unsafeAddr R[j + 128], zetas[1])
      j = j + 8
  else:
    while j < mlkemN:
      R[j] = fqMul(R[j], f)
      j = j + 1
    while len <= 128:
      invNttLayer(R, len, k)
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
