## Reference: [FIPS-203] algorithm 9 NTT; pitfall: keep the zeta order and Montgomery scaling exact.
proc nttLayer(R: var array[mlkemN, int16], len: int, k: var int) {.inline.} =
  ## R: polynomial. len: butterfly distance of this layer. k: next zeta index.
  ##   one layer = mlkemN / (2 len) groups, each with its own zeta
  var
    start: int = 0
    j: int = 0
    t: int16 = 0
    zeta: int16 = 0
  while start < mlkemN:
    zeta = zetas[k]
    k = k + 1
    j = start
    while j < start + len:
      t = fqMul(zeta, R[j + len])
      R[j + len] = R[j] - t
      R[j] = R[j] + t
      j = j + 1
    start = j + len

when defined(avx2):
  ## Reference: [FIPS-203] algorithm 9 NTT, layers 16 and 8 fused for one 64-block; pitfall: keep the zeta order exact.
  proc nttBlock64Avx2(R: var array[mlkemN, int16], start: int,
      zeta, zetaLo, zetaHi: int16) {.inline.} =
    ## R/start: polynomial and first index of the 64-coefficient block.
    var
      j: int = start
    while j < start + 16:
      nttButterflyInterleavedChunk8(unsafeAddr R[j], unsafeAddr R[j + 16],
        unsafeAddr R[j + 32], unsafeAddr R[j + 48], zeta, zetaLo, zetaHi)
      j = j + 8

  ## Reference: [FIPS-203] algorithm 9 NTT, one group of the len-8 layer; pitfall: keep the zeta order exact.
  proc nttGroup8Avx2(R: var array[mlkemN, int16], start: int, zeta: int16) {.inline.} =
    ## R/start: polynomial and first index of the 16-coefficient group.
    nttButterflyChunk8(unsafeAddr R[start], unsafeAddr R[start + 8], zeta)

## Reference: [FIPS-203] algorithm 9 NTT; pitfall: keep the zeta order and Montgomery scaling exact.
proc ntt*(R: var array[mlkemN, int16]) {.inline.} =
  ## Forward NTT from standard order to bit-reversed order.
  ##   scalar:  layers 128 64 32 16 8 4 2, one nttLayer each
  ##   AVX2:    128+64 fused | 32+16 fused per 64-block | 8 | then 4 2 scalar
  var
    len: int = 128
    start: int = 0
    j: int = 0
    k: int = 1
    k32: int = 4
    k16: int = 8
  when defined(avx2):
    while j < 64:
      nttButterflyInterleavedChunk8(unsafeAddr R[j], unsafeAddr R[j + 64],
        unsafeAddr R[j + 128], unsafeAddr R[j + 192], zetas[1], zetas[2], zetas[3])
      j = j + 8
    while start < mlkemN:
      nttBlock64Avx2(R, start, zetas[k32], zetas[k16], zetas[k16 + 1])
      k32 = k32 + 1
      k16 = k16 + 2
      start = start + 64
    k = 16
    start = 0
    while start < mlkemN:
      nttGroup8Avx2(R, start, zetas[k])
      k = k + 1
      start = start + 16
    len = 4
  while len >= 2:
    nttLayer(R, len, k)
    len = len shr 1
