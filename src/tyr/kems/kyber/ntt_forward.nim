proc ntt*(R: var array[kyberN, int16]) {.inline.} =
  ## Forward NTT from standard order to bit-reversed order.
  var
    len: int = 0
    start: int = 0
    j: int = 0
    k: int = 1
    t: int16 = 0
    zeta: int16 = 0
    zeta64Lo: int16 = 0 ## AVX2 path: the two zetas of the fused 64/32 layers
    zeta64Hi: int16 = 0
    zeta16Lo: int16 = 0 ## AVX2 path: the two zetas of the fused 16/8 layers
    zeta16Hi: int16 = 0
    k32: int = 4
    k16: int = 8
  len = 128
  when defined(avx2):
    zeta = zetas[1]
    zeta64Lo = zetas[2]
    zeta64Hi = zetas[3]
    j = 0
    while j < 64:
      nttButterflyInterleavedChunk8(
        unsafeAddr R[j],
        unsafeAddr R[j + 64],
        unsafeAddr R[j + 128],
        unsafeAddr R[j + 192],
        zeta, zeta64Lo, zeta64Hi)
      j = j + 8

    start = 0
    while start < kyberN:
      zeta = zetas[k32]
      k32 = k32 + 1
      zeta16Lo = zetas[k16]
      k16 = k16 + 1
      zeta16Hi = zetas[k16]
      k16 = k16 + 1
      j = start
      while j < start + 16:
        nttButterflyInterleavedChunk8(
          unsafeAddr R[j],
          unsafeAddr R[j + 16],
          unsafeAddr R[j + 32],
          unsafeAddr R[j + 48],
          zeta, zeta16Lo, zeta16Hi)
        j = j + 8
      start = start + 64

    k = 16
    len = 8
    start = 0
    while start < kyberN:
      zeta = zetas[k]
      k = k + 1
      j = start
      while j + 8 <= start + len:
        nttButterflyChunk8(unsafeAddr R[j], unsafeAddr R[j + len], zeta)
        j = j + 8
      while j < start + len:
        t = fqMul(zeta, R[j + len])
        R[j + len] = R[j] - t
        R[j] = R[j] + t
        j = j + 1
      start = j + len
    len = 4
  while len >= 2:
    start = 0
    while start < kyberN:
      zeta = zetas[k]
      k = k + 1
      j = start
      while j < start + len:
        t = fqMul(zeta, R[j + len])
        R[j + len] = R[j] - t
        R[j] = R[j] + t
        j = j + 1
      start = j + len
    len = len shr 1

