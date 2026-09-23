proc movColumns(mat: var seq[byte], pi: var seq[int16], pivots: var uint64,
    p: McElieceParams, fullRowBytes: int): bool =
  var
    buf: array[32, uint64] = default(array[32, uint64])
    ctzList: array[32, int] = default(array[32, int])
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

include "pk_gen_api.nim"
