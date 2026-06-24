## 64x64 bit matrix transpose used by Classic McEliece Benes layers.
## Pure-Nim port of PQClean transpose_64x64 (clean variants).

import std/assertions

## Transpose a 64x64 matrix of bits stored as 64 little-endian 64-bit rows.
proc transpose64x64*(outm: var array[64, uint64], inm: openArray[uint64]) =
  assert inm.len >= 64, "input must contain at least 64 rows"
  for i in 0 .. 63:
    outm[i] = inm[i]

  const masks = [
    (0x5555_5555_5555_5555'u64, 0xAAAA_AAAA_AAAA_AAAA'u64),
    (0x3333_3333_3333_3333'u64, 0xCCCC_CCCC_CCCC_CCCC'u64),
    (0x0F0F_0F0F_0F0F_0F0F'u64, 0xF0F0_F0F0_F0F0_F0F0'u64),
    (0x00FF_00FF_00FF_00FF'u64, 0xFF00_FF00_FF00_FF00'u64),
    (0x0000_FFFF_0000_FFFF'u64, 0xFFFF_0000_FFFF_0000'u64),
    (0x0000_0000_FFFF_FFFF'u64, 0xFFFF_FFFF_0000_0000'u64)
  ]

  var
    d: int = 5
    s: int = 0
    i: int = 0
    j: int = 0
    x: uint64 = 0
    y: uint64 = 0
  while d >= 0:
    s = 1 shl d
    i = 0
    while i < 64:
      j = i
      while j < i + s:
        x = (outm[j] and masks[d][0]) or ((outm[j + s] and masks[d][0]) shl s)
        y = ((outm[j] and masks[d][1]) shr s) or (outm[j + s] and masks[d][1])
        outm[j] = x
        outm[j + s] = y
        j = j + 1
      i += s * 2
    dec d

