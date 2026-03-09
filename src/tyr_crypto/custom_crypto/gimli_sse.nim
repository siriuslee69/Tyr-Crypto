## ------------------------------------------------------
## Gimli SSE <- SIMD-accelerated Gimli permutation
## ------------------------------------------------------

import simd_nexus/simd/base_operations
import nimsimd/avx2

import ./gimli_types

const
  gimliSwapPairs = 0xB1'i32
  gimliSwapHalves = 0x4E'i32


proc loadVec(s: Gimli_Block, o: int): M128i {.inline.} =
  result = mm_setr_epi32(
    cast[int32](s[o]),
    cast[int32](s[o + 1]),
    cast[int32](s[o + 2]),
    cast[int32](s[o + 3])
  )


proc storeVec(v: M128i, s: var Gimli_Block, o: int) {.inline.} =
  mm_storeu_si128(addr s[o], v)


proc gimli_core_sse*(state: var Gimli_Block) =
  ## SSE-accelerated Gimli permutation (24 rounds).
  var
    round: uint32 = 24
    a: M128i
    b: M128i
    c: M128i
    x: M128i
    y: M128i
    z: M128i
    roundVec: M128i
  a = loadVec(state, 0)
  b = loadVec(state, 4)
  c = loadVec(state, 8)
  round = 24'u32
  while round > 0'u32:
    x = rot_left(a, 24)
    y = rot_left(b, 9)
    z = c
    c = x xor (z shl 1) xor ((y and z) shl 2)
    b = y xor x xor ((x or z) shl 1)
    a = z xor y xor ((x and y) shl 3)
    case (round and 3)
    of 0'u32:
      a = mm_shuffle_epi32(a, gimliSwapPairs)
      roundVec = mm_setr_epi32(cast[int32](0x9e377900'u32 or round), 0, 0, 0)
      a = a xor roundVec
    of 2'u32:
      a = mm_shuffle_epi32(a, gimliSwapHalves)
    else:
      discard
    round = round - 1
  storeVec(a, state, 0)
  storeVec(b, state, 4)
  storeVec(c, state, 8)


proc gimliPermuteSse*(state: var Gimli_Block) {.inline.} =
  gimli_core_sse(state)


type
  GimliSimdState* = array[3, M128i]


proc loadSimdState*(s: Gimli_Block): GimliSimdState {.inline.} =
  var
    st: GimliSimdState
  st[0] = loadVec(s, 0)
  st[1] = loadVec(s, 4)
  st[2] = loadVec(s, 8)
  result = st


proc storeSimdState*(st: GimliSimdState, s: var Gimli_Block) {.inline.} =
  storeVec(st[0], s, 0)
  storeVec(st[1], s, 4)
  storeVec(st[2], s, 8)


proc gimli_core_sse_state*(st: var GimliSimdState) {.inline.} =
  ## SSE-accelerated Gimli permutation (24 rounds) on SIMD state.
  var
    round: uint32 = 24
    a: M128i
    b: M128i
    c: M128i
    x: M128i
    y: M128i
    z: M128i
    roundVec: M128i
  a = st[0]
  b = st[1]
  c = st[2]
  round = 24'u32
  while round > 0'u32:
    x = rot_left(a, 24)
    y = rot_left(b, 9)
    z = c
    c = x xor (z shl 1) xor ((y and z) shl 2)
    b = y xor x xor ((x or z) shl 1)
    a = z xor y xor ((x and y) shl 3)
    case (round and 3)
    of 0'u32:
      a = mm_shuffle_epi32(a, gimliSwapPairs)
      roundVec = mm_setr_epi32(cast[int32](0x9e377900'u32 or round), 0, 0, 0)
      a = a xor roundVec
    of 2'u32:
      a = mm_shuffle_epi32(a, gimliSwapHalves)
    else:
      discard
    round = round - 1
  st[0] = a
  st[1] = b
  st[2] = c


proc gimliPermuteSseState*(st: var GimliSimdState) {.inline.} =
  ## SSE-accelerated Gimli permutation on SIMD state.
  gimli_core_sse_state(st)


proc loadVec4(ss: array[4, Gimli_Block], o: int): M128i {.inline.} =
  result = mm_setr_epi32(
    cast[int32](ss[0][o]),
    cast[int32](ss[1][o]),
    cast[int32](ss[2][o]),
    cast[int32](ss[3][o])
  )


proc storeVec4(v: M128i, ss: var array[4, Gimli_Block], o: int) {.inline.} =
  var
    tmp: array[4, int32]
  mm_storeu_si128(addr tmp[0], v)
  ss[0][o] = uint32(tmp[0])
  ss[1][o] = uint32(tmp[1])
  ss[2][o] = uint32(tmp[2])
  ss[3][o] = uint32(tmp[3])


proc gimli_core_sse4x*(ss: var array[4, Gimli_Block]) {.inline.} =
  ## SSE-accelerated Gimli permutation (24 rounds) for 4 blocks.
  var
    round: uint32 = 24
    s: array[12, M128i]
    column: int = 0
    x: M128i
    y: M128i
    z: M128i
    roundVec: M128i
    i: int = 0
  i = 0
  while i < 12:
    s[i] = loadVec4(ss, i)
    i = i + 1
  round = 24'u32
  while round > 0'u32:
    column = 0
    while column < 4:
      x = rot_left(s[column], 24)
      y = rot_left(s[4 + column], 9)
      z = s[8 + column]
      s[8 + column] = x xor (z shl 1) xor ((y and z) shl 2)
      s[4 + column] = y xor x xor ((x or z) shl 1)
      s[column] = z xor y xor ((x and y) shl 3)
      column = column + 1
    case (round and 3)
    of 0'u32:
      swap(s[0], s[1])
      swap(s[2], s[3])
      roundVec = mm_set1_epi32(cast[int32](0x9e377900'u32 or round))
      s[0] = s[0] xor roundVec
    of 2'u32:
      swap(s[0], s[2])
      swap(s[1], s[3])
    else:
      discard
    round = round - 1
  i = 0
  while i < 12:
    storeVec4(s[i], ss, i)
    i = i + 1


proc gimliPermuteSse4x*(ss: var array[4, Gimli_Block]) {.inline.} =
  ## SSE-accelerated Gimli permutation for 4 blocks.
  gimli_core_sse4x(ss)


when defined(avx2):
  proc loadVec8(ss: array[8, Gimli_Block], o: int): M256i {.inline.} =
    result = mm256_setr_epi32(
      cast[int32](ss[0][o]), cast[int32](ss[1][o]), cast[int32](ss[2][o]), cast[int32](ss[3][o]),
      cast[int32](ss[4][o]), cast[int32](ss[5][o]), cast[int32](ss[6][o]), cast[int32](ss[7][o])
    )

  proc storeVec8(v: M256i, ss: var array[8, Gimli_Block], o: int) {.inline.} =
    var
      tmp: array[8, int32]
    mm256_storeu_si256(addr tmp[0], v)
    ss[0][o] = uint32(tmp[0])
    ss[1][o] = uint32(tmp[1])
    ss[2][o] = uint32(tmp[2])
    ss[3][o] = uint32(tmp[3])
    ss[4][o] = uint32(tmp[4])
    ss[5][o] = uint32(tmp[5])
    ss[6][o] = uint32(tmp[6])
    ss[7][o] = uint32(tmp[7])

  proc gimli_core_avx8x*(ss: var array[8, Gimli_Block]) {.inline.} =
    ## AVX2-accelerated Gimli permutation (24 rounds) for 8 blocks.
    var
      round: uint32 = 24
      s: array[12, M256i]
      column: int = 0
      x: M256i
      y: M256i
      z: M256i
      roundVec: M256i
      i: int = 0
    i = 0
    while i < 12:
      s[i] = loadVec8(ss, i)
      i = i + 1
    round = 24'u32
    while round > 0'u32:
      column = 0
      while column < 4:
        x = rotLeft32(s[column], 24)
        y = rotLeft32(s[4 + column], 9)
        z = s[8 + column]
        s[8 + column] = x xor (z shl 1) xor ((y and z) shl 2)
        s[4 + column] = y xor x xor ((x or z) shl 1)
        s[column] = z xor y xor ((x and y) shl 3)
        column = column + 1
      case (round and 3)
      of 0'u32:
        swap(s[0], s[1])
        swap(s[2], s[3])
        roundVec = mm256_set1_epi32(cast[int32](0x9e377900'u32 or round))
        s[0] = s[0] xor roundVec
      of 2'u32:
        swap(s[0], s[2])
        swap(s[1], s[3])
      else:
        discard
      round = round - 1
    i = 0
    while i < 12:
      storeVec8(s[i], ss, i)
      i = i + 1

  proc gimliPermuteAvx8x*(ss: var array[8, Gimli_Block]) {.inline.} =
    ## AVX2-accelerated Gimli permutation for 8 blocks.
    gimli_core_avx8x(ss)
