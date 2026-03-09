import std/unittest

import ../src/tyr_crypto/custom_crypto/gimli

suite "gimli sse":
  test "SSE permutation matches reference":
    var
      s0: Gimli_Block
      s1: Gimli_Block
      i: int = 0
    i = 0
    while i < s0.len:
      s0[i] = uint32(0x01020304'u32 + uint32(i) * 0x101'u32)
      s1[i] = s0[i]
      i = i + 1
    gimli_core_ref(s0)
    gimliPermuteSse(s1)
    check s0 == s1

  test "SSE 4x permutation matches reference":
    var
      ss: array[4, Gimli_Block]
      rs: array[4, Gimli_Block]
      i: int = 0
      j: int = 0
    i = 0
    while i < ss.len:
      j = 0
      while j < ss[i].len:
        ss[i][j] = uint32(0x01020304'u32 + uint32(i) * 0x11111111'u32 + uint32(j) * 0x101'u32)
        rs[i][j] = ss[i][j]
        j = j + 1
      i = i + 1
    i = 0
    while i < rs.len:
      gimli_core_ref(rs[i])
      i = i + 1
    gimliPermuteSse4x(ss)
    check ss == rs

  test "SSE SIMD state permutation matches reference":
    var
      s0: Gimli_Block
      s1: Gimli_Block
      st: GimliSimdState
      i: int = 0
    i = 0
    while i < s0.len:
      s0[i] = uint32(0x0f0e0d0c'u32 + uint32(i) * 0x111'u32)
      s1[i] = s0[i]
      i = i + 1
    gimli_core_ref(s0)
    st = loadSimdState(s1)
    gimliPermuteSseState(st)
    storeSimdState(st, s1)
    check s0 == s1

  when defined(avx2):
    test "AVX8x permutation matches reference":
      var
        ss: array[8, Gimli_Block]
        rs: array[8, Gimli_Block]
        i: int = 0
        j: int = 0
      i = 0
      while i < ss.len:
        j = 0
        while j < ss[i].len:
          ss[i][j] = uint32(0x0a0b0c0d'u32 + uint32(i) * 0x11111111'u32 + uint32(j) * 0x101'u32)
          rs[i][j] = ss[i][j]
          j = j + 1
        i = i + 1
      i = 0
      while i < rs.len:
        gimli_core_ref(rs[i])
        i = i + 1
      gimliPermuteAvx8x(ss)
      check ss == rs
