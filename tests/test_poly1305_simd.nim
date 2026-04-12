import std/unittest

import ../src/protocols/custom_crypto/poly1305 as custom_poly1305

proc copyTag(t: custom_poly1305.Poly1305Tag): seq[byte] =
  result = newSeq[byte](t.len)
  for i in 0 ..< t.len:
    result[i] = t[i]

suite "poly1305 simd":
  when defined(amd64) or defined(i386):
    test "SSE2x batch matches scalar":
      var
        keys: array[2, array[custom_poly1305.poly1305KeyBytes, byte]]
        msgs: array[2, seq[byte]]
        outs: array[2, custom_poly1305.Poly1305Tag]
        i: int = 0
        j: int = 0
      i = 0
      while i < 2:
        j = 0
        while j < custom_poly1305.poly1305KeyBytes:
          keys[i][j] = uint8((i * 29 + j) mod 256)
          j = j + 1
        msgs[i] = newSeq[byte](32)
        j = 0
        while j < msgs[i].len:
          msgs[i][j] = uint8((i * 17 + j * 3) mod 256)
          j = j + 1
        i = i + 1
      outs = custom_poly1305.poly1305MacSse2x(keys, msgs)
      i = 0
      while i < 2:
        check copyTag(outs[i]) == custom_poly1305.poly1305Tag(keys[i], msgs[i])
        i = i + 1

  when defined(avx2):
    test "AVX4x batch matches scalar":
      var
        keys: array[4, array[custom_poly1305.poly1305KeyBytes, byte]]
        msgs: array[4, seq[byte]]
        outs: array[4, custom_poly1305.Poly1305Tag]
        i: int = 0
        j: int = 0
      i = 0
      while i < 4:
        j = 0
        while j < custom_poly1305.poly1305KeyBytes:
          keys[i][j] = uint8((i * 41 + j) mod 256)
          j = j + 1
        msgs[i] = newSeq[byte](48)
        j = 0
        while j < msgs[i].len:
          msgs[i][j] = uint8((i * 13 + j * 5) mod 256)
          j = j + 1
        i = i + 1
      outs = custom_poly1305.poly1305MacAvx4x(keys, msgs)
      i = 0
      while i < 4:
        check copyTag(outs[i]) == custom_poly1305.poly1305Tag(keys[i], msgs[i])
        i = i + 1
