import std/unittest

import ../../src/tyr/macs/poly1305 as custom_poly1305

const
  poly1305BoundaryLengths: array[7, int] = [0, 15, 16, 17, 31, 32, 33]

proc copyTag(t: custom_poly1305.Poly1305Tag): seq[byte] =
  result = newSeq[byte](t.len)
  for i in 0 ..< t.len:
    result[i] = t[i]

proc makeKey(i: int): array[custom_poly1305.poly1305KeyBytes, byte] =
  ## i: Batch lane used to make each key distinct.
  var
    j: int = 0
  while j < result.len:
    result[j] = byte((i * 41 + j * 3) mod 256)
    j = j + 1

proc makeMessage(i, l: int): seq[byte] =
  ## i: Batch lane used to make each message distinct.
  ## l: Message length to generate.
  var
    j: int = 0
  result = newSeq[byte](l)
  while j < result.len:
    result[j] = byte((i * 29 + j * 5) mod 256)
    j = j + 1

proc prepareBatch[N: static[int]](
    K: var array[N, array[custom_poly1305.poly1305KeyBytes, byte]],
    M: var array[N, seq[byte]], l: int) =
  ## K: Output keys for each SIMD lane.
  ## M: Output equal-length messages for each SIMD lane.
  ## l: Message length to generate.
  var
    i: int = 0
  while i < N:
    K[i] = makeKey(i)
    M[i] = makeMessage(i, l)
    i = i + 1

proc checkBatch[N: static[int]](
    K: array[N, array[custom_poly1305.poly1305KeyBytes, byte]],
    M: array[N, seq[byte]], O: array[N, custom_poly1305.Poly1305Tag]) =
  ## K: Keys used by each SIMD lane.
  ## M: Messages used by each SIMD lane.
  ## O: SIMD tags to compare with scalar tags.
  var
    i: int = 0
  while i < N:
    check copyTag(O[i]) == custom_poly1305.poly1305Tag(K[i], M[i])
    i = i + 1

template checkBoundaryMatrix(n: static[int], b: untyped) =
  block:
    var
      K: array[n, array[custom_poly1305.poly1305KeyBytes, byte]]
      M: array[n, seq[byte]]
      O: array[n, custom_poly1305.Poly1305Tag]
      i: int = 0
    while i < poly1305BoundaryLengths.len:
      prepareBatch(K, M, poly1305BoundaryLengths[i])
      O = b(K, M)
      checkBatch(K, M, O)
      i = i + 1

suite "poly1305 simd":
  when defined(amd64) or defined(i386):
    test "SSE2x boundary matrix matches scalar":
      checkBoundaryMatrix(2, custom_poly1305.poly1305MacSse2x)

  when defined(avx2):
    test "AVX4x boundary matrix matches scalar":
      checkBoundaryMatrix(4, custom_poly1305.poly1305MacAvx4x)

  when defined(neon) or defined(arm64) or defined(aarch64):
    test "NEON2x boundary matrix matches scalar":
      checkBoundaryMatrix(2, custom_poly1305.poly1305MacNeon2x)
