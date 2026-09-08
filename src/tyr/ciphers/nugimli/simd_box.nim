## --------------------------------------------------------------
## NuGimli SIMD Box <- one Gimli box in SSE2 or NEON registers
## --------------------------------------------------------------

import tyrPragmas
import simd_nexus/simd/base_operations
import simd_nexus/simd/generic_u32
import ./types

when defined(neon) or defined(arm64) or defined(aarch64):
  type
    NuGimliVec4 = uint32x4
else:
  import nimsimd/avx2
  type
    NuGimliVec4 = M128i

proc loadChunk[N: static[int]](S: array[N, uint32], c: int): NuGimliVec4
    {.inline, role: {dataFetcher}.} =
  ## S: source state. c: 128-bit chunk index.
  var
    A: array[nugimliChunkWords, uint32]
  A[0] = S[c * nugimliChunkWords]
  A[1] = S[c * nugimliChunkWords + 1]
  A[2] = S[c * nugimliChunkWords + 2]
  A[3] = S[c * nugimliChunkWords + 3]
  result = loadU32x4[NuGimliVec4](A)

proc storeChunk[N: static[int]](v: NuGimliVec4, S: var array[N, uint32],
    c: int) {.inline, role: {dataWriter}.} =
  ## v: SIMD value. S: destination state. c: 128-bit chunk index.
  var
    A: array[nugimliChunkWords, uint32]
  A = storeU32x4(v)
  S[c * nugimliChunkWords] = A[0]
  S[c * nugimliChunkWords + 1] = A[1]
  S[c * nugimliChunkWords + 2] = A[2]
  S[c * nugimliChunkWords + 3] = A[3]

proc gimliBoxAtSimd*[N: static[int]](S: var array[N, uint32], a, b,
    c: int) {.inline, role: {math}.} =
  ## S: state. a/b/c: 128-bit chunk indices used as Gimli rows.
  var
    av, bv, cv: NuGimliVec4
    x, y, z: NuGimliVec4
  av = loadChunk(S, a)
  bv = loadChunk(S, b)
  cv = loadChunk(S, c)
  x = rot_left(av, 24)
  y = rot_left(bv, 9)
  z = cv
  cv = x xor (z shl 1) xor ((y and z) shl 2)
  bv = y xor x xor ((x or z) shl 1)
  av = z xor y xor ((x and y) shl 3)
  storeChunk(av, S, a)
  storeChunk(bv, S, b)
  storeChunk(cv, S, c)

proc gimliBoxInverseAtSimd*[N: static[int]](S: var array[N, uint32],
    a, b, c: int) {.inline, role: {math}.} =
  ## S: state. a/b/c: chunks produced by gimliBoxAtSimd.
  var
    bit: int = 0
    oa, ob, oc: NuGimliVec4
    x, y, z: NuGimliVec4
  oa = loadChunk(S, a)
  ob = loadChunk(S, b)
  oc = loadChunk(S, c)
  x = set1U32[NuGimliVec4](0'u32)
  y = x
  z = x
  bit = 0
  while bit < 32:
    x = oc xor (z shl 1) xor ((y and z) shl 2)
    y = ob xor x xor ((x or z) shl 1)
    z = oa xor y xor ((x and y) shl 3)
    bit = bit + 1
  storeChunk(rot_left(x, 8), S, a)
  storeChunk(rot_left(y, 23), S, b)
  storeChunk(z, S, c)
