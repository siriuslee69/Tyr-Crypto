## -----------------------------------------------------------------
## NuGimli Scalar Box <- exact forward and inverse Gimli column box
## -----------------------------------------------------------------

import std/bitops
import runePragmas
import ./types

proc gimliBoxAtScalar*[N: static[int]](S: var array[N, uint32], a, b,
    c: int) {.inline, role: {math}.} =
  ## S: state. a/b/c: 128-bit chunk indices used as Gimli rows.
  var
    i: int = 0
    x, y, z: uint32 = 0
  i = 0
  while i < nugimliChunkWords:
    x = rotateLeftBits(S[a * nugimliChunkWords + i], 24)
    y = rotateLeftBits(S[b * nugimliChunkWords + i], 9)
    z = S[c * nugimliChunkWords + i]
    S[c * nugimliChunkWords + i] = x xor (z shl 1) xor ((y and z) shl 2)
    S[b * nugimliChunkWords + i] = y xor x xor ((x or z) shl 1)
    S[a * nugimliChunkWords + i] = z xor y xor ((x and y) shl 3)
    i = i + 1

proc inverseGimliWords(oa, ob, oc: uint32): array[3, uint32]
    {.inline, role: {math}.} =
  ## oa/ob/oc: one output lane from the exact Gimli column box.
  var
    bit: int = 0
    x, y, z: uint32 = 0
  bit = 0
  while bit < 32:
    x = oc xor (z shl 1) xor ((y and z) shl 2)
    y = ob xor x xor ((x or z) shl 1)
    z = oa xor y xor ((x and y) shl 3)
    bit = bit + 1
  result[0] = rotateRightBits(x, 24)
  result[1] = rotateRightBits(y, 9)
  result[2] = z

proc gimliBoxInverseAtScalar*[N: static[int]](S: var array[N, uint32],
    a, b, c: int) {.inline, role: {math}.} =
  ## S: state. a/b/c: chunks produced by gimliBoxAtScalar.
  var
    i: int = 0
    oa, ob, oc: uint32 = 0
    A: array[3, uint32]
  i = 0
  while i < nugimliChunkWords:
    oa = S[a * nugimliChunkWords + i]
    ob = S[b * nugimliChunkWords + i]
    oc = S[c * nugimliChunkWords + i]
    A = inverseGimliWords(oa, ob, oc)
    S[a * nugimliChunkWords + i] = A[0]
    S[b * nugimliChunkWords + i] = A[1]
    S[c * nugimliChunkWords + i] = A[2]
    i = i + 1
