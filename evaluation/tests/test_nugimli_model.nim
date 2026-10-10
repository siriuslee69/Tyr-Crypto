## ------------------------------------------------------------------
## NuGimli Model Tests <- the analysis model must equal the real cipher
## ------------------------------------------------------------------
##
## Every reduced-round number in build/nugimli_rounds.md comes from
## evaluation/nugimli_analysis/round_model.nim, not from src/. These tests
## make sure that model is the cipher:
##
##   model (lmOneChunk)  ==  src/ permutation and inverse, all widths
##   bit-by-bit inverse  ==  32-pass inverse, on random columns
##   every LaneMix       ->  still a permutation (inverse undoes it)

import std/unittest
import runePragmas
import ../nugimli_analysis/primitives
import ../nugimli_analysis/round_model

proc modelMatchesSource[N: static[int]](seed: uint64): bool {.role: {helper}.} =
  ## seed: test pattern. True when model and src/ agree both ways.
  var
    s: uint64 = seed
    X, A, B: array[N, uint32] = default(array[N, uint32])
  fillState(X, s)
  A = X
  B = X
  modelPermute(A, lmOneChunk)
  permuteFull(B)
  result = A == B
  modelInvert(A, lmOneChunk)
  result = result and A == X

proc inversesAgree(count: int): int {.role: {helper}.} =
  ## count: random columns tried. Returns how many disagreed.
  var
    s: uint64 = 0x5eed'u64
    i: int = 0
    o: array[3, uint32] = default(array[3, uint32])
    x, y, z: uint32 = 0'u32
  while i < count:
    x = uint32(nextSplitMix(s))
    y = uint32(nextSplitMix(s))
    z = uint32(nextSplitMix(s))
    o = boxColumn(x, y, z)
    if boxColumnSolve(o[0], o[1], o[2]) != [x, y, z] or
        boxColumnPasses(o[0], o[1], o[2]) != [x, y, z]:
      result = result + 1
    i = i + 1

proc variantInverts[N: static[int]](m: LaneMix): bool {.role: {helper}.} =
  ## m: lane-mix variant. True when its inverse undoes it.
  var
    s: uint64 = 0xabcdef'u64
    X, A: array[N, uint32] = default(array[N, uint32])
  fillState(X, s)
  A = X
  modelPermute(A, m)
  result = A != X
  modelInvert(A, m)
  result = result and A == X

suite "nugimli analysis model":

  # {.testKind: tkIntegration, covers: "modelPermute|modelInvert".}
  test "model equals the shipped permutation at every width":
    check modelMatchesSource[16](1)
    check modelMatchesSource[32](2)
    check modelMatchesSource[64](3)

  # {.testKind: tkProperty, covers: "boxColumnSolve|boxColumnPasses".}
  test "both box inverses undo the box":
    check inversesAgree(200_000) == 0

  # {.testKind: tkProperty, covers: "laneSwap".}
  test "every lane-mix variant is still a permutation":
    check variantInverts[16](lmEvenChunks)
    check variantInverts[32](lmEvenChunks)
    check variantInverts[64](lmEvenChunks)
    check variantInverts[16](lmAllChunks)
    check variantInverts[64](lmAllChunks)
