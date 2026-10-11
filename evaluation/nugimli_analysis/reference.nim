## ----------------------------------------------------------------------
## NuGimli Cascade Reference <- direct scalar round loops for comparison
## ----------------------------------------------------------------------
##
## A test oracle, not part of the library: the same rounds as
## src/tyr/ciphers/nugimli/core.nim, written out as plain loops with the
## portable box and none of core's helpers. The published vectors
## (docs/NUGIMLI_CASCADE_VECTORS.md) come from these loops; the tests
## check that core, this file and round_model.nim agree bit for bit.

import std/bitops
import runePragmas
import ../../src/tyr/ciphers/nugimli/types
import ../../src/tyr/ciphers/nugimli/scalar_box

proc referenceLaneSwap[N: static[int]](S: var array[N, uint32], r: uint32)
    {.role: {math}.} =
  ## Even rounds: every even chunk swaps its lanes (self-inverse).
  var
    o: int = 0
  while o < N:
    case r and 3'u32
    of 0'u32:
      swap(S[o], S[o + 1])
      swap(S[o + 2], S[o + 3])
    of 2'u32:
      swap(S[o], S[o + 2])
      swap(S[o + 1], S[o + 3])
    else:
      discard
    o = o + 2 * nugimliChunkWords

proc referenceConstants[N: static[int]](S: var array[N, uint32], r: uint32)
    {.role: {math}.} =
  ## Round constants (an xor, so the same call undoes them).
  var
    domain: uint32 = cascadeRoundDomain xor uint32(N * 32)
  S[0] = S[0] xor domain xor r
  S[N - 1] = S[N - 1] xor rotateLeftBits(domain xor uint32(N), int(r and 31'u32))

proc referenceButterfly[N: static[int]](S: var array[N, uint32], r: uint32)
    {.role: {math}.} =
  ## Blocks of d chunks trade places with their neighbour (self-inverse):
  ## d = 2^((r-1) mod 2) for 4 chunks, mod 3 for 8, mod 4 for 16.
  var
    period: uint32 = 4'u32
    w: int = 0
    i: int = 0
  case N div nugimliChunkWords
  of 4: period = 2'u32
  of 8: period = 3'u32
  else: discard
  w = (1 shl int((r - 1'u32) mod period)) * nugimliChunkWords
  while i < N:
    if (i div w) mod 2 == 0:
      swap(S[i], S[i + w])
    i = i + 1

proc cascadePermuteReference*[N: static[int]](S: var array[N, uint32]) {.role: {math}.} =
  ## S: state permuted with all rounds of its width, counting down.
  var
    r: uint32 = uint32(cascadeRounds(N))
    c: int = 0
    i: int = 0
  while r > 0'u32:
    c = 0
    while c + 2 < N div nugimliChunkWords:
      gimliBoxAtScalar(S, c, c + 1, c + 2)
      c = c + 1
    referenceLaneSwap(S, r)
    i = 0
    while i < N:
      S[i] = rotateLeftBits(S[i], 1)
      i = i + 1
    referenceConstants(S, r)
    referenceButterfly(S, r)
    r = r - 1'u32

proc cascadeInvertReference*[N: static[int]](S: var array[N, uint32]) {.role: {math}.} =
  ## S: permuted state, turned back with the same steps in reverse.
  var
    r: uint32 = 1'u32
    c: int = 0
    i: int = 0
  while r <= uint32(cascadeRounds(N)):
    referenceButterfly(S, r)
    referenceConstants(S, r)
    i = 0
    while i < N:
      S[i] = rotateRightBits(S[i], 1)
      i = i + 1
    referenceLaneSwap(S, r)
    c = N div nugimliChunkWords - 3
    while c >= 0:
      gimliBoxInverseAtScalar(S, c, c + 1, c + 2)
      c = c - 1
    r = r + 1'u32
