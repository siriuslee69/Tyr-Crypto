## ------------------------------------------------------------------
## NuGimli Cascade Core <- optimized reversible wide Gimli schedule
## ------------------------------------------------------------------
## overlapping boxes <- one-bit twist <- butterfly chunk exchanges

import std/bitops
import metaPragmas
import ./types
import ./scalar_box

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  import ./simd_box

proc applyCascadeBox[N: static[int]](S: var array[N, uint32], a, b, c: int,
    inverse, optimized: static[bool]) {.inline, role: {math}.} =
  ## S: state. a/b/c: overlapping chunk indices. inverse/optimized: backend.
  when optimized and (defined(sse2) or defined(neon) or defined(arm64) or
      defined(aarch64)):
    when inverse:
      gimliBoxInverseAtSimd(S, a, b, c)
    else:
      gimliBoxAtSimd(S, a, b, c)
  else:
    when inverse:
      gimliBoxInverseAtScalar(S, a, b, c)
    else:
      gimliBoxAtScalar(S, a, b, c)

proc cascadeBoxes[N: static[int]](S: var array[N, uint32],
    inverse, optimized: static[bool]) {.inline, role: {math}.} =
  ## S: state traversed by every overlapping three-chunk window.
  const chunks = N div nugimliChunkWords
  var
    c: int = 0
  when inverse:
    c = chunks - 3
    while c >= 0:
      applyCascadeBox(S, c, c + 1, c + 2, true, optimized)
      c = c - 1
  else:
    c = 0
    while c + 2 < chunks:
      applyCascadeBox(S, c, c + 1, c + 2, false, optimized)
      c = c + 1

proc cascadeLaneSwap[N: static[int]](S: var array[N, uint32], r: uint32)
    {.inline, role: {helper}.} =
  ## S: state. r: public round selecting target chunk and Gimli lane swap.
  const chunks = N div nugimliChunkWords
  var
    c, o: int = 0
  c = (int(r) * 5) and (chunks - 1)
  o = c * nugimliChunkWords
  case r and 3'u32
  of 0'u32:
    swap(S[o], S[o + 1])
    swap(S[o + 2], S[o + 3])
  of 2'u32:
    swap(S[o], S[o + 2])
    swap(S[o + 1], S[o + 3])
  else:
    discard

proc cascadeBitTwist[N: static[int]](S: var array[N, uint32],
    inverse: static[bool]) {.inline, role: {math}.} =
  ## S: state. inverse: undo or apply the one-bit trail break.
  var
    i: int = 0
  i = 0
  while i < N:
    when inverse:
      S[i] = rotateRightBits(S[i], 1)
    else:
      S[i] = rotateLeftBits(S[i], 1)
    i = i + 1

proc cascadeRoundConstant[N: static[int]](S: var array[N, uint32],
    r: uint32) {.inline, role: {math}.} =
  ## S/r: state and public round receiving width-separated constants.
  var
    d: uint32 = 0'u32
  d = cascadeRoundDomain xor uint32(N * 32)
  S[0] = S[0] xor d xor r
  S[N - 1] = S[N - 1] xor rotateLeftBits(d xor uint32(N),
    int(r and 31'u32))

proc butterflyDistance(chunks: static[int], r: uint32): int
    {.inline, role: {parser}.} =
  ## chunks/r: public width and round selecting a power-of-two swap distance.
  case chunks
  of 4:
    result = 1 shl int((r - 1'u32) mod 2'u32)
  of 8:
    result = 1 shl int((r - 1'u32) mod 3'u32)
  of 16:
    result = 1 shl int((r - 1'u32) mod 4'u32)
  else:
    raise newException(ValueError, "Cascade supports 4, 8, or 16 chunks")

proc cascadeButterfly[N: static[int]](S: var array[N, uint32], r: uint32)
    {.inline, role: {helper}.} =
  ## S/r: state and public round selecting a self-inverse block exchange.
  const chunks = N div nugimliChunkWords
  var
    c, d: int = 0
  d = butterflyDistance(chunks, r)
  c = 0
  while c < chunks:
    swapChunkBlocks(S, c, c + d, d)
    c = c + d * 2

proc cascadeForwardRound[N: static[int]](S: var array[N, uint32], r: uint32,
    optimized: static[bool]) {.inline, role: {math}.} =
  ## S/r: state and round. optimized: SIMD or portable box backend.
  cascadeBoxes(S, false, optimized)
  cascadeLaneSwap(S, r)
  cascadeBitTwist(S, false)
  cascadeRoundConstant(S, r)
  cascadeButterfly(S, r)

proc cascadeInverseRound[N: static[int]](S: var array[N, uint32], r: uint32,
    optimized: static[bool]) {.inline, role: {math}.} =
  ## S/r: state and round undone in exact reverse order.
  cascadeButterfly(S, r)
  cascadeRoundConstant(S, r)
  cascadeBitTwist(S, true)
  cascadeLaneSwap(S, r)
  cascadeBoxes(S, true, optimized)

proc validateCascadeWidth(N: static[int]) {.inline, role: {parser}.} =
  ## N: compile-time state width in 32-bit words.
  if N != 16 and N != 32 and N != 64:
    raise newException(ValueError, "Cascade state must be 512, 1024, or 2048 bits")

proc cascadePermuteCore*[N: static[int]](S: var array[N, uint32],
    rounds: static[int], optimized: static[bool] = true) {.role: {math}.} =
  ## S: fixed-width state. rounds: descending full-round count.
  var
    r: uint32 = uint32(rounds)
  validateCascadeWidth(N)
  while r > 0'u32:
    cascadeForwardRound(S, r, optimized)
    r = r - 1'u32

proc cascadePermuteWindowCore*[N: static[int]](S: var array[N, uint32],
    startRound, count: int, optimized: static[bool] = true) {.role: {math}.} =
  ## S: state. startRound/count: exact descending prefix window.
  var
    r: uint32 = 0'u32
    remaining: int = count
  validateCascadeWidth(N)
  if startRound <= 0 or count < 0 or count > startRound:
    raise newException(ValueError, "Cascade round window is invalid")
  r = uint32(startRound)
  while remaining > 0:
    cascadeForwardRound(S, r, optimized)
    r = r - 1'u32
    remaining = remaining - 1

proc cascadeInvertCore*[N: static[int]](S: var array[N, uint32],
    rounds: static[int], optimized: static[bool] = true) {.role: {math}.} =
  ## S: permuted state. rounds: ascending inverse-round count.
  var
    r: uint32 = 1'u32
  validateCascadeWidth(N)
  while r <= uint32(rounds):
    cascadeInverseRound(S, r, optimized)
    r = r + 1'u32

proc xorCascadeKey[N: static[int]](S: var array[N, uint32],
    K: array[N, uint32]) {.inline, role: {math}.} =
  ## S/K: same-width state and key xor layer.
  var
    i: int = 0
  i = 0
  while i < N:
    S[i] = S[i] xor K[i]
    i = i + 1

proc cascadeEncryptCore*[N: static[int]](X, K: array[N, uint32],
    rounds: static[int]): array[N, uint32] {.role: {encryptor}.} =
  ## X/K: same-width block and key for K xor P(X xor K).
  result = X
  xorCascadeKey(result, K)
  cascadePermuteCore(result, rounds)
  xorCascadeKey(result, K)

proc cascadeDecryptCore*[N: static[int]](C, K: array[N, uint32],
    rounds: static[int]): array[N, uint32] {.role: {decryptor}.} =
  ## C/K: same-width block and key for K xor P^-1(C xor K).
  result = C
  xorCascadeKey(result, K)
  cascadeInvertCore(result, rounds)
  xorCascadeKey(result, K)
