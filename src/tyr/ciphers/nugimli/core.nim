## ------------------------------------------------------------------
## NuGimli Cascade Core <- reversible wide Gimli schedule, all widths
## ------------------------------------------------------------------
##
## One round r (counting down from the width's round count to 1):
##
##   1. boxes        Gimli box on chunks (0,1,2), (1,2,3), ... in order
##   2. lane swap    even r: every even chunk swaps lanes
##                   (r mod 4 = 0: [a b c d] -> [b a d c],
##                    r mod 4 = 2: [a b c d] -> [c d a b])
##   3. twist        every word rotates left by 1 bit
##   4. constants    S[0] ^= d ^ r,  S[N-1] ^= rotl(d ^ N, r mod 32)
##   5. butterfly    blocks of 2^((r-1) mod log2(chunks)) chunks trade places
##
## The inverse runs the same steps backward, rounds counting up.
##
##   cascadePermute(S)       S = P(S)            cascadeEncrypt(X, K) = K ^ P(X ^ K)
##   cascadeInvert(S)        S = P^-1(S)         cascadeDecrypt(C, K) = K ^ P^-1(C ^ K)
##   cascadePermuteWindow    rounds start .. start-count+1 only (analysis tools)
##
## `optimized = false` forces the portable box instead of SSE2/NEON; the
## tests use it to check that both give the same bytes.

import std/bitops
import runePragmas
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
    while c + 2 < chunks:
      applyCascadeBox(S, c, c + 1, c + 2, false, optimized)
      c = c + 1

proc swapLanePairs[N: static[int]](S: var array[N, uint32], o, p: int)
    {.inline, role: {helper}.} =
  ## S: state. o: first word of the chunk. p: 1 = small swap, 2 = big swap.
  ##   p = 1:  [a b c d] -> [b a d c]
  ##   p = 2:  [a b c d] -> [c d a b]
  swap(S[o], S[o + p])
  swap(S[o + 3 - p], S[o + 3])

proc cascadeLaneSwap[N: static[int]](S: var array[N, uint32], r: uint32)
    {.inline, role: {helper}.} =
  ## S: state. r: public round. On even rounds every EVEN chunk (0, 2, 4 ...)
  ## swaps its lanes; odd chunks keep theirs, so the next box window mixes
  ## two lane orders. Swapping every chunk would only rename the lanes.
  const chunks = N div nugimliChunkWords
  var
    c, p: int = 0
  case r and 3'u32
  of 0'u32: p = 1
  of 2'u32: p = 2
  else: return
  while c < chunks:
    swapLanePairs(S, c * nugimliChunkWords, p)
    c = c + 2

proc cascadeBitTwist[N: static[int]](S: var array[N, uint32],
    inverse: static[bool]) {.inline, role: {math}.} =
  ## S: state. inverse: undo or apply the one-bit trail break.
  var
    i: int = 0
  while i < N:
    when inverse:
      S[i] = rotateRightBits(S[i], 1)
    else:
      S[i] = rotateLeftBits(S[i], 1)
    i = i + 1

proc cascadeRoundConstant[N: static[int]](S: var array[N, uint32],
    r: uint32) {.inline, role: {math}.} =
  ## S/r: state and public round receiving width-separated constants.
  const d: uint32 = cascadeRoundDomain xor uint32(N * 32)
  S[0] = S[0] xor d xor r
  S[N - 1] = S[N - 1] xor rotateLeftBits(d xor uint32(N), int(r and 31'u32))

proc cascadeButterfly[N: static[int]](S: var array[N, uint32], r: uint32)
    {.inline, role: {helper}.} =
  ## S/r: state and public round. Blocks of d = 2^((r-1) mod log2(chunks))
  ## chunks trade places with their neighbour block (self-inverse).
  const
    chunks = N div nugimliChunkWords
    logChunks = fastLog2(chunks)
  var
    d: int = 1 shl int((r - 1'u32) mod uint32(logChunks))
    c: int = 0
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

proc cascadePermuteWindow*[N: static[int]](S: var array[N, uint32],
    startRound, count: int, optimized: static[bool] = true) {.role: {math}.} =
  ## S: state. Runs rounds startRound, startRound - 1, ... (count of them),
  ## the same rounds the full permutation runs at that point.
  var
    r: uint32 = 0'u32
    remaining: int = count
  requireCascadeWidth(N)
  if startRound <= 0 or count < 0 or count > startRound:
    raise newException(ValueError, "Cascade round window is invalid")
  r = uint32(startRound)
  while remaining > 0:
    cascadeForwardRound(S, r, optimized)
    r = r - 1'u32
    remaining = remaining - 1

proc cascadePermute*[N: static[int]](S: var array[N, uint32],
    optimized: static[bool] = true) {.role: {math}.} =
  ## S: 512-, 1024- or 2048-bit state, permuted in place (all rounds).
  var
    r: uint32 = uint32(cascadeRounds(N))
  requireCascadeWidth(N)
  while r > 0'u32:
    cascadeForwardRound(S, r, optimized)
    r = r - 1'u32

proc cascadeInvert*[N: static[int]](S: var array[N, uint32],
    optimized: static[bool] = true) {.role: {math}.} =
  ## S: permuted state, turned back in place (rounds 1 .. all).
  var
    r: uint32 = 1'u32
  requireCascadeWidth(N)
  while r <= uint32(cascadeRounds(N)):
    cascadeInverseRound(S, r, optimized)
    r = r + 1'u32

proc xorCascadeKey[N: static[int]](S: var array[N, uint32],
    K: array[N, uint32]) {.inline, role: {math}.} =
  ## S/K: same-width state and key xor layer.
  var
    i: int = 0
  while i < N:
    S[i] = S[i] xor K[i]
    i = i + 1

proc cascadeEncrypt*[N: static[int]](X, K: array[N, uint32]): array[N, uint32]
    {.role: {encryptor}.} =
  ## X/K: same-width block and key. Returns K xor P(X xor K).
  result = X
  xorCascadeKey(result, K)
  cascadePermute(result)
  xorCascadeKey(result, K)

proc cascadeDecrypt*[N: static[int]](C, K: array[N, uint32]): array[N, uint32]
    {.role: {decryptor}.} =
  ## C/K: same-width block and key. Returns K xor P^-1(C xor K).
  result = C
  xorCascadeKey(result, K)
  cascadeInvert(result)
  xorCascadeKey(result, K)
