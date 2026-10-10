## ------------------------------------------------------------------------
## NuGimli Round Model <- independent re-implementation for reduced rounds
## ------------------------------------------------------------------------
##
## Written from the specification, NOT copied from src/. Two parts are
## deliberately solved another way, so a shared mistake is unlikely:
##
##   part            src/ does                    this model does
##   --------------  ---------------------------  ---------------------------
##   butterfly       swap blocks of d chunks      chunk i <-> chunk i xor d
##   inverse box     32 fixed passes              bit-by-bit solve (low first)
##
## One round (r counts down from R to 1):
##
##   ┌───────────────────────────────────────────────────────────────┐
##   │ 1 box sweep   windows (0,1,2) (1,2,3) ... left to right       │
##   │ 2 lane swap   r mod 4 = 0: small  [a b c d] -> [b a d c]      │
##   │               r mod 4 = 2: big    [a b c d] -> [c d a b]      │
##   │ 3 twist       every word rotated left by 1                    │
##   │ 4 constants   word 0 and the last word                        │
##   │ 5 butterfly   chunk i <-> chunk i xor 2^((r-1) mod log2 C)    │
##   └───────────────────────────────────────────────────────────────┘
##
## A "lane" is a column: word i of every chunk, i = 0..3. Steps 1, 3, 4
## and 5 never move a bit to another lane. Only step 2 does, and `LaneMix`
## picks which chunks receive it:
##
##   LaneMix        chunks swapped on even rounds   share of the state
##   -------------  ------------------------------  ----------------------
##   lmOneChunk     chunk (5r) mod C only           1/C   <- shipped design
##   lmEvenChunks   chunks 0, 2, 4, ...             1/2   <- candidate fix
##   lmAllChunks    every chunk                     all   <- candidate fix
##
## lmOneChunk reproduces src/ bit for bit; test_nugimli_model checks that.

import std/bitops
import runePragmas
import ./primitives

const
  modelChunkWords* = 4
  modelRoundDomain = 0x43415343'u32

type
  LaneMix* = enum
    lmOneChunk = "one chunk (shipped)"
    lmEvenChunks = "every even chunk"
    lmAllChunks = "every chunk"

## ╭⟢ Box: the Gimli column box and its two inverses

proc boxColumn*(x0, y0, z0: uint32): array[3, uint32] {.inline, role: {math}.} =
  ## x0/y0/z0: one column taken from chunks a, b, c (in that order).
  ## Returns the new words for chunks a, b, c.
  var
    x: uint32 = rotateLeftBits(x0, 24)
    y: uint32 = rotateLeftBits(y0, 9)
    z: uint32 = z0
  result[2] = x xor (z shl 1) xor ((y and z) shl 2)
  result[1] = y xor x xor ((x or z) shl 1)
  result[0] = z xor y xor ((x and y) shl 3)

proc bitAt(v: uint32, k: int): uint32 {.inline, role: {math}.} =
  ## v/k: word and bit position; positions below 0 read as 0.
  if k < 0: result = 0'u32
  else: result = (v shr k) and 1'u32

proc boxColumnSolve*(oa, ob, oc: uint32): array[3, uint32] {.role: {math}.} =
  ## oa/ob/oc: box output for chunks a, b, c. Inverse by solving bit k
  ## from bits below k only; every nonlinear term is shifted left.
  var
    x, y, z: uint32 = 0'u32
    xk, yk, zk: uint32 = 0'u32
    k: int = 0
  while k < 32:
    xk = bitAt(oc, k) xor bitAt(z, k - 1) xor (bitAt(y, k - 2) and bitAt(z, k - 2))
    x = x or (xk shl k)
    yk = bitAt(ob, k) xor xk xor (bitAt(x, k - 1) or bitAt(z, k - 1))
    y = y or (yk shl k)
    zk = bitAt(oa, k) xor yk xor (bitAt(x, k - 3) and bitAt(y, k - 3))
    z = z or (zk shl k)
    k = k + 1
  result = [rotateRightBits(x, 24), rotateRightBits(y, 9), z]

proc boxColumnPasses*(oa, ob, oc: uint32): array[3, uint32] {.inline, role: {math}.} =
  ## oa/ob/oc: box output for chunks a, b, c. Inverse by 32 fixed passes:
  ## each pass makes one more low bit correct. Faster than the bit solve.
  var
    x, y, z: uint32 = 0'u32
    i: int = 0
  while i < 32:
    x = oc xor (z shl 1) xor ((y and z) shl 2)
    y = ob xor x xor ((x or z) shl 1)
    z = oa xor y xor ((x and y) shl 3)
    i = i + 1
  result = [rotateRightBits(x, 24), rotateRightBits(y, 9), z]

proc boxAt[N: static[int]](S: var array[N, uint32], a, b, c: int,
    inverse: bool) {.inline, role: {math}.} =
  ## S: state. a/b/c: chunk window. inverse: undo instead of apply.
  var
    i: int = 0
    o: array[3, uint32] = default(array[3, uint32])
  while i < modelChunkWords:
    if inverse:
      o = boxColumnPasses(S[a * 4 + i], S[b * 4 + i], S[c * 4 + i])
    else:
      o = boxColumn(S[a * 4 + i], S[b * 4 + i], S[c * 4 + i])
    S[a * 4 + i] = o[0]
    S[b * 4 + i] = o[1]
    S[c * 4 + i] = o[2]
    i = i + 1

proc boxSweep[N: static[int]](S: var array[N, uint32]) {.inline, role: {math}.} =
  ## S: state; windows (c, c+1, c+2) from left to right.
  var
    c: int = 0
  while c + 2 < N div 4:
    boxAt(S, c, c + 1, c + 2, false)
    c = c + 1

proc boxSweepInverse[N: static[int]](S: var array[N, uint32]) {.inline, role: {math}.} =
  ## S: state; the same windows undone from right to left.
  var
    c: int = N div 4 - 3
  while c >= 0:
    boxAt(S, c, c + 1, c + 2, true)
    c = c - 1

## ╭⟢ Linear steps: lane swap, twist, constants, butterfly

proc swapLanesOf[N: static[int]](S: var array[N, uint32], c: int,
    r: uint32) {.inline, role: {helper}.} =
  ## S/c/r: state, chunk and round. Small swap on r mod 4 = 0, big on 2.
  var
    o: int = c * 4
  case r and 3'u32
  of 0'u32:
    swap(S[o], S[o + 1])
    swap(S[o + 2], S[o + 3])
  of 2'u32:
    swap(S[o], S[o + 2])
    swap(S[o + 1], S[o + 3])
  else:
    discard

proc laneSwap*[N: static[int]](S: var array[N, uint32], r: uint32,
    m: LaneMix) {.role: {helper}.} =
  ## S/r: state and round. m: which chunks receive the swap.
  const chunks = N div 4
  var
    c: int = 0
    stepC: int = 1
  case m
  of lmOneChunk:
    swapLanesOf(S, (int(r) * 5) and (chunks - 1), r)
  of lmEvenChunks, lmAllChunks:
    stepC = (if m == lmEvenChunks: 2 else: 1)
    while c < chunks:
      swapLanesOf(S, c, r)
      c = c + stepC

proc twist*[N: static[int]](S: var array[N, uint32], inverse: bool)
    {.inline, role: {math}.} =
  ## S: state. inverse: rotate right instead of left.
  var
    i: int = 0
  while i < N:
    S[i] = (if inverse: rotateRightBits(S[i], 1) else: rotateLeftBits(S[i], 1))
    i = i + 1

proc addConstants[N: static[int]](S: var array[N, uint32], r: uint32)
    {.inline, role: {math}.} =
  ## S/r: state and round. Xor is its own inverse, so one routine serves both.
  var
    d: uint32 = modelRoundDomain xor uint32(N * 32)
  S[0] = S[0] xor d xor r
  S[N - 1] = S[N - 1] xor rotateLeftBits(d xor uint32(N), int(r and 31'u32))

proc butterflyDistance*(chunks: int, r: uint32): int {.inline, role: {math}.} =
  ## chunks/r: chunk count (a power of two) and round.
  result = 1 shl int((r - 1'u32) mod uint32(countTrailingZeroBits(chunks)))

proc swapChunks[N: static[int]](S: var array[N, uint32], a, b: int)
    {.inline, role: {helper}.} =
  ## S/a/b: state and the two chunks to exchange.
  swap(S[a * 4], S[b * 4])
  swap(S[a * 4 + 1], S[b * 4 + 1])
  swap(S[a * 4 + 2], S[b * 4 + 2])
  swap(S[a * 4 + 3], S[b * 4 + 3])

proc butterfly*[N: static[int]](S: var array[N, uint32], r: uint32)
    {.role: {helper}.} =
  ## S/r: state and round. Chunk i trades places with chunk i xor d.
  const chunks = N div 4
  var
    c: int = 0
    d: int = butterflyDistance(chunks, r)
  while c < chunks:
    if (c xor d) > c:
      swapChunks(S, c, c xor d)
    c = c + 1

## ╭⟢ Rounds

proc forwardRound*[N: static[int]](S: var array[N, uint32], r: uint32,
    m: LaneMix) {.role: {math}.} =
  ## S/r: state and round number. m: lane-mix variant.
  boxSweep(S)
  laneSwap(S, r, m)
  twist(S, false)
  addConstants(S, r)
  butterfly(S, r)

proc inverseRound*[N: static[int]](S: var array[N, uint32], r: uint32,
    m: LaneMix) {.role: {math}.} =
  ## S/r: state and round number. Undoes forwardRound step by step.
  butterfly(S, r)
  addConstants(S, r)
  twist(S, true)
  laneSwap(S, r, m)
  boxSweepInverse(S)

proc linearRound*[N: static[int]](D: var array[N, uint32], r: uint32,
    m: LaneMix) {.role: {math}.} =
  ## D/r: a DIFFERENCE and round. The linear steps after the boxes;
  ## constants drop out because they cancel in a xor difference.
  laneSwap(D, r, m)
  twist(D, false)
  butterfly(D, r)

proc windowRound*(start, k: int, backward: bool): uint32
    {.inline, role: {parser}.} =
  ## start/k: window start and step. Forward windows count down from start
  ## like the cipher; backward (inverse) windows count up.
  if backward: result = uint32(start + k)
  else: result = uint32(start - k)

proc stepRound*[N: static[int]](S: var array[N, uint32], r: uint32,
    backward: bool, m: LaneMix) {.inline, role: {math}.} =
  ## S/r: state and round. backward: inverse round. m: lane-mix variant.
  if backward: inverseRound(S, r, m)
  else: forwardRound(S, r, m)

proc modelPermute*[N: static[int]](S: var array[N, uint32], m: LaneMix)
    {.role: {math}.} =
  ## S: state through all rounds, R down to 1.
  var
    r: int = fullRounds[N]()
  while r >= 1:
    forwardRound(S, uint32(r), m)
    r = r - 1

proc modelInvert*[N: static[int]](S: var array[N, uint32], m: LaneMix)
    {.role: {math}.} =
  ## S: state through all inverse rounds, 1 up to R.
  var
    r: int = 1
  while r <= fullRounds[N]():
    inverseRound(S, uint32(r), m)
    r = r + 1
