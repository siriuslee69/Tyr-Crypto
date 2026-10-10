## ------------------------------------------------------------------
## NuGimli Trails <- greedy differential trails, calibrated on Gimli
## ------------------------------------------------------------------
##
## A "difference" is which bits differ between two inputs. A "trail" is a
## guess of how that difference travels round by round. Its "weight" w
## means the guess holds for 1 in 2^w input pairs. A trail with weight
## below the block size (512, 1024, 2048) is a usable distinguisher.
##
## Only the box is nonlinear, and it works column by column and bit by bit:
##
##   input difference at bit k of one column: (dx, dy, dz), 8 patterns
##   the three AND/OR gates may or may not pass it on
##   -> for each pattern, take the most likely gate outcome (the table)
##
##   gate   feeds output bit   exists only when
##   -----  -----------------  ----------------
##   y & z  c, 2 bits up       k <= 29
##   x | z  b, 1 bit up        k <= 30
##   x & y  a, 3 bits up       k <= 28
##
## "Greedy" = the most likely choice at every bit, never looking ahead.
## It finds A trail, not the BEST trail, so true best weights can be lower.
## The same search on original Gimli finds about 3x the published best
## 8-round weight (168 vs ~52), so divide by about 3 for a cautious view.

import std/[bitops, math]
import runePragmas
import ./primitives
import ./round_model

type
  GateChoice = object
    q: int       ## gate outputs: bit 0 = y&z, bit 1 = x|z, bit 2 = x&y
    w: float     ## -log2 of its probability

  TrailCheck* = object
    rounds*: int
    predicted*: float   ## weight from the model
    measured*: float    ## weight seen on real pairs

proc gateOutcome(v, p, mask: int): int {.inline, role: {math}.} =
  ## v: the three input bits (x, y, z). p: their difference. mask: gates that exist.
  var
    x: int = v and 1
    y: int = (v shr 1) and 1
    z: int = (v shr 2) and 1
    dx: int = p and 1
    dy: int = (p shr 1) and 1
    dz: int = (p shr 2) and 1
    g1: int = (y and z) xor ((y xor dy) and (z xor dz))
    g2: int = (x or z) xor ((x xor dx) or (z xor dz))
    g3: int = (x and y) xor ((x xor dx) and (y xor dy))
  result = (g1 or (g2 shl 1) or (g3 shl 2)) and mask

proc bestGate(p, mask: int): GateChoice {.role: {math}.} =
  ## p/mask: input difference pattern and existing gates. Most likely
  ## outcome; ties go to the one passing fewer differences on.
  var
    Count: array[8, int] = default(array[8, int])
    v, q: int = 0
  while v < 8:
    Count[gateOutcome(v, p, mask)] += 1
    v = v + 1
  result.q = -1
  while q < 8:
    if Count[q] > 0 and (result.q < 0 or Count[q] > Count[result.q] or
        (Count[q] == Count[result.q] and countSetBits(q) < countSetBits(result.q))):
      result.q = q
    q = q + 1
  result.w = log2(8.0 / float(Count[result.q]))

proc buildGateTable(): array[64, GateChoice] {.role: {truthBuilder}.} =
  ## Index p * 8 + mask -> best gate choice.
  var
    i: int = 0
  while i < 64:
    result[i] = bestGate(i div 8, i mod 8)
    i = i + 1

var
  gateTable: array[64, GateChoice] = buildGateTable()

proc existingGates(k: int): int {.inline, role: {parser}.} =
  ## k: bit position. Gates whose shifted output still lands inside the word.
  result = (if k <= 29: 1 else: 0) or (if k <= 30: 2 else: 0) or
    (if k <= 28: 4 else: 0)

proc columnDifference(dx0, dy0, dz0: uint32, W: var float): array[3, uint32]
    {.role: {math}.} =
  ## dx0/dy0/dz0: column difference from chunks a, b, c. W: weight added.
  ## Returns the output difference for chunks a, b, c.
  var
    dx: uint32 = rotateLeftBits(dx0, 24)
    dy: uint32 = rotateLeftBits(dy0, 9)
    dz: uint32 = dz0
    G: array[3, uint32] = default(array[3, uint32])
    active: uint32 = dx or dy or dz
    k, p: int = 0
    g: GateChoice = default(GateChoice)
  while active != 0'u32:
    k = countTrailingZeroBits(active)
    p = int(((dx shr k) and 1'u32) or (((dy shr k) and 1'u32) shl 1) or
      (((dz shr k) and 1'u32) shl 2))
    g = gateTable[p * 8 + existingGates(k)]
    G[0] = G[0] or (uint32(g.q and 1) shl k)
    G[1] = G[1] or (uint32((g.q shr 1) and 1) shl k)
    G[2] = G[2] or (uint32((g.q shr 2) and 1) shl k)
    W = W + g.w
    active = active and (active - 1'u32)
  result[2] = dx xor (dz shl 1) xor (G[0] shl 2)
  result[1] = dy xor dx xor (G[1] shl 1)
  result[0] = dz xor dy xor (G[2] shl 3)

proc boxDifference[N: static[int]](D: var array[N, uint32], a, b, c: int): float
    {.role: {math}.} =
  ## D: difference. a/b/c: chunk window. Returns the weight spent.
  var
    i: int = 0
    o: array[3, uint32] = default(array[3, uint32])
  while i < 4:
    o = columnDifference(D[a * 4 + i], D[b * 4 + i], D[c * 4 + i], result)
    D[a * 4 + i] = o[0]
    D[b * 4 + i] = o[1]
    D[c * 4 + i] = o[2]
    i = i + 1

proc roundDifference*[N: static[int]](D: var array[N, uint32], r: uint32,
    m: LaneMix): float {.role: {math}.} =
  ## D/r/m: difference, round, variant. Returns the round's weight.
  var
    c: int = 0
  while c + 2 < N div 4:
    result = result + boxDifference(D, c, c + 1, c + 2)
    c = c + 1
  linearRound(D, r, m)

proc followTrail[N: static[int]](Best: var seq[float], start, bit: int,
    m: LaneMix) {.role: {math}.} =
  ## Best: lowest weight per round count. start/bit: first round and bit.
  var
    D: array[N, uint32] = default(array[N, uint32])
    w: float = 0.0
    k: int = 0
  D[bit div 32] = 1'u32 shl (bit mod 32)
  while start - k >= 1 and w <= float(N * 32 + 64):
    w = w + roundDifference(D, uint32(start - k), m)
    k = k + 1
    Best[k] = min(Best[k], w)

proc greedyTrails*[N: static[int]](m: LaneMix): seq[float] {.role: {orchestrator}.} =
  ## m: variant. Index k = lowest greedy weight over k rounds, from any
  ## single active input bit at any starting round.
  var
    R: int = fullRounds[N]()
    j: int = 0
  result = newSeq[float](R + 1)
  while j <= R:
    result[j] = Inf
    j = j + 1
  j = 0
  while j < R * N * 32:
    followTrail[N](result, j div (N * 32) + 1, j mod (N * 32), m)
    j = j + 1

## ╭⟢ Gimli calibration

proc gimliRoundDifference(D: var array[12, uint32], r: int): float {.role: {math}.} =
  ## D/r: Gimli difference and round. Gimli swaps only its first row.
  result = boxDifference(D, 0, 1, 2)
  if (r and 3) == 0:
    swap(D[0], D[1])
    swap(D[2], D[3])
  elif (r and 3) == 2:
    swap(D[0], D[2])
    swap(D[1], D[3])

proc followGimli(Best: var seq[float], start, bit: int) {.role: {math}.} =
  ## Best: lowest weight per round count. start/bit: first round and bit.
  var
    D: array[12, uint32] = default(array[12, uint32])
    w: float = 0.0
    k: int = 0
  D[bit div 32] = 1'u32 shl (bit mod 32)
  while start - k >= 1 and w <= 450.0:
    w = w + gimliRoundDifference(D, start - k)
    k = k + 1
    Best[k] = min(Best[k], w)

proc gimliGreedyTrails*(): seq[float] {.role: {orchestrator}.} =
  ## The same greedy search on original 384-bit Gimli, 24 rounds.
  var
    j: int = 0
  result = newSeq[float](25)
  while j <= 24:
    result[j] = Inf
    j = j + 1
  j = 0
  while j < 24 * 384:
    followGimli(result, j div 384 + 1, j mod 384)
    j = j + 1

## ╭⟢ Check the model on real pairs

proc trailWeight[N: static[int]](D: var array[N, uint32], start, rounds: int,
    m: LaneMix): float {.role: {math}.} =
  ## D: difference, moved along the trail. start/rounds/m: window, variant.
  var
    k: int = 0
  while k < rounds:
    result = result + roundDifference(D, uint32(start - k), m)
    k = k + 1

proc runRounds[N: static[int]](S: var array[N, uint32], start, rounds: int,
    m: LaneMix) {.role: {math}.} =
  ## S: state through `rounds` real rounds, counting down from `start`.
  var
    k: int = 0
  while k < rounds:
    forwardRound(S, uint32(start - k), m)
    k = k + 1

proc predictedTrail[N: static[int]](rounds: int, m: LaneMix,
    start, bit: var int): float {.role: {math}.} =
  ## rounds/m: trail length and variant. start/bit: best start found.
  var
    D: array[N, uint32] = default(array[N, uint32])
    j: int = 0
    w: float = 0.0
  result = Inf
  while j < (fullRounds[N]() - rounds + 1) * N * 32:
    D = default(array[N, uint32])
    D[(j mod (N * 32)) div 32] = 1'u32 shl (j mod 32)
    w = trailWeight(D, rounds + j div (N * 32), rounds, m)
    if w < result:
      result = w
      start = rounds + j div (N * 32)
      bit = j mod (N * 32)
    j = j + 1

proc trailCheck*[N: static[int]](rounds, samples: int, m: LaneMix): TrailCheck
    {.role: {orchestrator}.} =
  ## rounds/samples/m: run real pairs through the best short trail and
  ## count how often they end in the predicted difference.
  var
    start, bit, hits, t: int = 0
    D, A, B: array[N, uint32] = default(array[N, uint32])
    seed: uint64 = 1234'u64
  result.rounds = rounds
  result.predicted = predictedTrail[N](rounds, m, start, bit)
  D[bit div 32] = 1'u32 shl (bit mod 32)
  discard trailWeight(D, start, rounds, m)
  while t < samples:
    fillState(A, seed)
    B = A
    B[bit div 32] = B[bit div 32] xor (1'u32 shl (bit mod 32))
    runRounds(A, start, rounds, m)
    runRounds(B, start, rounds, m)
    xorState(A, B)
    if A == D: hits = hits + 1
    t = t + 1
  result.measured = (if hits > 0: -log2(float(hits) / float(samples)) else: Inf)
