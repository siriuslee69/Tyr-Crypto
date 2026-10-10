## ------------------------------------------------------------------------
## NuGimli Reduced Rounds <- how many rounds each property needs to vanish
## ------------------------------------------------------------------------
##
## The full cipher passing statistical tests says little: every serious
## design does. The useful question is how many of its rounds an attack
## property survives. The gap to the full round count is the "margin".
##
##   measurement     question                                   good = few
##   --------------  -----------------------------------------  ----------
##   full diffusion  after how many rounds does every input     rounds
##                   bit flip every output bit at least once?
##   lane reach      ... reach all four lanes (columns)?
##   zero-sum        sum the outputs over all 2^d inputs that
##                   differ only in d chosen bits. Bits that
##                   always sum to 0 ("balanced") are a
##                   distinguisher. For how many rounds?
##   lane symmetry   start with lane 0 = lane 1 (and so on).
##                   When does the state look random again?
##
## Every measurement runs forward (encryption direction) and backward
## (inverse rounds, decryption direction): an attacker picks the weaker.
##
## A "window" is a run of consecutive rounds inside the schedule. Round
## numbers change the constants and swaps, so windows starting at
## different rounds behave differently; "worst" is the slowest window.

import std/bitops
import runePragmas
import ./primitives
import ./round_model

const
  diffusionSamples* = 64     ## pairs per input bit; a fair coin misses 64 times with chance 2^-64
  diffusionInputs* = 128     ## input bits sampled, evenly spaced
  diffusionMaxRounds* = 12   ## longest window measured
  zeroSumMaxRounds* = 12
  zeroSumBases* = 20         ## random fixed parts per cube. A bit survives all
                             ## of them by chance with 2^-20: 2048 bits -> 0.002
  symmetrySamples* = 2000
  symmetryMaxRounds* = 12

type
  Reach* = object
    full*: int    ## rounds until full diffusion (diffusionMaxRounds + 1 = not reached)
    lanes*: int   ## rounds until all four lanes are reached

  ReachSummary* = object
    own*: Reach   ## window at the cipher's own first round
    worst*: Reach ## slowest window over every start

## ╭⟢ Diffusion and lane reach

proc orDifference[N: static[int]](U: var array[N, uint32], A, B: array[N, uint32])
    {.inline, role: {math}.} =
  ## U: flips seen so far. A/B: the pair after the same rounds.
  var
    w: int = 0
  while w < N:
    U[w] = U[w] or (A[w] xor B[w])
    w = w + 1

proc allFlipped[N: static[int]](U: array[N, uint32]): bool {.inline, role: {parser}.} =
  ## U: flips seen so far. True when every output bit flipped at least once.
  var
    w: int = 0
  result = true
  while w < N:
    result = result and U[w] == 0xffffffff'u32
    w = w + 1

proc allLanes[N: static[int]](U: array[N, uint32]): bool {.inline, role: {parser}.} =
  ## U: flips seen so far. True when every lane holds at least one flip.
  var
    L: array[4, uint32] = default(array[4, uint32])
    w: int = 0
  while w < N:
    L[w and 3] = L[w and 3] or U[w]
    w = w + 1
  result = L[0] != 0 and L[1] != 0 and L[2] != 0 and L[3] != 0

proc runPair[N: static[int]](U: var seq[array[N, uint32]], A, B: var array[N, uint32],
    start: int, backward: bool, m: LaneMix) {.role: {math}.} =
  ## U: flips per round. A/B: a pair one input bit apart. start/backward/m: window.
  var
    k: int = 0
    r: uint32 = 0'u32
  while k < U.len:
    r = windowRound(start, k, backward)
    stepRound(A, r, backward, m)
    stepRound(B, r, backward, m)
    orDifference(U[k], A, B)
    k = k + 1

proc firstRound[N: static[int]](U: seq[array[N, uint32]], lanes: bool): int
    {.role: {parser}.} =
  ## U: flips per round. lanes: test lane reach instead of full diffusion.
  ## Returns U.len + 1 when the property never appears.
  var
    k: int = 0
  result = U.len + 1
  while k < U.len and result > U.len:
    if (lanes and allLanes(U[k])) or (not lanes and allFlipped(U[k])):
      result = k + 1
    k = k + 1

proc reachForBit[N: static[int]](bit, start, maxK: int, backward: bool,
    m: LaneMix, seed: var uint64): Reach {.role: {math}.} =
  ## bit: flipped input bit. start/maxK/backward/m: window. seed: sampler.
  var
    U: seq[array[N, uint32]] = newSeq[array[N, uint32]](maxK)
    A, B: array[N, uint32] = default(array[N, uint32])
    t: int = 0
  while t < diffusionSamples:
    fillState(A, seed)
    B = A
    B[bit div 32] = B[bit div 32] xor (1'u32 shl (bit mod 32))
    runPair(U, A, B, start, backward, m)
    t = t + 1
  result.full = firstRound(U, false)
  result.lanes = firstRound(U, true)

proc reachAt*[N: static[int]](start: int, backward: bool, m: LaneMix): Reach
    {.role: {math}.} =
  ## start/backward/m: one window. Slowest sampled input bit wins.
  var
    seed: uint64 = uint64(start * 31 + 7) + (if backward: 1000'u64 else: 0'u64)
    bit: int = 0
    one: Reach = default(Reach)
  while bit < N * 32:
    one = reachForBit[N](bit, start, diffusionMaxRounds, backward, m, seed)
    result.full = max(result.full, one.full)
    result.lanes = max(result.lanes, one.lanes)
    bit = bit + max(1, N * 32 div diffusionInputs)

proc windowFits(R, start: int, backward: bool): bool {.inline, role: {parser}.} =
  ## R/start/backward: true when a full-length window fits the schedule.
  if backward: result = R - start + 1 >= diffusionMaxRounds
  else: result = start >= diffusionMaxRounds

proc reachSummary*[N: static[int]](backward: bool, m: LaneMix): ReachSummary
    {.role: {orchestrator}.} =
  ## backward/m: direction and lane-mix variant, over every window start.
  var
    R: int = fullRounds[N]()
    s: int = 1
    one: Reach = default(Reach)
  while s <= R:
    if windowFits(R, s, backward):
      one = reachAt[N](s, backward, m)
      result.worst.full = max(result.worst.full, one.full)
      result.worst.lanes = max(result.worst.lanes, one.lanes)
    s = s + 1
  result.own = reachAt[N]((if backward: 1 else: R), backward, m)

## ╭⟢ Zero-sums (cube sums)

proc setBits[N: static[int]](S: var array[N, uint32], P: seq[int], mask: int)
    {.inline, role: {helper}.} =
  ## S: base with every cube bit cleared. P: cube bit positions. mask: which to set.
  var
    j: int = 0
  while j < P.len:
    S[P[j] div 32] = S[P[j] div 32] or (uint32((mask shr j) and 1) shl (P[j] mod 32))
    j = j + 1

proc clearBits[N: static[int]](S: var array[N, uint32], P: seq[int])
    {.inline, role: {helper}.} =
  ## S: state. P: positions to clear.
  var
    j: int = 0
  while j < P.len:
    S[P[j] div 32] = S[P[j] div 32] and not (1'u32 shl (P[j] mod 32))
    j = j + 1

proc sumRounds[N: static[int]](Acc: var seq[array[N, uint32]], X: var array[N, uint32],
    start: int, backward: bool, m: LaneMix) {.role: {math}.} =
  ## Acc: xor-sum per round. X: one cube member, stepped through the window.
  var
    k: int = 0
  while k < Acc.len:
    stepRound(X, windowRound(start, k, backward), backward, m)
    xorState(Acc[k], X)
    k = k + 1

proc keepBalanced[N: static[int]](Z: var seq[array[N, uint32]],
    Acc: seq[array[N, uint32]]) {.role: {math}.} =
  ## Z: bits balanced in every base so far. Acc: sums of this base.
  var
    i: int = 0
  while i < Z.len * N:
    Z[i div N][i mod N] = Z[i div N][i mod N] and not Acc[i div N][i mod N]
    i = i + 1

proc cubeOnce[N: static[int]](Z: var seq[array[N, uint32]], P: seq[int],
    start: int, backward: bool, m: LaneMix, seed: var uint64) {.role: {math}.} =
  ## Z: balanced bits. P: cube positions. One random base, all 2^d members.
  var
    base, X: array[N, uint32] = default(array[N, uint32])
    Acc: seq[array[N, uint32]] = newSeq[array[N, uint32]](Z.len)
    mask: int = 0
  fillState(base, seed)
  clearBits(base, P)
  while mask < (1 shl P.len):
    X = base
    setBits(X, P, mask)
    sumRounds(Acc, X, start, backward, m)
    mask = mask + 1
  keepBalanced(Z, Acc)

proc lastBalancedRound[N: static[int]](Z: seq[array[N, uint32]]): int {.role: {parser}.} =
  ## Z: balanced bits per round. Returns the last round that still has one.
  var
    k: int = 0
  while k < Z.len:
    if Z[k] != default(array[N, uint32]): result = k + 1
    k = k + 1

proc allOnes[N: static[int]](): array[N, uint32] {.inline, role: {helper}.} =
  ## Every bit set: "balanced so far" before the first base is summed.
  var
    w: int = 0
  while w < N:
    result[w] = 0xffffffff'u32
    w = w + 1

proc zeroSumRounds*[N: static[int]](P: seq[int], backward: bool, m: LaneMix): int
    {.role: {orchestrator}.} =
  ## P: cube positions. backward/m: direction and variant, at the own start.
  ## Returns the last round with a balanced output bit.
  var
    Z: seq[array[N, uint32]] = newSeq[array[N, uint32]](zeroSumMaxRounds)
    seed: uint64 = 777'u64
    b: int = 0
    start: int = (if backward: 1 else: fullRounds[N]())
  while b < Z.len:
    Z[b] = allOnes[N]()
    b = b + 1
  b = 0
  while b < zeroSumBases:
    cubeOnce(Z, P, start, backward, m, seed)
    b = b + 1
  result = lastBalancedRound(Z)

proc cubeSets*[N: static[int]](d: int): seq[seq[int]] {.role: {truthBuilder}.} =
  ## d: cube size. Six position sets: low and high bits of the first, last
  ## and middle words, the four lanes of the last chunk, and random bits.
  var
    j: int = 0
    seed: uint64 = 31337'u64
    p: int = 0
    S: array[6, seq[int]] = default(array[6, seq[int]])
  while j < d:
    S[0].add(j)
    S[1].add((N - 1) * 32 + j)
    S[2].add((N - 1) * 32 + 31 - j)
    S[3].add((N div 2) * 32 + j)
    S[4].add(((j mod 4) + N - 4) * 32 + j div 4)
    j = j + 1
  while S[5].len < d:
    p = int(nextSplitMix(seed) mod uint64(N * 32))
    if p notin S[5]: S[5].add(p)
  result = @S

proc zeroSumWorst*[N: static[int]](d: int, backward: bool, m: LaneMix): int
    {.role: {orchestrator}.} =
  ## d/backward/m: cube size, direction, variant. Longest-lived set wins.
  var
    P: seq[seq[int]] = cubeSets[N](d)
    i: int = 0
  while i < P.len:
    result = max(result, zeroSumRounds[N](P[i], backward, m))
    i = i + 1

## ╭⟢ Lane symmetry

proc symmetricState[N: static[int]](S: var array[N, uint32], kind: int,
    seed: var uint64) {.role: {helper}.} =
  ## S: state. kind 0: lanes 0=1, 2=3. kind 1: 0=2, 1=3. kind 2: 0=3, 1=2.
  const pairs = [[0, 1, 2, 3], [0, 2, 1, 3], [0, 3, 1, 2]]
  var
    c: int = 0
    a, b: uint32 = 0'u32
  while c < N div 4:
    a = uint32(nextSplitMix(seed))
    b = uint32(nextSplitMix(seed))
    S[c * 4 + pairs[kind][0]] = a
    S[c * 4 + pairs[kind][1]] = a
    S[c * 4 + pairs[kind][2]] = b
    S[c * 4 + pairs[kind][3]] = b
    c = c + 1

proc asymmetry[N: static[int]](S: array[N, uint32], kind: int): int
    {.role: {math}.} =
  ## S/kind: bits where the paired lanes now differ. Random state: N*8.
  const pairs = [[0, 1, 2, 3], [0, 2, 1, 3], [0, 3, 1, 2]]
  var
    c: int = 0
  while c < N div 4:
    result = result + countSetBits(S[c * 4 + pairs[kind][0]] xor S[c * 4 + pairs[kind][1]]) +
      countSetBits(S[c * 4 + pairs[kind][2]] xor S[c * 4 + pairs[kind][3]])
    c = c + 1

proc symmetryRounds*[N: static[int]](kind: int, m: LaneMix): int
    {.role: {orchestrator}.} =
  ## kind/m: symmetric start and variant. Returns the first round where the
  ## mean asymmetry is within 1 % of a random state (N*8 bits).
  var
    Sum: array[symmetryMaxRounds, float] = default(array[symmetryMaxRounds, float])
    S: array[N, uint32] = default(array[N, uint32])
    seed: uint64 = 5'u64 + uint64(kind)
    t, k: int = 0
  while t < symmetrySamples * symmetryMaxRounds:
    k = t mod symmetryMaxRounds
    if k == 0: symmetricState(S, kind, seed)
    forwardRound(S, uint32(fullRounds[N]() - k), m)
    Sum[k] = Sum[k] + float(asymmetry(S, kind))
    t = t + 1
  result = symmetryMaxRounds + 1
  k = symmetryMaxRounds - 1
  while k >= 0:
    if Sum[k] / float(symmetrySamples) >= 0.99 * float(N * 8): result = k + 1
    k = k - 1
