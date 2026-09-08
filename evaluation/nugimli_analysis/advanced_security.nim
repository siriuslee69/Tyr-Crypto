## ----------------------------------------------------------------------
## NuGimli Advanced Security <- algebraic and structural search evidence
## ----------------------------------------------------------------------

import std/[bitops, sets]
import tyrPragmas
import otter_repo_evaluation
import ./primitives

const
  invariantExtraRows* = 64
  deterministicTrials* = 32
  relatedKeyTrials* = 16
  symmetryTrials* = 128
  linearMasks* = 32
  linearSamples* = 8_192
  differentialTrailInputs* = 32
  differentialTrailSamples* = 4_096
  algebraicDegreeTarget* = 20

type
  AdvancedSecurityResult* = object
    bits*: int
    linearRank*: int
    affineRank*: int
    deterministicDifferentials*: int
    deterministicRelatedKeys*: int
    equivalentKeyBits*: int
    symmetryMatches*: int
    symmetryTests*: int
    slideMatches*: int
    slideTests*: int
    structuredInvariantMatches*: int
    structuredInvariantTests*: int
    maxLinearCorrelation*: float64
    minimumDifferenceFingerprints*: int
    maxProjectedDifferentialProbability*: float64
    algebraicDegreeLowerBound*: int

proc packedDifference[N: static[int]](A, B: array[N, uint32]): seq[uint64]
    {.inline, role: {helper}.} =
  ## A/B: paired states packed as one GF(2) difference row.
  var
    i: int = 0
  result.setLen(N div 2)
  i = 0
  while i < N div 2:
    result[i] = uint64(A[i * 2] xor B[i * 2]) or
      (uint64(A[i * 2 + 1] xor B[i * 2 + 1]) shl 32)
    i = i + 1

proc xorPacked(A: var seq[uint64], B: seq[uint64]) {.inline, role: {math}.} =
  ## A/B: equal-width GF(2) rows.
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = A[i] xor B[i]
    i = i + 1

proc buildInvariantMatrices[N: static[int]](seedValue: uint64,
    Linear, Affine: var seq[seq[uint64]]) {.role: {truthBuilder}.} =
  ## seedValue: deterministic sample seed. Linear/Affine: certificate matrices.
  var
    X, Y: array[N, uint32]
    seed: uint64 = seedValue
    base: seq[uint64] = @[]
    row: seq[uint64] = @[]
    i: int = 0
  Linear.setLen(N * 32 + invariantExtraRows)
  Affine.setLen(N * 32 + invariantExtraRows - 1)
  i = 0
  while i < Linear.len:
    fillState(X, seed)
    Y = X
    permuteFull(Y)
    row = packedDifference(X, Y)
    Linear[i] = row
    if i == 0:
      base = row
    else:
      xorPacked(row, base)
      Affine[i - 1] = row
    i = i + 1

proc invariantRanks*[N: static[int]](seedValue: uint64): tuple[linear,
    affine: int] {.role: {orchestrator}.} =
  ## seedValue: deterministic matrix sample seed.
  var
    Linear, Affine: seq[seq[uint64]] = @[]
  buildInvariantMatrices[N](seedValue, Linear, Affine)
  result.linear = gf2Rank(Linear, N * 32)
  result.affine = gf2Rank(Affine, N * 32)

proc differenceEqual[N: static[int]](A0, B0, A1,
    B1: array[N, uint32]): bool {.inline, role: {helper}.} =
  ## A0/B0 and A1/B1: output pairs whose xor differences are compared.
  var
    i: int = 0
  result = true
  i = 0
  while i < N:
    result = result and ((A0[i] xor B0[i]) == (A1[i] xor B1[i]))
    i = i + 1

proc zeroDifference[N: static[int]](A, B: array[N, uint32]): bool
    {.inline, role: {helper}.} =
  ## A/B: paired outputs checked for equality without early exit.
  var
    i: int = 0
    d: uint32 = 0'u32
  i = 0
  while i < N:
    d = d or (A[i] xor B[i])
    i = i + 1
  result = d == 0'u32

proc deterministicPlainBit[N: static[int]](inputBit: int,
    seed: var uint64): bool {.role: {math}.} =
  ## inputBit/seed: candidate translation difference and independent bases.
  var
    X, Y, A, B, A0, B0: array[N, uint32]
    trial, word, shift: int = 0
  word = inputBit div 32
  shift = inputBit mod 32
  result = true
  trial = 0
  while trial < deterministicTrials:
    fillState(X, seed)
    Y = X
    Y[word] = Y[word] xor (1'u32 shl shift)
    A = X
    B = Y
    permuteFull(A)
    permuteFull(B)
    if trial == 0:
      A0 = A
      B0 = B
    else:
      result = result and differenceEqual(A0, B0, A, B)
    trial = trial + 1

proc deterministicKeyBit[N: static[int]](inputBit: int, seed: var uint64,
    equivalent: var bool): bool {.role: {math}.} =
  ## inputBit/seed: related-key candidate. equivalent: exact collision result.
  var
    X, K, K2, A, B, A0, B0: array[N, uint32]
    trial, word, shift: int = 0
  word = inputBit div 32
  shift = inputBit mod 32
  result = true
  equivalent = true
  trial = 0
  while trial < relatedKeyTrials:
    fillState(X, seed)
    fillState(K, seed)
    K2 = K
    K2[word] = K2[word] xor (1'u32 shl shift)
    A = encryptFull(X, K)
    B = encryptFull(X, K2)
    equivalent = equivalent and zeroDifference(A, B)
    if trial == 0:
      A0 = A
      B0 = B
    else:
      result = result and differenceEqual(A0, B0, A, B)
    trial = trial + 1

proc searchDeterministicRelations[N: static[int]](R: var AdvancedSecurityResult,
    seedValue: uint64) {.role: {orchestrator}.} =
  ## R: result accumulator. seedValue: deterministic relation-search seed.
  var
    seed: uint64 = seedValue
    bit: int = 0
    equivalent: bool = false
  bit = 0
  while bit < N * 32:
    if deterministicPlainBit[N](bit, seed):
      R.deterministicDifferentials = R.deterministicDifferentials + 1
    if deterministicKeyBit[N](bit, seed, equivalent):
      R.deterministicRelatedKeys = R.deterministicRelatedKeys + 1
    if equivalent:
      R.equivalentKeyBits = R.equivalentKeyBits + 1
    bit = bit + 1

proc rotateWordBits[N: static[int]](S: array[N, uint32], amount: int): array[N,
    uint32] {.inline, role: {math}.} =
  ## S/amount: state transformed by a uniform within-word rotation.
  var
    i: int = 0
  i = 0
  while i < N:
    result[i] = rotateLeftBits(S[i], amount)
    i = i + 1

proc rotateWords[N: static[int]](S: array[N, uint32], amount: int): array[N,
    uint32] {.inline, role: {math}.} =
  ## S/amount: state transformed by a cyclic word-position rotation.
  var
    i: int = 0
  i = 0
  while i < N:
    result[(i + amount) mod N] = S[i]
    i = i + 1

proc testBitRotation[N: static[int]](amount: int,
    seed: var uint64): int {.role: {math}.} =
  ## amount/seed: candidate rotational symmetry and sample seed.
  var
    X, A, B: array[N, uint32]
    trial: int = 0
  trial = 0
  while trial < symmetryTrials:
    fillState(X, seed)
    A = rotateWordBits(X, amount)
    B = X
    permuteFull(A)
    permuteFull(B)
    B = rotateWordBits(B, amount)
    if A == B:
      result = result + 1
    trial = trial + 1

proc testWordRotation[N: static[int]](amount: int,
    seed: var uint64): int {.role: {math}.} =
  ## amount/seed: candidate word-position symmetry and sample seed.
  var
    X, A, B: array[N, uint32]
    trial: int = 0
  trial = 0
  while trial < symmetryTrials:
    fillState(X, seed)
    A = rotateWords(X, amount)
    B = X
    permuteFull(A)
    permuteFull(B)
    B = rotateWords(B, amount)
    if A == B:
      result = result + 1
    trial = trial + 1

proc searchRotationalSymmetries[N: static[int]](R: var AdvancedSecurityResult,
    seedValue: uint64) {.role: {orchestrator}.} =
  ## R: result accumulator. seedValue: rotational-search seed.
  const
    bitAmounts: array[4, int] = [1, 8, 16, 31]
    wordAmounts: array[3, int] = [1, 4, N div 2]
  var
    seed: uint64 = seedValue
    i: int = 0
  i = 0
  while i < bitAmounts.len:
    R.symmetryMatches = R.symmetryMatches +
      testBitRotation[N](bitAmounts[i], seed)
    R.symmetryTests = R.symmetryTests + symmetryTrials
    i = i + 1
  i = 0
  while i < wordAmounts.len:
    R.symmetryMatches = R.symmetryMatches +
      testWordRotation[N](wordAmounts[i], seed)
    R.symmetryTests = R.symmetryTests + symmetryTrials
    i = i + 1

proc testSlideWindow[N: static[int]](rounds: int,
    seed: var uint64): int {.role: {math}.} =
  ## rounds/seed: full-permutation commutation with a round-prefix transform.
  var
    X, A, B: array[N, uint32]
    trial: int = 0
  trial = 0
  while trial < symmetryTrials:
    fillState(X, seed)
    A = X
    permuteRounds(A, rounds)
    B = A
    permuteFull(B)
    permuteFull(X)
    permuteRounds(X, rounds)
    if B == X:
      result = result + 1
    trial = trial + 1

proc searchSlideRelations[N: static[int]](R: var AdvancedSecurityResult,
    seedValue: uint64) {.role: {orchestrator}.} =
  ## R: result accumulator. seedValue: slide-search seed.
  const
    windows: array[3, int] = [1, 2, 4]
  var
    seed: uint64 = seedValue
    i: int = 0
  i = 0
  while i < windows.len:
    R.slideMatches = R.slideMatches + testSlideWindow[N](windows[i], seed)
    R.slideTests = R.slideTests + symmetryTrials
    i = i + 1

proc parityMasked[N: static[int]](S, M: array[N, uint32]): uint8
    {.inline, role: {math}.} =
  ## S/M: state and linear mask whose parity is returned.
  var
    i: int = 0
    p: uint8 = 0'u8
  i = 0
  while i < N:
    p = p xor uint8(countSetBits(S[i] and M[i]) and 1)
    i = i + 1
  result = p

proc updateLinearCounts[N: static[int]](X, Y: array[N, uint32],
    InputMasks, OutputMasks: seq[array[N, uint32]],
    Counts: var seq[int]) {.role: {math}.} =
  ## X/Y: input/output. Masks/Counts: sampled linear approximations.
  var
    i: int = 0
    bit: uint8 = 0'u8
  i = 0
  while i < Counts.len:
    bit = parityMasked(X, InputMasks[i]) xor parityMasked(Y, OutputMasks[i])
    if bit == 0'u8:
      Counts[i] = Counts[i] + 1
    i = i + 1

proc searchLinearCorrelation[N: static[int]](seedValue: uint64): float64
    {.role: {orchestrator}.} =
  ## seedValue: deterministic mask and sample seed.
  var
    InputMasks, OutputMasks: seq[array[N, uint32]] = @[]
    Counts: seq[int] = @[]
    X, Y: array[N, uint32]
    seed: uint64 = seedValue
    i: int = 0
    correlation: float64 = 0.0
  InputMasks.setLen(linearMasks)
  OutputMasks.setLen(linearMasks)
  Counts.setLen(linearMasks)
  i = 0
  while i < linearMasks:
    fillState(InputMasks[i], seed)
    fillState(OutputMasks[i], seed)
    i = i + 1
  i = 0
  while i < linearSamples:
    fillState(X, seed)
    Y = X
    permuteFull(Y)
    updateLinearCounts(X, Y, InputMasks, OutputMasks, Counts)
    i = i + 1
  i = 0
  while i < Counts.len:
    correlation = abs((2.0 * float64(Counts[i]) - float64(linearSamples)) /
      float64(linearSamples))
    result = max(result, correlation)
    i = i + 1

proc differenceFingerprint[N: static[int]](A, B: array[N, uint32]): uint64
    {.inline, role: {helper}.} =
  ## A/B: paired outputs folded into a differential identity.
  var
    i: int = 0
  result = 0xcbf29ce484222325'u64
  i = 0
  while i < N:
    result = (result xor uint64(A[i] xor B[i])) * 0x100000001b3'u64
    i = i + 1

proc trailCandidate[N: static[int]](inputBit: int, seed: var uint64): tuple[
    uniqueCount: int, maxProbability: float64] {.role: {math}.} =
  ## inputBit/seed: fixed input difference and independent base states.
  var
    H: HashSet[uint64]
    Counts: array[256, int]
    X, Y, A, B: array[N, uint32]
    sample, word, shift, bucket, maximum: int = 0
  word = inputBit div 32
  shift = inputBit mod 32
  sample = 0
  while sample < differentialTrailSamples:
    fillState(X, seed)
    Y = X
    Y[word] = Y[word] xor (1'u32 shl shift)
    A = X
    B = Y
    permuteFull(A)
    permuteFull(B)
    H.incl(differenceFingerprint(A, B))
    bucket = int((A[0] xor B[0]) and 0xff'u32)
    Counts[bucket] = Counts[bucket] + 1
    sample = sample + 1
  sample = 0
  while sample < Counts.len:
    maximum = max(maximum, Counts[sample])
    sample = sample + 1
  result.uniqueCount = H.len
  result.maxProbability = float64(maximum) / float64(differentialTrailSamples)

proc searchDifferentialTrails[N: static[int]](R: var AdvancedSecurityResult,
    seedValue: uint64) {.role: {orchestrator}.} =
  ## R: result accumulator. seedValue: difference and sample seed.
  var
    seed: uint64 = seedValue
    i, inputBit: int = 0
    candidate: tuple[uniqueCount: int, maxProbability: float64]
  R.minimumDifferenceFingerprints = differentialTrailSamples
  i = 0
  while i < differentialTrailInputs:
    inputBit = int(nextSplitMix(seed) mod uint64(N * 32))
    candidate = trailCandidate[N](inputBit, seed)
    R.minimumDifferenceFingerprints = min(R.minimumDifferenceFingerprints,
      candidate.uniqueCount)
    R.maxProjectedDifferentialProbability = max(
      R.maxProjectedDifferentialProbability, candidate.maxProbability)
    i = i + 1

proc applyCubeMask[N: static[int]](X: var array[N, uint32],
    Directions: openArray[int], mask: int) {.inline, role: {math}.} =
  ## X: cube point. Directions/mask: selected derivative directions.
  var
    i, bit, word, shift: int = 0
  i = 0
  while i < Directions.len:
    if ((mask shr i) and 1) != 0:
      bit = Directions[i]
      word = bit div 32
      shift = bit mod 32
      X[word] = X[word] xor (1'u32 shl shift)
    i = i + 1

proc xorStateInto[N: static[int]](A: var array[N, uint32],
    B: array[N, uint32]) {.inline, role: {math}.} =
  ## A: derivative accumulator. B: next cube output.
  var
    i: int = 0
  i = 0
  while i < N:
    A[i] = A[i] xor B[i]
    i = i + 1

proc derivativeNonzero[N: static[int]](degree: int,
    seed: var uint64): bool {.role: {math}.} =
  ## degree/seed: derivative order and deterministic cube selection.
  var
    base, X, Y, accumulator: array[N, uint32]
    Directions: seq[int] = @[]
    mask, i, start, step: int = 0
    d: uint32 = 0'u32
  fillState(base, seed)
  Directions.setLen(degree)
  start = int(nextSplitMix(seed) mod uint64(N * 32))
  step = int(nextSplitMix(seed) mod uint64(N * 32)) or 1
  i = 0
  while i < degree:
    Directions[i] = (start + i * step) mod (N * 32)
    i = i + 1
  mask = 0
  while mask < (1 shl degree):
    X = base
    applyCubeMask(X, Directions, mask)
    Y = X
    permuteFull(Y)
    xorStateInto(accumulator, Y)
    mask = mask + 1
  i = 0
  while i < N:
    d = d or accumulator[i]
    i = i + 1
  result = d != 0'u32

proc algebraicDegreeLowerBound[N: static[int]](seedValue: uint64): int
    {.role: {orchestrator}.} =
  ## seedValue: deterministic higher-order derivative seed.
  var
    seed: uint64 = seedValue
    degree: int = 1
  degree = 1
  while degree <= algebraicDegreeTarget:
    if derivativeNonzero[N](degree, seed):
      result = degree
    degree = degree + 1

proc wordsUniform[N: static[int]](S: array[N, uint32]): bool
    {.inline, role: {parser}.} =
  var
    i: int = 1
    d: uint32 = 0'u32
  i = 1
  while i < N:
    d = d or (S[0] xor S[i])
    i = i + 1
  result = d == 0'u32

proc halvesEqual[N: static[int]](S: array[N, uint32]): bool
    {.inline, role: {parser}.} =
  var
    i: int = 0
    d: uint32 = 0'u32
  i = 0
  while i < N div 2:
    d = d or (S[i] xor S[i + N div 2])
    i = i + 1
  result = d == 0'u32

proc lanesUniform[N: static[int]](S: array[N, uint32]): bool
    {.inline, role: {parser}.} =
  var
    i: int = 0
    d: uint32 = 0'u32
  i = 0
  while i < N:
    d = d or (S[i] xor S[i + 1]) or (S[i] xor S[i + 2]) or
      (S[i] xor S[i + 3])
    i = i + 4
  result = d == 0'u32

proc structuredTrial[N: static[int]](kind: int, seed: var uint64): bool
    {.role: {math}.} =
  ## kind/seed: structured candidate subspace and deterministic member.
  var
    S: array[N, uint32]
    i: int = 0
    value: uint32 = 0'u32
  case kind
  of 0:
    value = uint32(nextSplitMix(seed))
    i = 0
    while i < N:
      S[i] = value
      i = i + 1
  of 1:
    i = 0
    while i < N div 2:
      S[i] = uint32(nextSplitMix(seed))
      S[i + N div 2] = S[i]
      i = i + 1
  else:
    i = 0
    while i < N:
      value = uint32(nextSplitMix(seed))
      S[i] = value
      S[i + 1] = value
      S[i + 2] = value
      S[i + 3] = value
      i = i + 4
  permuteFull(S)
  case kind
  of 0: result = wordsUniform(S)
  of 1: result = halvesEqual(S)
  else: result = lanesUniform(S)

proc searchStructuredKind[N: static[int]](R: var AdvancedSecurityResult,
    kind: int, seed: var uint64) {.role: {orchestrator}.}

proc searchStructuredInvariants[N: static[int]](R: var AdvancedSecurityResult,
    seedValue: uint64) {.role: {orchestrator}.} =
  ## R: result accumulator. seedValue: structured-subspace sample seed.
  var
    seed: uint64 = seedValue
    kind: int = 0
  kind = 0
  while kind < 3:
    searchStructuredKind[N](R, kind, seed)
    kind = kind + 1

proc searchStructuredKind[N: static[int]](R: var AdvancedSecurityResult,
    kind: int, seed: var uint64) {.role: {orchestrator}.} =
  ## R: result accumulator. kind/seed: one structured-subspace family.
  var
    trial: int = 0
  trial = 0
  while trial < symmetryTrials:
    if structuredTrial[N](kind, seed):
      R.structuredInvariantMatches = R.structuredInvariantMatches + 1
    R.structuredInvariantTests = R.structuredInvariantTests + 1
    trial = trial + 1

proc analyzeAdvanced*[N: static[int]](seedValue: uint64): AdvancedSecurityResult
    {.role: {metaOrchestrator}.} =
  ## seedValue: deterministic domain for all bounded searches.
  var
    ranks: tuple[linear, affine: int]
  result.bits = N * 32
  ranks = invariantRanks[N](seedValue xor 0x01'u64)
  result.linearRank = ranks.linear
  result.affineRank = ranks.affine
  searchDeterministicRelations[N](result, seedValue xor 0x02'u64)
  searchRotationalSymmetries[N](result, seedValue xor 0x03'u64)
  searchSlideRelations[N](result, seedValue xor 0x04'u64)
  result.maxLinearCorrelation = searchLinearCorrelation[N](seedValue xor 0x05'u64)
  searchDifferentialTrails[N](result, seedValue xor 0x08'u64)
  result.algebraicDegreeLowerBound = algebraicDegreeLowerBound[N](seedValue xor 0x06'u64)
  searchStructuredInvariants[N](result, seedValue xor 0x07'u64)
