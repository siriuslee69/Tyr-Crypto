## ---------------------------------------------------------------------
## NuGimli Security Checks <- diffusion and statistical measurements
## ---------------------------------------------------------------------

import std/[algorithm, bitops, sets, strutils]
import metaPragmas
import otter_repo_evaluation
import ./types
import ./primitives

const
  avalancheTrials* = 4
  differentialSamples* = 8_192
  differentialBuckets = 256
  statisticalBytes* = 125_000
  weakPathSamples* = 256

type
  AvalancheMemory = object
    outputCounts: seq[int]
    totalDistance: int64
    minDistance: int
    maxDistance: int
    minChangedWords: int
    maxChangedWords: int
    samples: int
    minInputBit: int
    partialCounts: seq[int]
    zeroCounts: seq[int]
    zeroDifferences: int

proc initAvalancheMemory(bits, words: int): AvalancheMemory
    {.role: {helper}.} =
  ## bits/words: output dimensions for one profile.
  result.outputCounts.setLen(bits)
  result.partialCounts.setLen(bits)
  result.zeroCounts.setLen(bits)
  result.minDistance = bits
  result.minChangedWords = words

proc recordOutputWord(M: var AvalancheMemory, d: uint32,
    base: int) {.inline, role: {math}.} =
  ## M: avalanche accumulator. d: output difference word. base: bit offset.
  var
    bit: int = 0
  bit = 0
  while bit < 32:
    M.outputCounts[base + bit] = M.outputCounts[base + bit] +
      int((d shr bit) and 1'u32)
    bit = bit + 1

proc recordDifference[N: static[int]](M: var AvalancheMemory,
    A, B: array[N, uint32], inputBit: int) {.role: {math}.} =
  ## M: avalanche accumulator. A/B: paired outputs. inputBit: flipped bit.
  var
    i, distance, words: int = 0
    d: uint32 = 0'u32
  i = 0
  while i < N:
    d = A[i] xor B[i]
    distance = distance + countSetBits(d)
    if d != 0'u32:
      words = words + 1
    recordOutputWord(M, d, i * 32)
    i = i + 1
  M.totalDistance = M.totalDistance + int64(distance)
  if distance < M.minDistance:
    M.minInputBit = inputBit
  M.minDistance = min(M.minDistance, distance)
  M.maxDistance = max(M.maxDistance, distance)
  M.minChangedWords = min(M.minChangedWords, words)
  M.maxChangedWords = max(M.maxChangedWords, words)
  if words < N:
    M.partialCounts[inputBit] = M.partialCounts[inputBit] + 1
  if distance == 0:
    M.zeroCounts[inputBit] = M.zeroCounts[inputBit] + 1
    M.zeroDifferences = M.zeroDifferences + 1
  M.samples = M.samples + 1

proc runAvalancheTrial[N: static[int]](M: var AvalancheMemory,
    X, K: array[N, uint32], keyMode: bool)
    {.role: {math}.} =
  ## M: accumulator. X/K: base cipher case. keyMode: flip key or plaintext.
  var
    base, changed: array[N, uint32]
    TX, TK: array[N, uint32]
    bit, word, shift: int = 0
  base = encryptFull(X, K)
  bit = 0
  while bit < N * 32:
    TX = X
    TK = K
    word = bit div 32
    shift = bit mod 32
    if keyMode:
      TK[word] = TK[word] xor (1'u32 shl shift)
    else:
      TX[word] = TX[word] xor (1'u32 shl shift)
    changed = encryptFull(TX, TK)
    recordDifference(M, base, changed, bit)
    bit = bit + 1

proc finishAvalanche(M: AvalancheMemory, bits: int): AvalancheResult
    {.role: {truthBuilder}.} =
  ## M: completed accumulator. bits: profile width.
  var
    i: int = 0
    ratio, bias: float64 = 0.0
  result.samples = M.samples
  result.minChangedWords = M.minChangedWords
  result.maxChangedWords = M.maxChangedWords
  result.minInputBit = M.minInputBit
  result.zeroDifferences = M.zeroDifferences
  if M.samples <= 0:
    return
  result.meanRatio = float64(M.totalDistance) /
    (float64(M.samples) * float64(bits))
  result.minRatio = float64(M.minDistance) / float64(bits)
  result.maxRatio = float64(M.maxDistance) / float64(bits)
  i = 0
  while i < M.outputCounts.len:
    ratio = float64(M.outputCounts[i]) / float64(M.samples)
    bias = abs(ratio - 0.5)
    result.maxOutputBias = max(result.maxOutputBias, bias)
    if M.partialCounts[i] > result.maxPartialTrials:
      result.maxPartialTrials = M.partialCounts[i]
      result.partialInputBit = i
    if M.zeroCounts[i] > result.maxZeroTrials:
      result.maxZeroTrials = M.zeroCounts[i]
      result.zeroInputBit = i
    i = i + 1

proc evaluateAvalanche*[N: static[int]](keyMode: bool,
    seedValue: uint64): AvalancheResult {.role: {orchestrator}.} =
  ## keyMode: plaintext or key experiment. seedValue: reproducible input seed.
  var
    M: AvalancheMemory = initAvalancheMemory(N * 32, N)
    X, K: array[N, uint32]
    seed: uint64 = seedValue
    trial: int = 0
  trial = 0
  while trial < avalancheTrials:
    fillState(X, seed)
    fillState(K, seed)
    runAvalancheTrial(M, X, K, keyMode)
    trial = trial + 1
  result = finishAvalanche(M, N * 32)

proc evaluateDifferential*[N: static[int]](seedValue: uint64): DifferentialResult
    {.role: {orchestrator}.} =
  ## seedValue: fixed one-bit differential input seed.
  var
    Counts: array[differentialBuckets, int]
    X, Y, K, A, B: array[N, uint32]
    seed: uint64 = seedValue
    i, bucket, distance, words: int = 0
    totalDistance: int64 = 0
    expected, delta: float64 = 0.0
  fillState(K, seed)
  result.minChangedWords = N
  i = 0
  while i < differentialSamples:
    fillState(X, seed)
    Y = X
    Y[0] = Y[0] xor 1'u32
    A = encryptFull(X, K)
    B = encryptFull(Y, K)
    bucket = int((A[0] xor B[0]) and uint32(differentialBuckets - 1))
    Counts[bucket] = Counts[bucket] + 1
    distance = hammingDistance(A, B)
    words = changedWords(A, B)
    totalDistance = totalDistance + int64(distance)
    result.minChangedWords = min(result.minChangedWords, words)
    i = i + 1
  expected = float64(differentialSamples) / float64(differentialBuckets)
  i = 0
  while i < Counts.len:
    delta = float64(Counts[i]) - expected
    result.chiSquare = result.chiSquare + delta * delta / expected
    result.maxBucket = max(result.maxBucket, Counts[i])
    i = i + 1
  result.pValue = regularizedGammaQ(float64(differentialBuckets - 1) / 2.0,
    result.chiSquare / 2.0)
  result.expectedBucket = expected
  result.meanRatio = float64(totalDistance) /
    (float64(differentialSamples) * float64(N * 32))
  result.samples = differentialSamples

proc differenceFingerprint[N: static[int]](A, B: array[N, uint32]): uint64
    {.inline, role: {helper}.} =
  ## A/B: paired outputs folded into a test-only difference fingerprint.
  var
    i: int = 0
  result = 0xcbf29ce484222325'u64
  i = 0
  while i < N:
    result = (result xor uint64(A[i] xor B[i])) * 0x100000001b3'u64
    i = i + 1

proc differenceText[N: static[int]](A, B: array[N, uint32]): string
    {.role: {helper}.} =
  ## A/B: paired outputs rendered as active word and xor-mask pairs.
  var
    L: seq[string] = @[]
    i: int = 0
    d: uint32 = 0'u32
  i = 0
  while i < N:
    d = A[i] xor B[i]
    if d != 0'u32:
      L.add("w" & $i & ":0x" & toHex(d, 8))
    i = i + 1
  if L.len == 0:
    result = "zero"
  else:
    result = L.join(",")

proc evaluateWeakPath*[N: static[int]](keyMode: bool,
    inputBit: int, seedValue: uint64): WeakPathResult {.role: {orchestrator}.} =
  ## keyMode/inputBit: candidate path. seedValue: independent validation seed.
  var
    H: HashSet[uint64]
    X, K, TX, TK, A, B: array[N, uint32]
    seed: uint64 = seedValue
    i, word, shift, distance, words: int = 0
  result.inputBit = inputBit
  result.samples = weakPathSamples
  result.minDistance = N * 32
  result.minChangedWords = N
  word = inputBit div 32
  shift = inputBit mod 32
  i = 0
  while i < weakPathSamples:
    fillState(X, seed)
    fillState(K, seed)
    TX = X
    TK = K
    if keyMode:
      TK[word] = TK[word] xor (1'u32 shl shift)
    else:
      TX[word] = TX[word] xor (1'u32 shl shift)
    A = encryptFull(X, K)
    B = encryptFull(TX, TK)
    if i == 0:
      result.firstDifference = differenceText(A, B)
    distance = hammingDistance(A, B)
    words = changedWords(A, B)
    H.incl(differenceFingerprint(A, B))
    result.minDistance = min(result.minDistance, distance)
    result.maxDistance = max(result.maxDistance, distance)
    result.minChangedWords = min(result.minChangedWords, words)
    result.maxChangedWords = max(result.maxChangedWords, words)
    if distance == 0:
      result.zeroDifferences = result.zeroDifferences + 1
    i = i + 1
  result.distinctDifferences = H.len

proc rootOf(P: var seq[int], v: int): int {.inline, role: {helper}.} =
  ## P: disjoint-set parents. v: node whose root is resolved.
  var
    r, n, parent: int = 0
  r = v
  while P[r] != r:
    r = P[r]
  n = v
  while P[n] != n:
    parent = P[n]
    P[n] = r
    n = parent
  result = r

proc joinComponents(P: var seq[int], a, b: int) {.inline, role: {helper}.} =
  ## P: disjoint-set parents. a/b: state words connected by influence.
  var
    ra, rb: int = 0
  ra = rootOf(P, a)
  rb = rootOf(P, b)
  if ra != rb:
    P[rb] = ra

proc joinChangedOutputs[N: static[int]](P: var seq[int], inputWord: int,
    A, B: array[N, uint32]) {.role: {truthBuilder}.} =
  ## P: component state. inputWord: source word. A/B: paired outputs.
  var
    i: int = 0
  i = 0
  while i < N:
    if A[i] != B[i]:
      joinComponents(P, inputWord, i)
    i = i + 1

proc finishComponents(P: var seq[int]): ComponentResult
    {.role: {truthBuilder}.} =
  ## P: completed disjoint-set parents.
  var
    Counts: seq[int] = @[]
    i, root: int = 0
  Counts.setLen(P.len)
  i = 0
  while i < P.len:
    root = rootOf(P, i)
    Counts[root] = Counts[root] + 1
    i = i + 1
  i = 0
  while i < Counts.len:
    if Counts[i] > 0:
      result.sizes.add(Counts[i])
    i = i + 1
  result.sizes.sort(SortOrder.Descending)
  result.count = result.sizes.len

proc evaluateComponents*[N: static[int]](seedValue: uint64): ComponentResult
    {.role: {orchestrator}.} =
  ## seedValue: word-influence graph sample seed.
  var
    P: seq[int] = @[]
    X, K, Y, A, B: array[N, uint32]
    seed: uint64 = seedValue
    bit, word, shift: int = 0
  P.setLen(N)
  bit = 0
  while bit < N:
    P[bit] = bit
    bit = bit + 1
  fillState(X, seed)
  fillState(K, seed)
  A = encryptFull(X, K)
  bit = 0
  while bit < N * 32:
    Y = X
    word = bit div 32
    shift = bit mod 32
    Y[word] = Y[word] xor (1'u32 shl shift)
    B = encryptFull(Y, K)
    joinChangedOutputs(P, word, A, B)
    bit = bit + 1
  result = finishComponents(P)

proc buildCipherStream[N: static[int]](seedValue: uint64): seq[uint8]
    {.role: {dataWriter}.} =
  ## seedValue: fixed-key counter-stream seed.
  var
    X, K, C: array[N, uint32]
    seed: uint64 = seedValue
    counter: uint64 = 0'u64
  result = newSeqOfCap[uint8](statisticalBytes)
  fillState(K, seed)
  while result.len < statisticalBytes:
    setCounterState(X, counter)
    C = encryptFull(X, K)
    appendStateBytes(result, C, statisticalBytes)
    counter = counter + 1'u64

proc evaluateStatistics*[N: static[int]](seedValue: uint64): StatisticalResult
    {.role: {orchestrator}.} =
  ## seedValue: fixed-key counter-stream statistical seed.
  var
    B: seq[uint8] = @[]
    P: NistParams
    R: seq[NistResult] = @[]
    i: int = 0
  B = buildCipherStream[N](seedValue)
  P = nistParamsForBits(B.len * 8)
  R = nistCoreSuiteFromBytes(B, P)
  result.total = R.len
  result.minPValue = 1.0
  i = 0
  while i < R.len:
    result.minPValue = min(result.minPValue, R[i].pValue)
    if R[i].passed:
      result.passed = result.passed + 1
    else:
      result.failedNames.add(R[i].name)
    i = i + 1

proc evaluateDiffusionPoint[N: static[int]](rounds: int,
    seedValue: uint64): DiffusionPoint {.role: {orchestrator}.} =
  ## rounds/seedValue: reduced permutation point and deterministic state seed.
  const
    positions: array[3, int] = [0, (N * 32) div 2, N * 32 - 1]
  var
    X, A, B: array[N, uint32]
    seed: uint64 = seedValue
    i, word, shift, distance, words: int = 0
    total: int = 0
  fillState(X, seed)
  result.rounds = rounds
  result.minChangedWords = N
  i = 0
  while i < positions.len:
    A = X
    B = X
    word = positions[i] div 32
    shift = positions[i] mod 32
    B[word] = B[word] xor (1'u32 shl shift)
    permuteRounds(A, rounds)
    permuteRounds(B, rounds)
    distance = hammingDistance(A, B)
    words = changedWords(A, B)
    total = total + distance
    result.minChangedWords = min(result.minChangedWords, words)
    i = i + 1
  result.meanRatio = float64(total) / float64(positions.len * N * 32)

proc evaluateDiffusion*[N: static[int]](seedValue: uint64): seq[DiffusionPoint]
    {.role: {orchestrator}.} =
  ## seedValue: reduced-round diffusion input seed.
  const
    earlyRounds: array[5, int] = [1, 2, 4, 8, 12]
  var
    i: int = 0
    rounds: int = 0
  i = 0
  while i < earlyRounds.len:
    result.add(evaluateDiffusionPoint[N](earlyRounds[i], seedValue))
    i = i + 1
  rounds = fullRounds[N]()
  result.add(evaluateDiffusionPoint[N](rounds, seedValue))
