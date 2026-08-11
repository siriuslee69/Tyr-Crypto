## ---------------------------------------------------------------------
## NuGimli Stream Metrics <- online entropy, bias, repeats, and NIST core
## ---------------------------------------------------------------------

import std/[bitops, sets]
import std/math as stdmath
import metaPragmas
import otter_repo_evaluation
import ./stream_types

const
  streamNistBytes* = 8_192
  fingerprintLimit = 100_000

type
  StreamMetricMemory* = object
    histogram: array[256, uint64]
    sampledBytes: uint64
    ones: uint64
    zeroBytes: uint64
    pairCount: uint64
    sumX, sumY, sumXX, sumYY, sumXY: float64
    previousByte: uint8
    hasPrevious: bool
    previousFingerprint: uint64
    hasPreviousFingerprint: bool
    consecutiveRepeats: uint64
    fingerprints: HashSet[uint64]
    fingerprintCollisions: uint64
    fingerprintSamples: int
    nistBytes: seq[uint8]

proc resetMetrics*(M: var StreamMetricMemory) {.role: {helper}.} =
  ## M: interval accumulator reset without retaining prior samples.
  M = default(StreamMetricMemory)
  M.nistBytes = newSeqOfCap[uint8](streamNistBytes)

proc observeByte(M: var StreamMetricMemory, b: uint8)
    {.inline, role: {math}.} =
  ## M: interval accumulator. b: next sampled stream byte.
  var
    x, y: float64 = 0.0
  M.histogram[int(b)] = M.histogram[int(b)] + 1'u64
  M.sampledBytes = M.sampledBytes + 1'u64
  M.ones = M.ones + uint64(countSetBits(b))
  if b == 0'u8:
    M.zeroBytes = M.zeroBytes + 1'u64
  if M.hasPrevious:
    x = float64(M.previousByte)
    y = float64(b)
    M.sumX = M.sumX + x
    M.sumY = M.sumY + y
    M.sumXX = M.sumXX + x * x
    M.sumYY = M.sumYY + y * y
    M.sumXY = M.sumXY + x * y
    M.pairCount = M.pairCount + 1'u64
  M.previousByte = b
  M.hasPrevious = true
  if M.nistBytes.len < streamNistBytes:
    M.nistBytes.add(b)

proc observeWord(M: var StreamMetricMemory, w: uint32)
    {.inline, role: {math}.} =
  ## M: interval accumulator. w: one little-endian output word.
  observeByte(M, uint8(w))
  observeByte(M, uint8(w shr 8))
  observeByte(M, uint8(w shr 16))
  observeByte(M, uint8(w shr 24))

proc stateFingerprint[N: static[int]](S: array[N, uint32]): uint64
    {.inline, role: {helper}.} =
  ## S: output block folded into a 64-bit repeat detector.
  var
    i: int = 0
  result = 0xcbf29ce484222325'u64
  i = 0
  while i < N:
    result = (result xor uint64(S[i])) * 0x100000001b3'u64
    i = i + 1

proc observeFingerprint(M: var StreamMetricMemory, fingerprint: uint64)
    {.inline, role: {truthBuilder}.} =
  ## M: interval accumulator. fingerprint: current output block identity.
  if M.hasPreviousFingerprint and fingerprint == M.previousFingerprint:
    M.consecutiveRepeats = M.consecutiveRepeats + 1'u64
  M.previousFingerprint = fingerprint
  M.hasPreviousFingerprint = true
  if M.fingerprintSamples < fingerprintLimit:
    if fingerprint in M.fingerprints:
      M.fingerprintCollisions = M.fingerprintCollisions + 1'u64
    else:
      M.fingerprints.incl(fingerprint)
    M.fingerprintSamples = M.fingerprintSamples + 1

proc observeState*[N: static[int]](M: var StreamMetricMemory,
    S: array[N, uint32], blockIndex: uint64) {.role: {math}.} =
  ## M: interval accumulator. S: output block. blockIndex: stage-local index.
  var
    i: int = 1
  observeWord(M, S[0])
  if (blockIndex and 63'u64) == 0'u64:
    i = 1
    while i < N:
      observeWord(M, S[i])
      i = i + 1
  observeFingerprint(M, stateFingerprint(S))

proc shannonEntropy(M: StreamMetricMemory): float64 {.role: {math}.} =
  ## M: interval histogram converted to Shannon bits per byte.
  var
    i: int = 0
    p: float64 = 0.0
  if M.sampledBytes == 0'u64:
    return
  i = 0
  while i < M.histogram.len:
    if M.histogram[i] > 0'u64:
      p = float64(M.histogram[i]) / float64(M.sampledBytes)
      result = result - p * stdmath.log2(p)
    i = i + 1

proc minimumEntropy(M: StreamMetricMemory): float64 {.role: {math}.} =
  ## M: interval histogram converted to empirical min-entropy per byte.
  var
    i: int = 0
    maximum: uint64 = 0'u64
  if M.sampledBytes == 0'u64:
    return
  i = 0
  while i < M.histogram.len:
    maximum = max(maximum, M.histogram[i])
    i = i + 1
  result = -stdmath.log2(float64(maximum) / float64(M.sampledBytes))

proc serialCorrelation(M: StreamMetricMemory): float64 {.role: {math}.} =
  ## M: interval byte pairs converted to Pearson lag-one correlation.
  var
    n, numerator, dx, dy: float64 = 0.0
  if M.pairCount < 2'u64:
    return
  n = float64(M.pairCount)
  numerator = n * M.sumXY - M.sumX * M.sumY
  dx = n * M.sumXX - M.sumX * M.sumX
  dy = n * M.sumYY - M.sumY * M.sumY
  if dx > 0.0 and dy > 0.0:
    result = numerator / stdmath.sqrt(dx * dy)

proc addNistResult(C: var StreamCheckpoint, R: openArray[NistResult])
    {.role: {truthBuilder}.} =
  ## C: checkpoint receiving statistical outcomes. R: core diagnostics.
  var
    i: int = 0
  C.nistTotal = R.len
  C.minPValue = 1.0
  i = 0
  while i < R.len:
    C.minPValue = min(C.minPValue, R[i].pValue)
    if R[i].passed:
      C.nistPassed = C.nistPassed + 1
    else:
      C.failedTestMask = C.failedTestMask or (1'u32 shl i)
    i = i + 1

proc snapshotMetrics*(M: StreamMetricMemory, C: var StreamCheckpoint,
    runNist: bool) {.role: {truthBuilder}.} =
  ## M: completed interval metrics. C: report row. runNist: run core suite.
  var
    P: NistParams
    R: seq[NistResult] = @[]
  C.sampledBytes = M.sampledBytes
  C.shannonEntropy = shannonEntropy(M)
  C.minEntropy = minimumEntropy(M)
  C.serialCorrelation = serialCorrelation(M)
  C.consecutiveRepeats = M.consecutiveRepeats
  C.fingerprintCollisions = M.fingerprintCollisions
  if M.sampledBytes > 0'u64:
    C.onesRatio = float64(M.ones) / float64(M.sampledBytes * 8'u64)
    C.zeroByteRatio = float64(M.zeroBytes) / float64(M.sampledBytes)
  if runNist and M.nistBytes.len == streamNistBytes:
    P = nistParamsForBits(M.nistBytes.len * 8)
    P.spectralMaxBits = 16_384
    P.patternSize = 8
    R = nistCoreSuiteFromBytes(M.nistBytes, P)
    addNistResult(C, R)
