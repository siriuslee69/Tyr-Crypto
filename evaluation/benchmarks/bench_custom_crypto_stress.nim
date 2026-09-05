## ============================================================
## | Tyr AVX2 stress benchmark <- threaded custom primitives   |
## ============================================================
##
## Each worker owns its inputs, SIMD state, output buffers, and counters.
## Workers are joined before the main thread aggregates their results.

import std/[os, strutils, monotimes, cpuinfo]

import ../../src/tyr/ciphers/chacha/xchacha20_simd
import ../../src/tyr/ciphers/aes_ctr
import ../../src/tyr/ciphers/gimli
import ../../src/tyr/hashes/blake3

const
  defaultSeconds = 120
  stressBytes = 4096
  nanosecondsPerSecond = 1_000_000_000'i64

when defined(avx2):
  const avx2Compiled = true
else:
  const avx2Compiled = false

type
  WorkerState = object
    workerId: int
    stopTicks: int64
    xchachaKey: array[32, byte]
    xchachaNonce: array[24, byte]
    aesNonce: array[16, byte]
    aesInput: array[stressBytes, byte]
    blakeCvs: array[8, Blake3Cv]
    blakeBlocks: array[8, Blake3Block]
    gimliState: array[8, Gimli_Block]
    operations: uint64
    bytesProcessed: uint64
    checksum: uint64

proc fillBytes(A: var openArray[byte], start: int) =
  ## Fill one worker-owned byte array with deterministic input data.
  var
    i: int = 0
  while i < A.len:
    A[i] = byte((start + i) and 0xff)
    i = i + 1

proc initWorker(S: var WorkerState, workerId: int, stopTicks: int64) =
  ## Prepare all state without sharing mutable buffers between workers.
  var
    i: int = 0
    j: int = 0
  S.workerId = workerId
  S.stopTicks = stopTicks
  fillBytes(S.xchachaKey, 0x11 + workerId * 7)
  fillBytes(S.xchachaNonce, 0x31 + workerId * 7)
  fillBytes(S.aesNonce, 0x51 + workerId * 7)
  fillBytes(S.aesInput, 0x71 + workerId * 7)
  i = 0
  while i < S.blakeCvs.len:
    j = 0
    while j < S.blakeCvs[i].len:
      S.blakeCvs[i][j] = 0x6a09e667'u32 + uint32(workerId + i + j)
      j = j + 1
    i = i + 1
  i = 0
  while i < S.blakeBlocks.len:
    j = 0
    while j < S.blakeBlocks[i].len:
      S.blakeBlocks[i][j] = 0x01020304'u32 + uint32(workerId + i + j)
      j = j + 1
    i = i + 1
  i = 0
  while i < S.gimliState.len:
    j = 0
    while j < S.gimliState[i].len:
      S.gimliState[i][j] = 0x10203040'u32 + uint32(workerId + i + j)
      j = j + 1
    i = i + 1

proc mixStream(A: openArray[byte], checksum: var uint64) {.inline.} =
  ## Keep returned stream bytes observable without synchronizing workers.
  checksum = checksum xor uint64(A[0])
  checksum = checksum xor (uint64(A[A.len shr 1]) shl 8)
  checksum = checksum xor (uint64(A[A.len - 1]) shl 16)

proc mixBlake(A: array[8, Blake3Out], checksum: var uint64) {.inline.} =
  ## Keep several AVX8 lanes observable without a shared sink.
  checksum = checksum xor uint64(A[0][0])
  checksum = checksum xor (uint64(A[3][4]) shl 7)
  checksum = checksum xor (uint64(A[7][15]) shl 13)

proc mixGimli(A: array[8, Gimli_Block], checksum: var uint64) {.inline.} =
  ## Keep several AVX8x lanes observable without a shared sink.
  checksum = checksum xor uint64(A[0][0])
  checksum = checksum xor (uint64(A[3][5]) shl 9)
  checksum = checksum xor (uint64(A[7][11]) shl 17)

proc worker(S: ptr WorkerState) {.thread.} =
  var
    xchachaOut: seq[byte] = @[]
    aesOut: seq[byte] = @[]
    blakeOut: array[8, Blake3Out]
    nowTicks: int64 = 0
  when defined(avx2):
    while true:
      nowTicks = getMonoTime().ticks
      if nowTicks >= S.stopTicks:
        break
      xchachaOut = xchacha20StreamSimd(S.xchachaKey, S.xchachaNonce,
        stressBytes, 0'u32, xcbAvx2)
      mixStream(xchachaOut, S.checksum)
      aesOut = aesCtrXor(S.xchachaKey, S.aesNonce, S.aesInput, acbAvx2)
      mixStream(aesOut, S.checksum)
      blakeOut = blake3CompressAvx8(S.blakeCvs, S.blakeBlocks,
        S.operations, 64'u32, 0'u32)
      mixBlake(blakeOut, S.checksum)
      gimliPermuteAvx8x(S.gimliState)
      mixGimli(S.gimliState, S.checksum)
      S.operations = S.operations + 4'u64
      S.bytesProcessed = S.bytesProcessed + uint64(stressBytes * 2)
  else:
    discard

proc requestedSeconds(): int =
  ## Read the optional executable argument: --seconds:N.
  var
    seconds: int = defaultSeconds
    i: int = 1
    argument: string = ""
    value: string = ""
  while i <= paramCount():
    argument = paramStr(i)
    if argument.startsWith("--seconds:"):
      value = argument[10 .. ^1]
      try:
        seconds = parseInt(value)
      except ValueError:
        quit("invalid --seconds value: " & value, 1)
    i = i + 1
  if seconds <= 0:
    quit("--seconds must be greater than zero", 1)
  result = seconds

proc formatMiBPerSecond(bytes: uint64, elapsedTicks: int64): string =
  var
    elapsedSeconds: float64 = 0.0
    rate: float64 = 0.0
  if elapsedTicks > 0:
    elapsedSeconds = float64(elapsedTicks) / float64(nanosecondsPerSecond)
    rate = float64(bytes) / 1024.0 / 1024.0 / elapsedSeconds
  result = formatFloat(rate, ffDecimal, 2)

proc main() =
  var
    seconds: int = requestedSeconds()
    threadCount: int = countProcessors()
    startTicks: int64 = 0
    stopTicks: int64 = 0
    elapsedTicks: int64 = 0
    states: seq[WorkerState]
    threads: seq[Thread[ptr WorkerState]]
    totalOperations: uint64 = 0
    totalBytes: uint64 = 0
    combinedChecksum: uint64 = 0
    i: int = 0
  if threadCount < 1:
    threadCount = 1
  when not compileOption("threads"):
    quit("this benchmark requires --threads:on", 1)
  startTicks = getMonoTime().ticks
  stopTicks = startTicks + int64(seconds) * nanosecondsPerSecond
  states.setLen(threadCount)
  threads.setLen(threadCount)
  i = 0
  while i < threadCount:
    initWorker(states[i], i, stopTicks)
    createThread(threads[i], worker, addr states[i])
    i = i + 1
  i = 0
  while i < threadCount:
    joinThread(threads[i])
    i = i + 1
  elapsedTicks = getMonoTime().ticks - startTicks
  i = 0
  while i < threadCount:
    totalOperations = totalOperations + states[i].operations
    totalBytes = totalBytes + states[i].bytesProcessed
    combinedChecksum = combinedChecksum xor states[i].checksum
    i = i + 1
  echo "CPU threads available: ", threadCount
  echo "Worker threads: ", threadCount
  echo "Requested duration (seconds): ", seconds
  echo "Operations: ", totalOperations
  echo "Bytes processed: ", totalBytes
  echo "Elapsed time (seconds): ", formatFloat(float64(elapsedTicks) /
    float64(nanosecondsPerSecond), ffDecimal, 3)
  echo "Throughput (MiB/s): ", formatMiBPerSecond(totalBytes, elapsedTicks)
  echo "AVX2 compiled in: ", avx2Compiled
  echo "Checksum: 0x", toHex(combinedChecksum, 16)

when isMainModule:
  main()
