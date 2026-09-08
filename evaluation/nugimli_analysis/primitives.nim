## ----------------------------------------------------------------------
## Cascade Analysis Primitives <- deterministic inputs and profile calls
## ----------------------------------------------------------------------

import std/bitops
import tyrPragmas
import ../../src/tyr/ciphers/nugimli/types
import ../../src/tyr/ciphers/nugimli/domain
import ../../src/tyr/ciphers/nugimli/cascade
import ../../src/tyr/ciphers/nugimli/reference
import ../../src/tyr/ciphers/nugimli/core

proc fullRounds*[N: static[int]](): int {.inline, role: {parser}.} =
  ## N: state width in 32-bit words.
  when N == 16: result = nugimli512Rounds
  elif N == 32: result = nugimli1024Rounds
  elif N == 64: result = nugimli2048Rounds
  else: raise newException(ValueError, "unsupported Cascade analysis width")

proc nextSplitMix*(S: var uint64): uint64 {.inline, role: {math}.} =
  ## S: deterministic SplitMix64 state.
  var
    z: uint64 = 0'u64
  S = S + 0x9e3779b97f4a7c15'u64
  z = S
  z = (z xor (z shr 30)) * 0xbf58476d1ce4e5b9'u64
  z = (z xor (z shr 27)) * 0x94d049bb133111eb'u64
  result = z xor (z shr 31)

proc fillState*[N: static[int]](S: var array[N, uint32],
    seed: var uint64) {.role: {helper}.} =
  ## S: state to fill. seed: deterministic generator state.
  var
    i: int = 0
    z: uint64 = 0'u64
  i = 0
  while i < N:
    z = nextSplitMix(seed)
    S[i] = uint32(z xor (z shr 32))
    i = i + 1

proc xorState*[N: static[int]](S: var array[N, uint32],
    K: array[N, uint32]) {.inline, role: {math}.} =
  ## S/K: same-width state and xor operand.
  var
    i: int = 0
  i = 0
  while i < N:
    S[i] = S[i] xor K[i]
    i = i + 1

proc permuteFull*[N: static[int]](S: var array[N, uint32],
    optimized: static[bool] = true) {.role: {math}.} =
  ## S: Cascade state. optimized: SIMD or portable box path.
  when N == 16: cascadePermuteCore(S, nugimli512Rounds, optimized)
  elif N == 32: cascadePermuteCore(S, nugimli1024Rounds, optimized)
  else: cascadePermuteCore(S, nugimli2048Rounds, optimized)

proc invertFull*[N: static[int]](S: var array[N, uint32],
    optimized: static[bool] = true) {.role: {math}.} =
  ## S: Cascade state. optimized: SIMD or portable inverse box path.
  when N == 16: cascadeInvertCore(S, nugimli512Rounds, optimized)
  elif N == 32: cascadeInvertCore(S, nugimli1024Rounds, optimized)
  else: cascadeInvertCore(S, nugimli2048Rounds, optimized)

proc encryptFull*[N: static[int]](X, K: array[N, uint32]): array[N, uint32]
    {.role: {encryptor}.} =
  ## X/K: same-width Cascade plaintext and key.
  result = X
  xorState(result, K)
  permuteFull(result)
  xorState(result, K)

proc decryptFull*[N: static[int]](C, K: array[N, uint32]): array[N, uint32]
    {.role: {decryptor}.} =
  ## C/K: same-width Cascade ciphertext and key.
  result = C
  xorState(result, K)
  invertFull(result)
  xorState(result, K)

proc permuteRounds*[N: static[int]](S: var array[N, uint32],
    rounds: int) {.role: {math}.} =
  ## S/rounds: Cascade state and prefix length from the full schedule.
  cascadePermuteWindowCore(S, fullRounds[N](), rounds)

proc hammingDistance*[N: static[int]](A, B: array[N, uint32]): int
    {.inline, role: {math}.} =
  ## A/B: states whose differing bits are counted.
  var
    i: int = 0
  i = 0
  while i < N:
    result = result + countSetBits(A[i] xor B[i])
    i = i + 1

proc changedWords*[N: static[int]](A, B: array[N, uint32]): int
    {.inline, role: {math}.} =
  ## A/B: states whose active 32-bit output words are counted.
  var
    i: int = 0
  i = 0
  while i < N:
    if A[i] != B[i]: result = result + 1
    i = i + 1

proc setCounterState*[N: static[int]](S: var array[N, uint32],
    counter: uint64) {.role: {helper}.} =
  ## S: zeroed counter block. counter: block sequence number.
  var
    i: int = 0
  i = 0
  while i < N:
    S[i] = 0'u32
    i = i + 1
  S[0] = uint32(counter)
  S[1] = uint32(counter shr 32)

proc appendWordBytes(B: var seq[uint8], w: uint32,
    limit: int) {.inline, role: {dataWriter}.} =
  ## B: output stream. w: little-endian word. limit: byte cap.
  var
    i: int = 0
  i = 0
  while i < 4 and B.len < limit:
    B.add(uint8(w shr (i * 8)))
    i = i + 1

proc appendStateBytes*[N: static[int]](B: var seq[uint8],
    S: array[N, uint32], limit: int) {.role: {dataWriter}.} =
  ## B: output stream. S: state serialized little-endian. limit: byte cap.
  var
    i: int = 0
  i = 0
  while i < N and B.len < limit:
    appendWordBytes(B, S[i], limit)
    i = i + 1
