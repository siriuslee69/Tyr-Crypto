## ------------------------------------------------------------------
## NuGimli Tests <- reversibility, backend parity, and block transforms
## ------------------------------------------------------------------

import std/unittest
import runePragmas
import ../../src/tyr/ciphers/nugimli/types
import ../../src/tyr/ciphers/nugimli/domain

import ../nugimli_analysis/reference
import ../../src/tyr/ciphers/nugimli/core
import ./nugimli_cascade_vectors

proc fillNuGimliState[N: static[int]](S: var array[N, uint32],
    seed: uint32) {.role: {helper}.} =
  ## S: state to fill. seed: deterministic non-secret test pattern.
  var
    i: int = 0
  i = 0
  while i < N:
    S[i] = seed xor (uint32(i + 1) * 0x9e3779b9'u32) xor
      (uint32(i * i + 17) * 0x01010101'u32)
    i = i + 1

proc xorNuGimliState[N: static[int]](S: var array[N, uint32],
    K: array[N, uint32]) {.role: {helper}.} =
  ## S: state to change. K: deterministic test xor operand.
  var
    i: int = 0
  i = 0
  while i < N:
    S[i] = S[i] xor K[i]
    i = i + 1

proc nuGimliFingerprint[N: static[int]](S: array[N, uint32]): uint64
    {.role: {helper}.} =
  ## S: complete state folded into a stable test-only FNV-1a fingerprint.
  var
    i: int = 0
  result = 0xcbf29ce484222325'u64
  i = 0
  while i < N:
    result = (result xor uint64(S[i])) * 0x100000001b3'u64
    i = i + 1

proc changedNuGimliWords[N: static[int]](A, B: array[N, uint32]): int
    {.role: {helper}.} =
  ## A/B: paired states whose active output words are counted.
  var
    i: int = 0
  i = 0
  while i < N:
    if A[i] != B[i]:
      result = result + 1
    i = i + 1

proc fillCascadeVectorInputs[N: static[int]](X, K: var array[N, uint32])
    {.role: {helper}.} =
  ## X/K: documented permutation input and keyed-cipher vector material.
  var
    i: int = 0
  i = 0
  while i < N:
    X[i] = uint32(i) * 0x01020304'u32 xor 0xa5a5a5a5'u32
    K[i] = uint32(i + 1) * 0x9e3779b9'u32 xor 0x3c6ef372'u32
    i = i + 1

template profileChecks(label: string, State: typedesc) =
  test label & " permutation inverse":
    var
      original, state: State = default(State)
    fillNuGimliState(original, 0x12345678'u32)
    state = original
    cascadePermute(state)
    check state != original
    cascadeInvert(state)
    check state == original

  test label & " keyed block transform":
    var
      X, K, C, expected, recovered: State = default(State)
    fillNuGimliState(X, 0x10203040'u32)
    fillNuGimliState(K, 0xa5a5a5a5'u32)
    C = cascadeEncrypt(X, K)
    expected = X
    xorNuGimliState(expected, K)
    cascadePermute(expected)
    xorNuGimliState(expected, K)
    check C == expected
    check C != X
    recovered = cascadeDecrypt(C, K)
    check recovered == X

template backendChecks(label: string, State: typedesc, roundCount: int) =
  test label & " optimized scalar and reference agree":
    var
      optimized, scalar, window, reference, original: State = default(State)
    fillNuGimliState(original, 0x89abcdef'u32)
    optimized = original
    scalar = original
    cascadePermute(optimized, true)
    cascadePermute(scalar, false)
    window = original
    cascadePermuteWindow(window, roundCount, roundCount, true)
    reference = original
    cascadePermuteReference(reference)
    check optimized == scalar
    check optimized == window
    check optimized == reference
    cascadeInvert(optimized, true)
    cascadeInvert(scalar, false)
    cascadeInvertReference(reference)
    check optimized == original
    check scalar == original
    check reference == original

template cascadeTrailCheck(label: string, State: typedesc, inputBit: int) =
  test label & " breaks the Gimli top-bit trail":
    var
      X, Y, K, A, B: State = default(State)
      word, shift: int = 0
    fillNuGimliState(X, 0x7357a11a'u32)
    fillNuGimliState(K, 0xc45cade5'u32)
    Y = X
    word = inputBit div 32
    shift = inputBit mod 32
    Y[word] = Y[word] xor (1'u32 shl shift)
    A = X
    B = Y
    cascadePermute(A)
    cascadePermute(B)
    check changedNuGimliWords(A, B) == A.len
    A = cascadeEncrypt(X, K)
    K[word] = K[word] xor (1'u32 shl shift)
    B = cascadeEncrypt(X, K)
    check A != B
    check changedNuGimliWords(A, B) == A.len

template relatedKeyShiftCheck(label: string, State: typedesc) =
  ## K xor P(X xor K) has a built-in relation for every difference D:
  ##   encrypt(X xor D, K xor D) == encrypt(X, K) xor D
  ## It holds by construction, so this test pins it as a known property.
  ## A related-key search that only flips key bits never sees it.
  # {.testKind: tkProperty, covers: "cascadeEncrypt".}
  test label & " key layer shifts with an equal key and block difference":
    var
      X, K, D, shiftedX, shiftedK, A, B: State = default(State)
    fillNuGimliState(X, 0x0badf00d'u32)
    fillNuGimliState(K, 0x5eed1234'u32)
    fillNuGimliState(D, 0x00c0ffee'u32)
    shiftedX = X
    shiftedK = K
    xorNuGimliState(shiftedX, D)
    xorNuGimliState(shiftedK, D)
    A = cascadeEncrypt(X, K)
    B = cascadeEncrypt(shiftedX, shiftedK)
    xorNuGimliState(A, D)
    check A == B

template vectorChecks(label: string, State: typedesc, expectedPermutation,
    expectedCiphertext: untyped) =
  test label & " complete published vectors":
    var
      X, K, P, reference, C, recovered: State = default(State)
    fillCascadeVectorInputs(X, K)
    P = X
    reference = X
    cascadePermute(P)
    cascadePermuteReference(reference)
    C = cascadeEncrypt(X, K)
    recovered = cascadeDecrypt(C, K)
    check P == expectedPermutation
    check reference == expectedPermutation
    check C == expectedCiphertext
    check recovered == X

suite "nugimli":
  test "arbitrary contiguous chunk blocks swap":
    var
      state, expected: NuGimli1024 = default(NuGimli1024)
      i: int = 0
    i = 0
    while i < state.len:
      state[i] = uint32(i)
      expected[i] = uint32(i)
      i = i + 1
    swapChunkBlocks(state, 1, 5, 2)
    i = 0
    while i < 8:
      expected[4 + i] = uint32(20 + i)
      expected[20 + i] = uint32(4 + i)
      i = i + 1
    check state == expected
    swapChunkBlocks(state, 1, 5, 2)
    i = 0
    while i < state.len:
      check state[i] == uint32(i)
      i = i + 1

  profileChecks("Cascade-512", NuGimli512)
  profileChecks("Cascade-1024", NuGimli1024)
  profileChecks("Cascade-2048", NuGimli2048)
  backendChecks("Cascade-512", NuGimli512, cascadeRounds(16))
  backendChecks("Cascade-1024", NuGimli1024, cascadeRounds(32))
  backendChecks("Cascade-2048", NuGimli2048, cascadeRounds(64))
  cascadeTrailCheck("Cascade-512", NuGimli512, 287)
  cascadeTrailCheck("Cascade-1024", NuGimli1024, 799)
  cascadeTrailCheck("Cascade-2048", NuGimli2048, 1603)
  relatedKeyShiftCheck("Cascade-512", NuGimli512)
  relatedKeyShiftCheck("Cascade-1024", NuGimli1024)
  relatedKeyShiftCheck("Cascade-2048", NuGimli2048)
  vectorChecks("Cascade-512", NuGimli512, cascadePermutation512Vector,
    cascadeCiphertext512Vector)
  vectorChecks("Cascade-1024", NuGimli1024, cascadePermutation1024Vector,
    cascadeCiphertext1024Vector)
  vectorChecks("Cascade-2048", NuGimli2048, cascadePermutation2048Vector,
    cascadeCiphertext2048Vector)

  test "frozen scalar-independent regression outputs":
    var
      S512: NuGimli512 = default(NuGimli512)
      S1024: NuGimli1024 = default(NuGimli1024)
      S2048: NuGimli2048 = default(NuGimli2048)
    fillNuGimliState(S512, 0x31415926'u32)
    cascadePermute(S512)
    check nuGimliFingerprint(S512) == 7746884849776999048'u64
    fillNuGimliState(S1024, 0x31415926'u32)
    cascadePermute(S1024)
    check nuGimliFingerprint(S1024) == 10781833102301254439'u64
    fillNuGimliState(S2048, 0x31415926'u32)
    cascadePermute(S2048)
    check nuGimliFingerprint(S2048) == 7930554559429063498'u64
