## ------------------------------------------------------------------
## NuGimli Tests <- reversibility, backend parity, and block transforms
## ------------------------------------------------------------------

import std/unittest
import metaPragmas
import ../src/protocols/custom_crypto/nugimli/types
import ../src/protocols/custom_crypto/nugimli/domain
import ../src/protocols/custom_crypto/nugimli/cascade
import ../src/protocols/custom_crypto/nugimli/reference
import ../src/protocols/custom_crypto/nugimli/core
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

template profileChecks(label: string, State: typedesc, permuteFn, invertFn,
    encryptFn, decryptFn: untyped) =
  test label & " permutation inverse":
    var
      original, state: State
    fillNuGimliState(original, 0x12345678'u32)
    state = original
    permuteFn(state)
    check state != original
    invertFn(state)
    check state == original

  test label & " keyed block transform":
    var
      X, K, C, expected, recovered: State
    fillNuGimliState(X, 0x10203040'u32)
    fillNuGimliState(K, 0xa5a5a5a5'u32)
    C = encryptFn(X, K)
    expected = X
    xorNuGimliState(expected, K)
    permuteFn(expected)
    xorNuGimliState(expected, K)
    check C == expected
    check C != X
    recovered = decryptFn(C, K)
    check recovered == X

template backendChecks(label: string, State: typedesc, roundCount,
    referencePermute, referenceInvert: untyped) =
  test label & " optimized scalar and reference agree":
    var
      optimized, scalar, window, reference, original: State
    fillNuGimliState(original, 0x89abcdef'u32)
    optimized = original
    scalar = original
    cascadePermuteCore(optimized, roundCount, true)
    cascadePermuteCore(scalar, roundCount, false)
    window = original
    cascadePermuteWindowCore(window, roundCount, roundCount, true)
    reference = original
    referencePermute(reference)
    check optimized == scalar
    check optimized == window
    check optimized == reference
    cascadeInvertCore(optimized, roundCount, true)
    cascadeInvertCore(scalar, roundCount, false)
    referenceInvert(reference)
    check optimized == original
    check scalar == original
    check reference == original

template cascadeTrailCheck(label: string, State: typedesc, inputBit: int,
    permuteFn, encryptFn: untyped) =
  test label & " breaks the Gimli top-bit trail":
    var
      X, Y, K, A, B: State
      word, shift: int = 0
    fillNuGimliState(X, 0x7357a11a'u32)
    fillNuGimliState(K, 0xc45cade5'u32)
    Y = X
    word = inputBit div 32
    shift = inputBit mod 32
    Y[word] = Y[word] xor (1'u32 shl shift)
    A = X
    B = Y
    permuteFn(A)
    permuteFn(B)
    check changedNuGimliWords(A, B) == A.len
    A = encryptFn(X, K)
    K[word] = K[word] xor (1'u32 shl shift)
    B = encryptFn(X, K)
    check A != B
    check changedNuGimliWords(A, B) == A.len

template vectorChecks(label: string, State: typedesc, expectedPermutation,
    expectedCiphertext, permuteFn, referenceFn, encryptFn, decryptFn: untyped) =
  test label & " complete published vectors":
    var
      X, K, P, reference, C, recovered: State
    fillCascadeVectorInputs(X, K)
    P = X
    reference = X
    permuteFn(P)
    referenceFn(reference)
    C = encryptFn(X, K)
    recovered = decryptFn(C, K)
    check P == expectedPermutation
    check reference == expectedPermutation
    check C == expectedCiphertext
    check recovered == X

suite "nugimli":
  test "arbitrary contiguous chunk blocks swap":
    var
      state, expected: NuGimli1024
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

  profileChecks("Cascade-512", NuGimli512, cascadePermute512,
    cascadeInvert512, cascadeEncrypt512, cascadeDecrypt512)
  profileChecks("Cascade-1024", NuGimli1024, cascadePermute1024,
    cascadeInvert1024, cascadeEncrypt1024, cascadeDecrypt1024)
  profileChecks("Cascade-2048", NuGimli2048, cascadePermute2048,
    cascadeInvert2048, cascadeEncrypt2048, cascadeDecrypt2048)
  backendChecks("Cascade-512", NuGimli512, nugimli512Rounds,
    cascadeReferencePermute512, cascadeReferenceInvert512)
  backendChecks("Cascade-1024", NuGimli1024, nugimli1024Rounds,
    cascadeReferencePermute1024, cascadeReferenceInvert1024)
  backendChecks("Cascade-2048", NuGimli2048, nugimli2048Rounds,
    cascadeReferencePermute2048, cascadeReferenceInvert2048)

  cascadeTrailCheck("Cascade-512", NuGimli512, 287,
    cascadePermute512, cascadeEncrypt512)
  cascadeTrailCheck("Cascade-1024", NuGimli1024, 799,
    cascadePermute1024, cascadeEncrypt1024)
  cascadeTrailCheck("Cascade-2048", NuGimli2048, 1603,
    cascadePermute2048, cascadeEncrypt2048)

  vectorChecks("Cascade-512", NuGimli512, cascadePermutation512Vector,
    cascadeCiphertext512Vector, cascadePermute512, cascadeReferencePermute512,
    cascadeEncrypt512, cascadeDecrypt512)
  vectorChecks("Cascade-1024", NuGimli1024, cascadePermutation1024Vector,
    cascadeCiphertext1024Vector, cascadePermute1024,
    cascadeReferencePermute1024, cascadeEncrypt1024, cascadeDecrypt1024)
  vectorChecks("Cascade-2048", NuGimli2048, cascadePermutation2048Vector,
    cascadeCiphertext2048Vector, cascadePermute2048,
    cascadeReferencePermute2048, cascadeEncrypt2048, cascadeDecrypt2048)

  test "frozen scalar-independent regression outputs":
    var
      S512: NuGimli512
      S1024: NuGimli1024
      S2048: NuGimli2048
    fillNuGimliState(S512, 0x31415926'u32)
    cascadePermute512(S512)
    check nuGimliFingerprint(S512) == 8782100691334107046'u64
    fillNuGimliState(S1024, 0x31415926'u32)
    cascadePermute1024(S1024)
    check nuGimliFingerprint(S1024) == 4275555771909210885'u64
    fillNuGimliState(S2048, 0x31415926'u32)
    cascadePermute2048(S2048)
    check nuGimliFingerprint(S2048) == 15119555303360204443'u64
