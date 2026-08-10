## -------------------------------------------------------------------------
## XChaCha20 Batch <- independent streams across scalar or SIMD message lanes
## -------------------------------------------------------------------------

import ../../../../../.iron/meta/metaPragmas
import ./chacha20_scalar as chacha_scalar
import ./xchacha20 as scalar

when defined(avx2):
  import nimsimd/avx2

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/[base_operations, generic_u32]

when defined(avx2) or defined(sse2) or defined(neon) or defined(arm64) or
    defined(aarch64):
  import ../secure_memory

const
  xchachaKeyBytes = 32
  xchachaNonceBytes = 24

when defined(avx2) or defined(sse2) or defined(neon) or defined(arm64) or
    defined(aarch64):
  const
    xchachaBlockBytes = 64
    xchachaSigma = [
      0x61707865'u32, 0x3320646e'u32, 0x79622d32'u32, 0x6b206574'u32
    ]

type
  ByteSeq = seq[uint8]

when defined(avx2) or defined(sse2) or defined(neon) or defined(arm64) or
    defined(aarch64):
  proc loadBatchU32(A: openArray[uint8], o: int): uint32 {.inline,
      role: {parser}, tag: {other}.} =
    ## A/o: one little-endian word from a validated key or nonce.
    result = uint32(A[o]) or (uint32(A[o + 1]) shl 8) or
      (uint32(A[o + 2]) shl 16) or (uint32(A[o + 3]) shl 24)

  proc storeBatchWord(A: var ByteSeq, o: int, v: uint32) {.inline,
      role: {actor}, tag: {other}.} =
    ## A/o/v: destination, byte offset, and one possibly partial final word.
    var
      i: int = 0
      n: int = 0
    if o >= A.len:
      return
    n = min(4, A.len - o)
    while i < n:
      A[o + i] = uint8((v shr (i * 8)) and 0xff'u32)
      i = i + 1

proc requireBatchInputs(K, N: openArray[ByteSeq], l: int, c: uint32) {.
    role: {parser}, tag: {other}.} =
  ## K/N/l/c: equal key/nonce rows, bytes per stream, and first block counter.
  var
    i: int = 0
  if K.len != N.len:
    raise newException(ValueError, "XChaCha20 batch key and nonce counts differ")
  chacha_scalar.requireChaCha20BlockRange(c, l)
  while i < K.len:
    if K[i].len != xchachaKeyBytes or N[i].len != xchachaNonceBytes:
      raise newException(ValueError,
        "XChaCha20 batch requires 32-byte keys and 24-byte nonces")
    i = i + 1

when defined(avx2):
  proc avxSet1(v: uint32): M256i {.inline, role: {helper}, tag: {other}.} =
    ## v: one word broadcast across eight independent streams.
    result = mm256_set1_epi32(cast[int32](v))

  proc avxLoadWord(A: array[8, ByteSeq], o: int): M256i {.inline,
      role: {helper}, tag: {other}.} =
    ## A/o: one word from each of eight independent streams.
    result = mm256_setr_epi32(
      cast[int32](loadBatchU32(A[0], o)),
      cast[int32](loadBatchU32(A[1], o)),
      cast[int32](loadBatchU32(A[2], o)),
      cast[int32](loadBatchU32(A[3], o)),
      cast[int32](loadBatchU32(A[4], o)),
      cast[int32](loadBatchU32(A[5], o)),
      cast[int32](loadBatchU32(A[6], o)),
      cast[int32](loadBatchU32(A[7], o)))

  proc avxRotl(v: M256i, n: int32): M256i {.inline, role: {math},
      tag: {other}.} =
    ## v/n: eight words and one ChaCha rotation count.
    result = mm256_or_si256(mm256_slli_epi32(v, n),
      mm256_srli_epi32(v, 32'i32 - n))

  proc avxQuarterRound(a, b, c, d: var M256i) {.inline, role: {math},
      tag: {other}.} =
    ## a/b/c/d: one ChaCha quarter-round across eight streams.
    a = mm256_add_epi32(a, b)
    d = avxRotl(mm256_xor_si256(d, a), 16)
    c = mm256_add_epi32(c, d)
    b = avxRotl(mm256_xor_si256(b, c), 12)
    a = mm256_add_epi32(a, b)
    d = avxRotl(mm256_xor_si256(d, a), 8)
    c = mm256_add_epi32(c, d)
    b = avxRotl(mm256_xor_si256(b, c), 7)

  proc avxRounds(S: var array[16, M256i]) {.inline, role: {actor},
      tag: {other}.} =
    ## S: twenty ChaCha rounds over eight independent states.
    var
      i: int = 0
    while i < 10:
      avxQuarterRound(S[0], S[4], S[8], S[12])
      avxQuarterRound(S[1], S[5], S[9], S[13])
      avxQuarterRound(S[2], S[6], S[10], S[14])
      avxQuarterRound(S[3], S[7], S[11], S[15])
      avxQuarterRound(S[0], S[5], S[10], S[15])
      avxQuarterRound(S[1], S[6], S[11], S[12])
      avxQuarterRound(S[2], S[7], S[8], S[13])
      avxQuarterRound(S[3], S[4], S[9], S[14])
      i = i + 1

  proc deriveBatchSubkeys8(K, N: array[8, ByteSeq]): array[8, M256i] {.
      role: {truthBuilder}, tag: {other}.} =
    ## K/N: eight validated XChaCha20 keys and nonces.
    var
      S: array[16, M256i]
      i: int = 0
    defer:
      secureClearPod(S)
    S[0] = avxSet1(xchachaSigma[0])
    S[1] = avxSet1(xchachaSigma[1])
    S[2] = avxSet1(xchachaSigma[2])
    S[3] = avxSet1(xchachaSigma[3])
    while i < 8:
      S[4 + i] = avxLoadWord(K, i * 4)
      i = i + 1
    i = 0
    while i < 4:
      S[12 + i] = avxLoadWord(N, i * 4)
      i = i + 1
    avxRounds(S)
    result[0] = S[0]
    result[1] = S[1]
    result[2] = S[2]
    result[3] = S[3]
    result[4] = S[12]
    result[5] = S[13]
    result[6] = S[14]
    result[7] = S[15]

  proc storeAvxWord(v: M256i, A: var array[8, ByteSeq], o: int) {.inline,
      role: {actor}, tag: {other}.} =
    ## v/A/o: one output word copied into each stream.
    var
      V: array[8, int32]
      i: int = 0
    mm256_storeu_si256(cast[pointer](addr V[0]), v)
    while i < A.len:
      storeBatchWord(A[i], o, cast[uint32](V[i]))
      i = i + 1

  proc xchachaBlock8(H: array[8, M256i], N: array[8, ByteSeq], c: uint32,
      A: var array[8, ByteSeq], o: int) {.role: {actor}, tag: {other}.} =
    ## H/N/c/A/o: subkeys, nonces, counter, outputs, and byte offset.
    var
      S: array[16, M256i]
      O: array[16, M256i]
      i: int = 0
    defer:
      secureClearPod(S)
      secureClearPod(O)
    S[0] = avxSet1(xchachaSigma[0])
    S[1] = avxSet1(xchachaSigma[1])
    S[2] = avxSet1(xchachaSigma[2])
    S[3] = avxSet1(xchachaSigma[3])
    while i < 8:
      S[4 + i] = H[i]
      i = i + 1
    S[12] = avxSet1(c)
    S[13] = avxSet1(0'u32)
    S[14] = avxLoadWord(N, 16)
    S[15] = avxLoadWord(N, 20)
    O = S
    avxRounds(S)
    i = 0
    while i < S.len:
      S[i] = mm256_add_epi32(S[i], O[i])
      storeAvxWord(S[i], A, o + i * 4)
      i = i + 1

  proc prepareBatch8(K, N: array[8, ByteSeq], l: int,
      c: uint32): array[8, ByteSeq] {.role: {truthBuilder}, tag: {other}.} =
    ## K/N/l/c: eight streams, bytes per stream, and first block counter.
    var
      H: array[8, M256i]
      o: int = 0
      counter: uint32 = c
      i: int = 0
    defer:
      secureClearPod(H)
    H = deriveBatchSubkeys8(K, N)
    while i < result.len:
      result[i].setLen(l)
      i = i + 1
    while o < l:
      xchachaBlock8(H, N, counter, result, o)
      o = o + xchachaBlockBytes
      if o < l:
        counter = counter + 1'u32

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  when defined(neon) or defined(arm64) or defined(aarch64):
    type
      BatchVec4 = uint32x4
  else:
    type
      BatchVec4 = M128i

  proc vec4Set1(v: uint32): BatchVec4 {.inline, role: {helper},
      tag: {other}.} =
    ## v: one word broadcast across four independent streams.
    result = set1U32[BatchVec4](v)

  proc vec4LoadWord(A: array[4, ByteSeq], o: int): BatchVec4 {.inline,
      role: {helper}, tag: {other}.} =
    ## A/o: one word from each of four independent streams.
    var
      V: array[4, uint32]
    V[0] = loadBatchU32(A[0], o)
    V[1] = loadBatchU32(A[1], o)
    V[2] = loadBatchU32(A[2], o)
    V[3] = loadBatchU32(A[3], o)
    result = loadU32x4[BatchVec4](V)

  proc vec4QuarterRound(a, b, c, d: var BatchVec4) {.inline, role: {math},
      tag: {other}.} =
    ## a/b/c/d: one ChaCha quarter-round across four streams.
    a = a + b
    d = rotl32(d xor a, 16'i32)
    c = c + d
    b = rotl32(b xor c, 12'i32)
    a = a + b
    d = rotl32(d xor a, 8'i32)
    c = c + d
    b = rotl32(b xor c, 7'i32)

  proc vec4Rounds(S: var array[16, BatchVec4]) {.inline, role: {actor},
      tag: {other}.} =
    ## S: twenty ChaCha rounds over four independent states.
    var
      i: int = 0
    while i < 10:
      vec4QuarterRound(S[0], S[4], S[8], S[12])
      vec4QuarterRound(S[1], S[5], S[9], S[13])
      vec4QuarterRound(S[2], S[6], S[10], S[14])
      vec4QuarterRound(S[3], S[7], S[11], S[15])
      vec4QuarterRound(S[0], S[5], S[10], S[15])
      vec4QuarterRound(S[1], S[6], S[11], S[12])
      vec4QuarterRound(S[2], S[7], S[8], S[13])
      vec4QuarterRound(S[3], S[4], S[9], S[14])
      i = i + 1

  proc deriveBatchSubkeys4(K, N: array[4, ByteSeq]): array[8, BatchVec4] {.
      role: {truthBuilder}, tag: {other}.} =
    ## K/N: four validated XChaCha20 keys and nonces.
    var
      S: array[16, BatchVec4]
      i: int = 0
    defer:
      secureClearPod(S)
    S[0] = vec4Set1(xchachaSigma[0])
    S[1] = vec4Set1(xchachaSigma[1])
    S[2] = vec4Set1(xchachaSigma[2])
    S[3] = vec4Set1(xchachaSigma[3])
    while i < 8:
      S[4 + i] = vec4LoadWord(K, i * 4)
      i = i + 1
    i = 0
    while i < 4:
      S[12 + i] = vec4LoadWord(N, i * 4)
      i = i + 1
    vec4Rounds(S)
    result[0] = S[0]
    result[1] = S[1]
    result[2] = S[2]
    result[3] = S[3]
    result[4] = S[12]
    result[5] = S[13]
    result[6] = S[14]
    result[7] = S[15]

  proc storeVec4Word(v: BatchVec4, A: var array[4, ByteSeq], o: int) {.
      inline, role: {actor}, tag: {other}.} =
    ## v/A/o: one output word copied into each stream.
    var
      V: array[4, uint32] = storeU32x4(v)
      i: int = 0
    while i < A.len:
      storeBatchWord(A[i], o, V[i])
      i = i + 1

  proc xchachaBlock4(H: array[8, BatchVec4], N: array[4, ByteSeq], c: uint32,
      A: var array[4, ByteSeq], o: int) {.role: {actor}, tag: {other}.} =
    ## H/N/c/A/o: subkeys, nonces, counter, outputs, and byte offset.
    var
      S: array[16, BatchVec4]
      O: array[16, BatchVec4]
      i: int = 0
    defer:
      secureClearPod(S)
      secureClearPod(O)
    S[0] = vec4Set1(xchachaSigma[0])
    S[1] = vec4Set1(xchachaSigma[1])
    S[2] = vec4Set1(xchachaSigma[2])
    S[3] = vec4Set1(xchachaSigma[3])
    while i < 8:
      S[4 + i] = H[i]
      i = i + 1
    S[12] = vec4Set1(c)
    S[13] = vec4Set1(0'u32)
    S[14] = vec4LoadWord(N, 16)
    S[15] = vec4LoadWord(N, 20)
    O = S
    vec4Rounds(S)
    i = 0
    while i < S.len:
      S[i] = S[i] + O[i]
      storeVec4Word(S[i], A, o + i * 4)
      i = i + 1

  proc prepareBatch4(K, N: array[4, ByteSeq], l: int,
      c: uint32): array[4, ByteSeq] {.role: {truthBuilder}, tag: {other}.} =
    ## K/N/l/c: four streams, bytes per stream, and first block counter.
    var
      H: array[8, BatchVec4]
      o: int = 0
      counter: uint32 = c
      i: int = 0
    defer:
      secureClearPod(H)
    H = deriveBatchSubkeys4(K, N)
    while i < result.len:
      result[i].setLen(l)
      i = i + 1
    while o < l:
      xchachaBlock4(H, N, counter, result, o)
      o = o + xchachaBlockBytes
      if o < l:
        counter = counter + 1'u32

when defined(avx2):
  proc loadBatch8(K, N: openArray[ByteSeq], o: int,
      K8, N8: var array[8, ByteSeq]) {.inline, role: {helper},
      tag: {other}.} =
    ## K/N/o/K8/N8: copy one complete eight-stream batch.
    var
      i: int = 0
    while i < K8.len:
      K8[i] = K[o + i]
      N8[i] = N[o + i]
      i = i + 1

  proc storeBatch8(S: var seq[ByteSeq], o: int,
      A: var array[8, ByteSeq]) {.inline, role: {actor}, tag: {other}.} =
    ## S/o/A: move one complete eight-stream result batch.
    var
      i: int = 0
    while i < A.len:
      S[o + i] = move(A[i])
      i = i + 1

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  proc loadBatch4(K, N: openArray[ByteSeq], o: int,
      K4, N4: var array[4, ByteSeq]) {.inline, role: {helper},
      tag: {other}.} =
    ## K/N/o/K4/N4: copy one complete four-stream batch.
    var
      i: int = 0
    while i < K4.len:
      K4[i] = K[o + i]
      N4[i] = N[o + i]
      i = i + 1

  proc storeBatch4(S: var seq[ByteSeq], o: int,
      A: var array[4, ByteSeq]) {.inline, role: {actor}, tag: {other}.} =
    ## S/o/A: move one complete four-stream result batch.
    var
      i: int = 0
    while i < A.len:
      S[o + i] = move(A[i])
      i = i + 1

proc xchacha20BatchWidth*(): int {.role: {parser}, tag: {other}.} =
  ## Return the compiled independent-stream lane width.
  when defined(avx2):
    result = 8
  elif defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    result = 4
  else:
    result = 1

proc xchacha20BatchStreams*(K, N: openArray[ByteSeq], l: int,
    c: uint32 = 0'u32): seq[ByteSeq] {.role: {truthBuilder}, tag: {other}.} =
  ## K/N/l/c: independent keys, nonces, bytes per stream, and first counter.
  var
    i: int = 0
    stream: ByteSeq = @[]
  when defined(avx2):
    var
      K8: array[8, ByteSeq]
      N8: array[8, ByteSeq]
      S8: array[8, ByteSeq]
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    var
      K4: array[4, ByteSeq]
      N4: array[4, ByteSeq]
      S4: array[4, ByteSeq]
  requireBatchInputs(K, N, l, c)
  result.setLen(K.len)
  when defined(avx2):
    while i <= K.len - K8.len:
      loadBatch8(K, N, i, K8, N8)
      S8 = prepareBatch8(K8, N8, l, c)
      storeBatch8(result, i, S8)
      i = i + K8.len
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    while i <= K.len - K4.len:
      loadBatch4(K, N, i, K4, N4)
      S4 = prepareBatch4(K4, N4, l, c)
      storeBatch4(result, i, S4)
      i = i + K4.len
  while i < K.len:
    stream = scalar.xchacha20Stream(K[i], N[i], l, c)
    result[i] = move(stream)
    i = i + 1
