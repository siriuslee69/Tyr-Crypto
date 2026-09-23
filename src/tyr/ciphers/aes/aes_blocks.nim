## AES block routines included by aes_core.nim.
##
## This section shares aes_core.nim's lookup tables, types, and imports.

{.push overflowChecks: off.}
proc ctEq(a, b: uint8): uint8 {.inline.} =
  ## Returns 0xFF when equal, 0x00 otherwise (constant-time).
  var x: uint8 = a xor b
  result = uint8((uint16(x) - 1'u16) shr 8)

proc sboxCt(x: uint8): uint8 {.inline.} =
  ## Constant-time S-box lookup by scanning all entries.
  var
    acc: uint8 = 0
    i: int = 0
    mask: uint8 = 0
  while i < 256:
    mask = ctEq(x, uint8(i))
    acc = acc or (sbox[i] and mask)
    i = i + 1
  result = acc
{.pop.}

proc subByte(x: uint8): uint8 {.inline.} =
  when defined(unsafeFastAes):
    result = sbox[x]
  else:
    result = sboxCt(x)

proc subByteFast(x: uint8): uint8 {.inline.} =
  ## Fast table lookup for public-data-only AES paths.
  result = sbox[x]

proc xtime(x: uint8): uint8 {.inline.} =
  var
    shifted: uint8 = uint8(x shl 1)
    carry: uint8 = (x shr 7) and 0x1'u8
  result = shifted xor (0x1b'u8 * carry)

proc mul2(x: uint8): uint8 {.inline.} =
  xtime(x)

proc mul3(x: uint8): uint8 {.inline.} =
  xtime(x) xor x

proc subBytes(state: var AesBlock) =
  var i: int = 0
  i = 0
  while i < state.len:
    state[i] = subByte(state[i])
    i = i + 1

proc subBytesFast(state: var AesBlock) =
  var i: int = 0
  i = 0
  while i < state.len:
    state[i] = subByteFast(state[i])
    i = i + 1

proc shiftRows(state: var AesBlock) =
  var t: uint8 = 0'u8
  # Row 1: shift left by 1
  t = state[1]
  state[1] = state[5]
  state[5] = state[9]
  state[9] = state[13]
  state[13] = t
  # Row 2: shift left by 2
  t = state[2]
  state[2] = state[10]
  state[10] = t
  t = state[6]
  state[6] = state[14]
  state[14] = t
  # Row 3: shift left by 3
  t = state[3]
  state[3] = state[15]
  state[15] = state[11]
  state[11] = state[7]
  state[7] = t

proc mixColumns(state: var AesBlock) =
  var
    c: int = 0
    o: int = 0
    a0, a1, a2, a3: uint8 = 0'u8
  c = 0
  while c < 4:
    o = c * 4
    a0 = state[o]
    a1 = state[o + 1]
    a2 = state[o + 2]
    a3 = state[o + 3]
    state[o] = mul2(a0) xor mul3(a1) xor a2 xor a3
    state[o + 1] = a0 xor mul2(a1) xor mul3(a2) xor a3
    state[o + 2] = a0 xor a1 xor mul2(a2) xor mul3(a3)
    state[o + 3] = mul3(a0) xor a1 xor a2 xor mul2(a3)
    c = c + 1

proc addRoundKey(state: var AesBlock, roundKeys: array[aesRoundKeysLen256, uint8],
    round: int) =
  var
    base: int = round * aesBlockLen
    i: int = 0
  i = 0
  while i < aesBlockLen:
    state[i] = state[i] xor roundKeys[base + i]
    i = i + 1

proc addRoundKey(state: var AesBlock, roundKeys: array[aesRoundKeysLen128, uint8],
    round: int) =
  var
    base: int = round * aesBlockLen
    i: int = 0
  i = 0
  while i < aesBlockLen:
    state[i] = state[i] xor roundKeys[base + i]
    i = i + 1

proc load32Be(A: openArray[uint8], o: int): uint32 {.inline.} =
  result =
    (uint32(A[o]) shl 24) or
    (uint32(A[o + 1]) shl 16) or
    (uint32(A[o + 2]) shl 8) or
    uint32(A[o + 3])

proc store32Be(A: var openArray[uint8], o: int, v: uint32) {.inline.} =
  A[o] = uint8((v shr 24) and 0xff'u32)
  A[o + 1] = uint8((v shr 16) and 0xff'u32)
  A[o + 2] = uint8((v shr 8) and 0xff'u32)
  A[o + 3] = uint8(v and 0xff'u32)

proc expandKey128(key: openArray[uint8]): array[aesRoundKeysLen128, uint8] =
  if key.len != aesKeyLen128:
    raise newException(ValueError, "AES-128 requires 16-byte key")
  var
    bytesGenerated: int = 0
    rconIter: int = 1
    temp: array[4, uint8] = default(array[4, uint8])
    j: int = 0
    t0: uint8 = 0
  while bytesGenerated < aesKeyLen128:
    result[bytesGenerated] = key[bytesGenerated]
    bytesGenerated = bytesGenerated + 1
  while bytesGenerated < aesRoundKeysLen128:
    temp[0] = result[bytesGenerated - 4]
    temp[1] = result[bytesGenerated - 3]
    temp[2] = result[bytesGenerated - 2]
    temp[3] = result[bytesGenerated - 1]
    if (bytesGenerated mod aesKeyLen128) == 0:
      t0 = temp[0]
      temp[0] = temp[1]
      temp[1] = temp[2]
      temp[2] = temp[3]
      temp[3] = t0
      temp[0] = subByte(temp[0])
      temp[1] = subByte(temp[1])
      temp[2] = subByte(temp[2])
      temp[3] = subByte(temp[3])
      temp[0] = temp[0] xor rcon[rconIter]
      rconIter = rconIter + 1
    j = 0
    while j < 4:
      result[bytesGenerated] = result[bytesGenerated - aesKeyLen128] xor temp[j]
      bytesGenerated = bytesGenerated + 1
      j = j + 1

proc expandKey128Fast(key: openArray[uint8]): array[aesRoundKeysLen128, uint8] =
  if key.len != aesKeyLen128:
    raise newException(ValueError, "AES-128 requires 16-byte key")
  var
    bytesGenerated: int = 0
    rconIter: int = 1
    temp: array[4, uint8] = default(array[4, uint8])
    j: int = 0
    t0: uint8 = 0
  while bytesGenerated < aesKeyLen128:
    result[bytesGenerated] = key[bytesGenerated]
    bytesGenerated = bytesGenerated + 1
  while bytesGenerated < aesRoundKeysLen128:
    temp[0] = result[bytesGenerated - 4]
    temp[1] = result[bytesGenerated - 3]
    temp[2] = result[bytesGenerated - 2]
    temp[3] = result[bytesGenerated - 1]
    if (bytesGenerated mod aesKeyLen128) == 0:
      t0 = temp[0]
      temp[0] = temp[1]
      temp[1] = temp[2]
      temp[2] = temp[3]
      temp[3] = t0
      temp[0] = subByteFast(temp[0])
      temp[1] = subByteFast(temp[1])
      temp[2] = subByteFast(temp[2])
      temp[3] = subByteFast(temp[3])
      temp[0] = temp[0] xor rcon[rconIter]
      rconIter = rconIter + 1
    j = 0
    while j < 4:
      result[bytesGenerated] = result[bytesGenerated - aesKeyLen128] xor temp[j]
      bytesGenerated = bytesGenerated + 1
      j = j + 1

proc init*(ctx: var Aes128Ctx, key: openArray[uint8]) =
  clear(ctx)
  ctx.roundKeys = expandKey128(key)
  ctx.initialized = true

proc initPublicFast*(ctx: var Aes128Ctx, key: openArray[uint8]) =
  ## Fast AES-128 key schedule for public-data-only use.
  clear(ctx)
  ctx.roundKeys = expandKey128Fast(key)
  ctx.initialized = true

when defined(aesni):
  proc init*(ctx: var Aes128NiCtx, key: openArray[uint8]) =
    var
      scalarCtx: Aes128Ctx = default(Aes128Ctx)
      i: int = 0
      o: int = 0
    defer:
      clear(scalarCtx)
    clear(ctx)
    scalarCtx.init(key)
    i = 0
    while i <= aesNr128:
      o = i * aesBlockLen
      ctx.roundKeys[i] = mm_loadu_si128(cast[pointer](unsafeAddr scalarCtx.roundKeys[o]))
      i = i + 1
    ctx.initialized = true

  proc initPublicFast*(ctx: var Aes128NiCtx, key: openArray[uint8]) =
    ctx.init(key)

proc expandKey256(key: openArray[uint8]): array[aesRoundKeysLen256, uint8] =
  if key.len != aesKeyLen256:
    raise newException(ValueError, "AES-256 requires 32-byte key")
  var
    bytesGenerated: int = 0
    rconIter: int = 1
    temp: array[4, uint8] = default(array[4, uint8])
    j: int = 0
    t0: uint8 = 0
  while bytesGenerated < aesKeyLen256:
    result[bytesGenerated] = key[bytesGenerated]
    bytesGenerated = bytesGenerated + 1
  while bytesGenerated < aesRoundKeysLen256:
    temp[0] = result[bytesGenerated - 4]
    temp[1] = result[bytesGenerated - 3]
    temp[2] = result[bytesGenerated - 2]
    temp[3] = result[bytesGenerated - 1]
    if (bytesGenerated mod aesKeyLen256) == 0:
      t0 = temp[0]
      temp[0] = temp[1]
      temp[1] = temp[2]
      temp[2] = temp[3]
      temp[3] = t0
      temp[0] = subByte(temp[0])
      temp[1] = subByte(temp[1])
      temp[2] = subByte(temp[2])
      temp[3] = subByte(temp[3])
      temp[0] = temp[0] xor rcon[rconIter]
      rconIter = rconIter + 1
    elif (bytesGenerated mod aesKeyLen256) == 16:
      temp[0] = subByte(temp[0])
      temp[1] = subByte(temp[1])
      temp[2] = subByte(temp[2])
      temp[3] = subByte(temp[3])
    j = 0
    while j < 4:
      result[bytesGenerated] = result[bytesGenerated - aesKeyLen256] xor temp[j]
      bytesGenerated = bytesGenerated + 1
      j = j + 1

proc init*(ctx: var Aes256Ctx, key: openArray[uint8]) =
  clear(ctx)
  ctx.roundKeys = expandKey256(key)
  ctx.initialized = true

proc encryptBlock*(ctx: Aes128Ctx, input: AesBlock): AesBlock =
  var
    state = input
    round: int = 1
  requireInitialized(ctx)
  addRoundKey(state, ctx.roundKeys, 0)
  round = 1
  while round < aesNr128:
    subBytes(state)
    shiftRows(state)
    mixColumns(state)
    addRoundKey(state, ctx.roundKeys, round)
    round = round + 1
  subBytes(state)
  shiftRows(state)
  addRoundKey(state, ctx.roundKeys, aesNr128)
  result = state

proc encryptBlockPublicFast*(ctx: Aes128Ctx, input: AesBlock): AesBlock =
  ## Fast AES-128 encryption for public-data-only use.
  var
    s0: uint32 = load32Be(input, 0) xor load32Be(ctx.roundKeys, 0)
    s1: uint32 = load32Be(input, 4) xor load32Be(ctx.roundKeys, 4)
    s2: uint32 = load32Be(input, 8) xor load32Be(ctx.roundKeys, 8)
    s3: uint32 = load32Be(input, 12) xor load32Be(ctx.roundKeys, 12)
    t0: uint32 = 0
    t1: uint32 = 0
    t2: uint32 = 0
    t3: uint32 = 0
    round: int = 1
    rkOff: int = 16
  requireInitialized(ctx)
  round = 1
  while round < aesNr128:
    t0 = te0[(s0 shr 24) and 0xff'u32] xor
      te1[(s1 shr 16) and 0xff'u32] xor
      te2[(s2 shr 8) and 0xff'u32] xor
      te3[s3 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 0)
    t1 = te0[(s1 shr 24) and 0xff'u32] xor
      te1[(s2 shr 16) and 0xff'u32] xor
      te2[(s3 shr 8) and 0xff'u32] xor
      te3[s0 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 4)
    t2 = te0[(s2 shr 24) and 0xff'u32] xor
      te1[(s3 shr 16) and 0xff'u32] xor
      te2[(s0 shr 8) and 0xff'u32] xor
      te3[s1 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 8)
    t3 = te0[(s3 shr 24) and 0xff'u32] xor
      te1[(s0 shr 16) and 0xff'u32] xor
      te2[(s1 shr 8) and 0xff'u32] xor
      te3[s2 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 12)
    s0 = t0
    s1 = t1
    s2 = t2
    s3 = t3
    rkOff = rkOff + 16
    round = round + 1
  t0 =
    (uint32(sbox[(s0 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s1 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s2 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s3 and 0xff'u32])
  t1 =
    (uint32(sbox[(s1 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s2 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s3 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s0 and 0xff'u32])
  t2 =
    (uint32(sbox[(s2 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s3 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s0 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s1 and 0xff'u32])
  t3 =
    (uint32(sbox[(s3 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s0 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s1 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s2 and 0xff'u32])
  t0 = t0 xor load32Be(ctx.roundKeys, rkOff + 0)
  t1 = t1 xor load32Be(ctx.roundKeys, rkOff + 4)
  t2 = t2 xor load32Be(ctx.roundKeys, rkOff + 8)
  t3 = t3 xor load32Be(ctx.roundKeys, rkOff + 12)
  store32Be(result, 0, t0)
  store32Be(result, 4, t1)
  store32Be(result, 8, t2)
  store32Be(result, 12, t3)

proc encryptBlocksPublicFast*(ctx: Aes128Ctx, input: openArray[AesBlock],
    output: var openArray[AesBlock]) {.gcsafe.} =
  ## Fast AES-128 bulk encryption for public-data-only use.
  var
    i: int = 0
  requireInitialized(ctx)
  if output.len != input.len:
    raise newException(ValueError, "AES public bulk encrypt length mismatch")
  i = 0
  while i < input.len:
    output[i] = encryptBlockPublicFast(ctx, input[i])
    i = i + 1

when defined(aesni):
  proc encryptBlock*(ctx: Aes128NiCtx, input: AesBlock): AesBlock =
    var
      state: M128i = default(M128i)
      round: int = 1
    requireInitialized(ctx)
    state = mm_loadu_si128(cast[pointer](unsafeAddr input[0]))
    state = mm_xor_si128(state, ctx.roundKeys[0])
    round = 1
    while round < aesNr128:
      state = mm_aesenc_si128(state, ctx.roundKeys[round])
      round = round + 1
    state = mm_aesenclast_si128(state, ctx.roundKeys[aesNr128])
    mm_storeu_si128(cast[pointer](unsafeAddr result[0]), state)

  proc encryptBlock4*(ctx: Aes128NiCtx, input: array[4, AesBlock]): array[4, AesBlock] =
    var
      s0, s1, s2, s3: M128i = default(M128i)
      round: int = 1
    requireInitialized(ctx)
    s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[0][0]))
    s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[1][0]))
    s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[2][0]))
    s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[3][0]))
    s0 = mm_xor_si128(s0, ctx.roundKeys[0])
    s1 = mm_xor_si128(s1, ctx.roundKeys[0])
    s2 = mm_xor_si128(s2, ctx.roundKeys[0])
    s3 = mm_xor_si128(s3, ctx.roundKeys[0])
    round = 1
    while round < aesNr128:
      s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
      s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
      s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
      s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
      round = round + 1
    s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
    s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
    s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
    s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
    mm_storeu_si128(cast[pointer](unsafeAddr result[0][0]), s0)
    mm_storeu_si128(cast[pointer](unsafeAddr result[1][0]), s1)
    mm_storeu_si128(cast[pointer](unsafeAddr result[2][0]), s2)
    mm_storeu_si128(cast[pointer](unsafeAddr result[3][0]), s3)

  proc encryptBlock8*(ctx: Aes128NiCtx, input: array[8, AesBlock]): array[8, AesBlock] =
    var
      s0, s1, s2, s3: M128i = default(M128i)
      s4, s5, s6, s7: M128i = default(M128i)
      round: int = 1
    requireInitialized(ctx)
    s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[0][0]))
    s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[1][0]))
    s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[2][0]))
    s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[3][0]))
    s4 = mm_loadu_si128(cast[pointer](unsafeAddr input[4][0]))
    s5 = mm_loadu_si128(cast[pointer](unsafeAddr input[5][0]))
    s6 = mm_loadu_si128(cast[pointer](unsafeAddr input[6][0]))
    s7 = mm_loadu_si128(cast[pointer](unsafeAddr input[7][0]))
    s0 = mm_xor_si128(s0, ctx.roundKeys[0])
    s1 = mm_xor_si128(s1, ctx.roundKeys[0])
    s2 = mm_xor_si128(s2, ctx.roundKeys[0])
    s3 = mm_xor_si128(s3, ctx.roundKeys[0])
    s4 = mm_xor_si128(s4, ctx.roundKeys[0])
    s5 = mm_xor_si128(s5, ctx.roundKeys[0])
    s6 = mm_xor_si128(s6, ctx.roundKeys[0])
    s7 = mm_xor_si128(s7, ctx.roundKeys[0])
    round = 1
    while round < aesNr128:
      s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
      s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
      s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
      s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
      s4 = mm_aesenc_si128(s4, ctx.roundKeys[round])
      s5 = mm_aesenc_si128(s5, ctx.roundKeys[round])
      s6 = mm_aesenc_si128(s6, ctx.roundKeys[round])
      s7 = mm_aesenc_si128(s7, ctx.roundKeys[round])
      round = round + 1
    s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
    s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
    s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
    s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
    s4 = mm_aesenclast_si128(s4, ctx.roundKeys[aesNr128])
    s5 = mm_aesenclast_si128(s5, ctx.roundKeys[aesNr128])
    s6 = mm_aesenclast_si128(s6, ctx.roundKeys[aesNr128])
    s7 = mm_aesenclast_si128(s7, ctx.roundKeys[aesNr128])
    mm_storeu_si128(cast[pointer](unsafeAddr result[0][0]), s0)
    mm_storeu_si128(cast[pointer](unsafeAddr result[1][0]), s1)
    mm_storeu_si128(cast[pointer](unsafeAddr result[2][0]), s2)
    mm_storeu_si128(cast[pointer](unsafeAddr result[3][0]), s3)
    mm_storeu_si128(cast[pointer](unsafeAddr result[4][0]), s4)
    mm_storeu_si128(cast[pointer](unsafeAddr result[5][0]), s5)
    mm_storeu_si128(cast[pointer](unsafeAddr result[6][0]), s6)
    mm_storeu_si128(cast[pointer](unsafeAddr result[7][0]), s7)

  proc encryptBlocks*(ctx: Aes128NiCtx, input: openArray[AesBlock],
      output: var openArray[AesBlock]) =
    var
      i: int = 0
      s0, s1, s2, s3: M128i = default(M128i)
      s4, s5, s6, s7: M128i = default(M128i)
      round: int = 1
    requireInitialized(ctx)
    if output.len != input.len:
      raise newException(ValueError, "AES block bulk encrypt length mismatch")
    i = 0
    while i + 8 <= input.len:
      s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 0][0]))
      s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 1][0]))
      s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 2][0]))
      s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 3][0]))
      s4 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 4][0]))
      s5 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 5][0]))
      s6 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 6][0]))
      s7 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 7][0]))
      s0 = mm_xor_si128(s0, ctx.roundKeys[0])
      s1 = mm_xor_si128(s1, ctx.roundKeys[0])
      s2 = mm_xor_si128(s2, ctx.roundKeys[0])
      s3 = mm_xor_si128(s3, ctx.roundKeys[0])
      s4 = mm_xor_si128(s4, ctx.roundKeys[0])
      s5 = mm_xor_si128(s5, ctx.roundKeys[0])
      s6 = mm_xor_si128(s6, ctx.roundKeys[0])
      s7 = mm_xor_si128(s7, ctx.roundKeys[0])
      round = 1
      while round < aesNr128:
        s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
        s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
        s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
        s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
        s4 = mm_aesenc_si128(s4, ctx.roundKeys[round])
        s5 = mm_aesenc_si128(s5, ctx.roundKeys[round])
        s6 = mm_aesenc_si128(s6, ctx.roundKeys[round])
        s7 = mm_aesenc_si128(s7, ctx.roundKeys[round])
        round = round + 1
      s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
      s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
      s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
      s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
      s4 = mm_aesenclast_si128(s4, ctx.roundKeys[aesNr128])
      s5 = mm_aesenclast_si128(s5, ctx.roundKeys[aesNr128])
      s6 = mm_aesenclast_si128(s6, ctx.roundKeys[aesNr128])
      s7 = mm_aesenclast_si128(s7, ctx.roundKeys[aesNr128])
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 0][0]), s0)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 1][0]), s1)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 2][0]), s2)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 3][0]), s3)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 4][0]), s4)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 5][0]), s5)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 6][0]), s6)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 7][0]), s7)
      i = i + 8
    while i + 4 <= input.len:
      s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 0][0]))
      s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 1][0]))
      s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 2][0]))
      s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 3][0]))
      s0 = mm_xor_si128(s0, ctx.roundKeys[0])
      s1 = mm_xor_si128(s1, ctx.roundKeys[0])
      s2 = mm_xor_si128(s2, ctx.roundKeys[0])
      s3 = mm_xor_si128(s3, ctx.roundKeys[0])
      round = 1
      while round < aesNr128:
        s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
        s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
        s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
        s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
        round = round + 1
      s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
      s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
      s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
      s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 0][0]), s0)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 1][0]), s1)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 2][0]), s2)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 3][0]), s3)
      i = i + 4
    while i < input.len:
      output[i] = encryptBlock(ctx, input[i])
      i = i + 1

proc encryptBlock*(ctx: Aes256Ctx, input: AesBlock): AesBlock =
  var state = input
  requireInitialized(ctx)
  addRoundKey(state, ctx.roundKeys, 0)
  var round: int = 1
  round = 1
  while round < aesNr256:
    subBytes(state)
    shiftRows(state)
    mixColumns(state)
    addRoundKey(state, ctx.roundKeys, round)
    round = round + 1
  subBytes(state)
  shiftRows(state)
  addRoundKey(state, ctx.roundKeys, aesNr256)
  result = state
