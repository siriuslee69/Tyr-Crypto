## ----------------------------------------------------------
## Falcon RNG <- ChaCha20 PRNG seeded from local SHAKE256
## ----------------------------------------------------------

import ../../../sha3
import ./shake
import ./util

type
  FalconPrngBuffer = object
    d*: array[512, byte]

  FalconPrngState = object
    d*: array[256, byte]

  FalconPrng* = object
    buf*: FalconPrngBuffer
    pos*: int
    state*: FalconPrngState
    kind*: int

const
  chachaConstWords: array[4, uint32] = [
    0x61707865'u32, 0x3320646e'u32, 0x79622d32'u32, 0x6b206574'u32
  ]

proc rotl32(x: uint32, n: int): uint32 {.inline.} =
  (x shl n) or (x shr (32 - n))

template qround(state: var array[16, uint32], a, b, c, d: static[int]) =
  state[a] = state[a] + state[b]
  state[d] = state[d] xor state[a]
  state[d] = rotl32(state[d], 16)
  state[c] = state[c] + state[d]
  state[b] = state[b] xor state[c]
  state[b] = rotl32(state[b], 12)
  state[a] = state[a] + state[b]
  state[d] = state[d] xor state[a]
  state[d] = rotl32(state[d], 8)
  state[c] = state[c] + state[d]
  state[b] = state[b] xor state[c]
  state[b] = rotl32(state[b], 7)

proc prngRefill*(p: var FalconPrng) =
  var
    counter = load64Le(p.state.d, 48)
    lane: int = 0
  while lane < 8:
    var
      state: array[16, uint32]
      v: int = 0
      rounds: int = 0
    v = 0
    while v < 4:
      state[v] = chachaConstWords[v]
      v = v + 1
    v = 0
    while v < 12:
      state[4 + v] =
        uint32(p.state.d[4 * v + 0]) or
        (uint32(p.state.d[4 * v + 1]) shl 8) or
        (uint32(p.state.d[4 * v + 2]) shl 16) or
        (uint32(p.state.d[4 * v + 3]) shl 24)
      v = v + 1
    state[14] = state[14] xor uint32(counter)
    state[15] = state[15] xor uint32(counter shr 32)
    rounds = 0
    while rounds < 10:
      qround(state, 0, 4, 8, 12)
      qround(state, 1, 5, 9, 13)
      qround(state, 2, 6, 10, 14)
      qround(state, 3, 7, 11, 15)
      qround(state, 0, 5, 10, 15)
      qround(state, 1, 6, 11, 12)
      qround(state, 2, 7, 8, 13)
      qround(state, 3, 4, 9, 14)
      rounds = rounds + 1
    v = 0
    while v < 4:
      state[v] = state[v] + chachaConstWords[v]
      v = v + 1
    v = 4
    while v < 14:
      state[v] = state[v] + (
        uint32(p.state.d[4 * (v - 4) + 0]) or
        (uint32(p.state.d[4 * (v - 4) + 1]) shl 8) or
        (uint32(p.state.d[4 * (v - 4) + 2]) shl 16) or
        (uint32(p.state.d[4 * (v - 4) + 3]) shl 24)
      )
      v = v + 1
    state[14] = state[14] + (
      (uint32(p.state.d[40]) or
      (uint32(p.state.d[41]) shl 8) or
      (uint32(p.state.d[42]) shl 16) or
      (uint32(p.state.d[43]) shl 24)) xor uint32(counter)
    )
    state[15] = state[15] + (
      (uint32(p.state.d[44]) or
      (uint32(p.state.d[45]) shl 8) or
      (uint32(p.state.d[46]) shl 16) or
      (uint32(p.state.d[47]) shl 24)) xor uint32(counter shr 32)
    )
    counter = counter + 1'u64
    v = 0
    while v < 16:
      let base = (lane shl 2) + (v shl 5)
      p.buf.d[base + 0] = byte(state[v])
      p.buf.d[base + 1] = byte(state[v] shr 8)
      p.buf.d[base + 2] = byte(state[v] shr 16)
      p.buf.d[base + 3] = byte(state[v] shr 24)
      v = v + 1
    lane = lane + 1
  store64Le(p.state.d, counter, 48)
  p.pos = 0

proc prngInit*(p: var FalconPrng, seedMaterial: openArray[byte]) =
  ## Seed Falcon's internal ChaCha20 PRNG from arbitrary local SHAKE256 input.
  var
    tmp = newSeq[byte](56)
    raw: array[56, byte]
    i: int = 0
  shake256Into(tmp, seedMaterial)
  while i < raw.len:
    raw[i] = tmp[i]
    i = i + 1
  prngInit(p, raw)
  clearPlainData(raw)
  clearBytes(tmp)

proc prngInit*(p: var FalconPrng, rawSeed56: array[56, byte]) =
  var
    i: int = 0
    tl: uint64
    th: uint64
  while i < 14:
    let w =
      uint32(rawSeed56[(i shl 2) + 0]) or
      (uint32(rawSeed56[(i shl 2) + 1]) shl 8) or
      (uint32(rawSeed56[(i shl 2) + 2]) shl 16) or
      (uint32(rawSeed56[(i shl 2) + 3]) shl 24)
    p.state.d[(i shl 2) + 0] = byte(w)
    p.state.d[(i shl 2) + 1] = byte(w shr 8)
    p.state.d[(i shl 2) + 2] = byte(w shr 16)
    p.state.d[(i shl 2) + 3] = byte(w shr 24)
    i = i + 1
  tl = uint64(
    uint32(p.state.d[48]) or
    (uint32(p.state.d[49]) shl 8) or
    (uint32(p.state.d[50]) shl 16) or
    (uint32(p.state.d[51]) shl 24)
  )
  th = uint64(
    uint32(p.state.d[52]) or
    (uint32(p.state.d[53]) shl 8) or
    (uint32(p.state.d[54]) shl 16) or
    (uint32(p.state.d[55]) shl 24)
  )
  store64Le(p.state.d, tl + (th shl 32), 48)
  prngRefill(p)

proc prngInitFromShake*(p: var FalconPrng, ctx: var FalconShake256) =
  var seed: array[56, byte]
  extractFalconShake256(ctx, seed)
  prngInit(p, seed)
  clearPlainData(seed)

proc prngGetBytes*(p: var FalconPrng, dst: var openArray[byte]) =
  var
    produced: int = 0
    chunk: int = 0
  while produced < dst.len:
    chunk = p.buf.d.len - p.pos
    if chunk > dst.len - produced:
      chunk = dst.len - produced
    copyMem(addr dst[produced], unsafeAddr p.buf.d[p.pos], chunk)
    produced = produced + chunk
    p.pos = p.pos + chunk
    if p.pos == p.buf.d.len:
      prngRefill(p)

proc prngGetU64*(p: var FalconPrng): uint64 {.inline.} =
  var u = p.pos
  if u >= p.buf.d.len - 9:
    prngRefill(p)
    u = 0
  p.pos = u + 8
  load64Le(p.buf.d, u)

proc prngGetU8*(p: var FalconPrng): uint32 {.inline.} =
  result = uint32(p.buf.d[p.pos])
  p.pos = p.pos + 1
  if p.pos == p.buf.d.len:
    prngRefill(p)
