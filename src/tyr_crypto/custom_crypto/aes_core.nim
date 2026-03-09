## ------------------------------------------------------
## AES-256 Core <- Pure Nim AES block implementation
## Default: constant-time S-box and branchless xtime.
## Define -d:unsafeFastAes to use table lookups (unsafe).
## ------------------------------------------------------

const
  aesBlockLen* = 16
  aesKeyLen256* = 32
  aesNr256 = 14
  aesRoundKeysLen256 = aesBlockLen * (aesNr256 + 1)

type
  AesBlock* = array[aesBlockLen, uint8]

  Aes256Ctx* = object
    roundKeys: array[aesRoundKeysLen256, uint8]

const
  sbox: array[256, uint8] = [
    0x63'u8, 0x7c'u8, 0x77'u8, 0x7b'u8, 0xf2'u8, 0x6b'u8, 0x6f'u8, 0xc5'u8,
    0x30'u8, 0x01'u8, 0x67'u8, 0x2b'u8, 0xfe'u8, 0xd7'u8, 0xab'u8, 0x76'u8,
    0xca'u8, 0x82'u8, 0xc9'u8, 0x7d'u8, 0xfa'u8, 0x59'u8, 0x47'u8, 0xf0'u8,
    0xad'u8, 0xd4'u8, 0xa2'u8, 0xaf'u8, 0x9c'u8, 0xa4'u8, 0x72'u8, 0xc0'u8,
    0xb7'u8, 0xfd'u8, 0x93'u8, 0x26'u8, 0x36'u8, 0x3f'u8, 0xf7'u8, 0xcc'u8,
    0x34'u8, 0xa5'u8, 0xe5'u8, 0xf1'u8, 0x71'u8, 0xd8'u8, 0x31'u8, 0x15'u8,
    0x04'u8, 0xc7'u8, 0x23'u8, 0xc3'u8, 0x18'u8, 0x96'u8, 0x05'u8, 0x9a'u8,
    0x07'u8, 0x12'u8, 0x80'u8, 0xe2'u8, 0xeb'u8, 0x27'u8, 0xb2'u8, 0x75'u8,
    0x09'u8, 0x83'u8, 0x2c'u8, 0x1a'u8, 0x1b'u8, 0x6e'u8, 0x5a'u8, 0xa0'u8,
    0x52'u8, 0x3b'u8, 0xd6'u8, 0xb3'u8, 0x29'u8, 0xe3'u8, 0x2f'u8, 0x84'u8,
    0x53'u8, 0xd1'u8, 0x00'u8, 0xed'u8, 0x20'u8, 0xfc'u8, 0xb1'u8, 0x5b'u8,
    0x6a'u8, 0xcb'u8, 0xbe'u8, 0x39'u8, 0x4a'u8, 0x4c'u8, 0x58'u8, 0xcf'u8,
    0xd0'u8, 0xef'u8, 0xaa'u8, 0xfb'u8, 0x43'u8, 0x4d'u8, 0x33'u8, 0x85'u8,
    0x45'u8, 0xf9'u8, 0x02'u8, 0x7f'u8, 0x50'u8, 0x3c'u8, 0x9f'u8, 0xa8'u8,
    0x51'u8, 0xa3'u8, 0x40'u8, 0x8f'u8, 0x92'u8, 0x9d'u8, 0x38'u8, 0xf5'u8,
    0xbc'u8, 0xb6'u8, 0xda'u8, 0x21'u8, 0x10'u8, 0xff'u8, 0xf3'u8, 0xd2'u8,
    0xcd'u8, 0x0c'u8, 0x13'u8, 0xec'u8, 0x5f'u8, 0x97'u8, 0x44'u8, 0x17'u8,
    0xc4'u8, 0xa7'u8, 0x7e'u8, 0x3d'u8, 0x64'u8, 0x5d'u8, 0x19'u8, 0x73'u8,
    0x60'u8, 0x81'u8, 0x4f'u8, 0xdc'u8, 0x22'u8, 0x2a'u8, 0x90'u8, 0x88'u8,
    0x46'u8, 0xee'u8, 0xb8'u8, 0x14'u8, 0xde'u8, 0x5e'u8, 0x0b'u8, 0xdb'u8,
    0xe0'u8, 0x32'u8, 0x3a'u8, 0x0a'u8, 0x49'u8, 0x06'u8, 0x24'u8, 0x5c'u8,
    0xc2'u8, 0xd3'u8, 0xac'u8, 0x62'u8, 0x91'u8, 0x95'u8, 0xe4'u8, 0x79'u8,
    0xe7'u8, 0xc8'u8, 0x37'u8, 0x6d'u8, 0x8d'u8, 0xd5'u8, 0x4e'u8, 0xa9'u8,
    0x6c'u8, 0x56'u8, 0xf4'u8, 0xea'u8, 0x65'u8, 0x7a'u8, 0xae'u8, 0x08'u8,
    0xba'u8, 0x78'u8, 0x25'u8, 0x2e'u8, 0x1c'u8, 0xa6'u8, 0xb4'u8, 0xc6'u8,
    0xe8'u8, 0xdd'u8, 0x74'u8, 0x1f'u8, 0x4b'u8, 0xbd'u8, 0x8b'u8, 0x8a'u8,
    0x70'u8, 0x3e'u8, 0xb5'u8, 0x66'u8, 0x48'u8, 0x03'u8, 0xf6'u8, 0x0e'u8,
    0x61'u8, 0x35'u8, 0x57'u8, 0xb9'u8, 0x86'u8, 0xc1'u8, 0x1d'u8, 0x9e'u8,
    0xe1'u8, 0xf8'u8, 0x98'u8, 0x11'u8, 0x69'u8, 0xd9'u8, 0x8e'u8, 0x94'u8,
    0x9b'u8, 0x1e'u8, 0x87'u8, 0xe9'u8, 0xce'u8, 0x55'u8, 0x28'u8, 0xdf'u8,
    0x8c'u8, 0xa1'u8, 0x89'u8, 0x0d'u8, 0xbf'u8, 0xe6'u8, 0x42'u8, 0x68'u8,
    0x41'u8, 0x99'u8, 0x2d'u8, 0x0f'u8, 0xb0'u8, 0x54'u8, 0xbb'u8, 0x16'u8
  ]

  rcon: array[11, uint8] = [
    0x00'u8, 0x01'u8, 0x02'u8, 0x04'u8, 0x08'u8, 0x10'u8,
    0x20'u8, 0x40'u8, 0x80'u8, 0x1b'u8, 0x36'u8
  ]

{.push overflowChecks: off.}
proc ctEq(a, b: uint8): uint8 {.inline.} =
  ## Returns 0xFF when equal, 0x00 otherwise (constant-time).
  let x = a xor b
  result = uint8((uint16(x) - 1'u16) shr 8)

proc sboxCt(x: uint8): uint8 {.inline.} =
  ## Constant-time S-box lookup by scanning all entries.
  var acc: uint8 = 0
  var i = 0
  while i < 256:
    let mask = ctEq(x, uint8(i))
    acc = acc or (sbox[i] and mask)
    i = i + 1
  result = acc
{.pop.}

proc subByte(x: uint8): uint8 {.inline.} =
  when defined(unsafeFastAes):
    result = sbox[x]
  else:
    result = sboxCt(x)

proc xtime(x: uint8): uint8 {.inline.} =
  let shifted = uint8(x shl 1)
  let carry = (x shr 7) and 0x1'u8
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

proc shiftRows(state: var AesBlock) =
  var t: uint8
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
  var c: int = 0
  var a0, a1, a2, a3: uint8
  c = 0
  while c < 4:
    let o = c * 4
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
  let base = round * aesBlockLen
  var i: int = 0
  i = 0
  while i < aesBlockLen:
    state[i] = state[i] xor roundKeys[base + i]
    i = i + 1

proc expandKey256(key: openArray[uint8]): array[aesRoundKeysLen256, uint8] =
  if key.len != aesKeyLen256:
    raise newException(ValueError, "AES-256 requires 32-byte key")
  var bytesGenerated = 0
  var rconIter = 1
  var temp: array[4, uint8]
  while bytesGenerated < aesKeyLen256:
    result[bytesGenerated] = key[bytesGenerated]
    bytesGenerated = bytesGenerated + 1
  while bytesGenerated < aesRoundKeysLen256:
    temp[0] = result[bytesGenerated - 4]
    temp[1] = result[bytesGenerated - 3]
    temp[2] = result[bytesGenerated - 2]
    temp[3] = result[bytesGenerated - 1]
    if (bytesGenerated mod aesKeyLen256) == 0:
      let t0 = temp[0]
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
    var j: int = 0
    j = 0
    while j < 4:
      result[bytesGenerated] = result[bytesGenerated - aesKeyLen256] xor temp[j]
      bytesGenerated = bytesGenerated + 1
      j = j + 1

proc init*(ctx: var Aes256Ctx, key: openArray[uint8]) =
  ctx.roundKeys = expandKey256(key)

proc encryptBlock*(ctx: Aes256Ctx, input: AesBlock): AesBlock =
  var state = input
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
