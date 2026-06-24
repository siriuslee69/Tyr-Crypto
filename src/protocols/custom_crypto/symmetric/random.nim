## -----------------------------------------------------------
## Random <- mixed system entropy helper in the symmetric layer
## -----------------------------------------------------------

import std/sysrand
import ../xchacha20

const
  rngContext = "tyr-crypto-random-v1"
  blockLen = 16
  seedLen = 64

proc appendStringBytes(dst: var seq[uint8], value: string) =
  var
    start: int = 0
    i: int = 0
  start = dst.len
  dst.setLen(start + value.len)
  i = 0
  while i < value.len:
    dst[start + i] = uint8(ord(value[i]))
    i = i + 1

proc appendBytes(dst: var seq[uint8], value: openArray[uint8]) =
  var
    start: int = 0
    i: int = 0
  if value.len == 0:
    return
  start = dst.len
  dst.setLen(start + value.len)
  i = 0
  while i < value.len:
    dst[start + i] = value[i]
    i = i + 1

proc appendUint64Le(dst: var seq[uint8], value: uint64) =
  var
    start: int = 0
    i: int = 0
  start = dst.len
  dst.setLen(start + 8)
  i = 0
  while i < 8:
    dst[start + i] = uint8((value shr (i * 8)) and 0xff'u64)
    i = i + 1

proc toByteSeq[T](input: openArray[T]): seq[uint8] =
  var i: int = 0
  static:
    doAssert sizeof(T) == 1, "extra entropy must use a 1-byte element type"
  result = newSeq[uint8](input.len)
  i = 0
  while i < input.len:
    result[i] = cast[uint8](input[i])
    i = i + 1

proc toArray32(data: openArray[uint8], start: int): array[32, byte] =
  var i: int = 0
  i = 0
  while i < result.len:
    result[i] = byte(data[start + i])
    i = i + 1

proc toArray16(data: openArray[uint8], start: int): array[16, byte] =
  var i: int = 0
  i = 0
  while i < result.len:
    result[i] = byte(data[start + i])
    i = i + 1

proc absorbEntropy(keyState: var array[32, byte], data: openArray[uint8]) =
  var
    offset: int = 0
    take: int = 0
    i: int = 0
    chunk: array[blockLen, byte]
  if data.len == 0:
    chunk[0] = 0x80'u8
    keyState = hchacha20(keyState, chunk)
    return

  offset = 0
  while offset < data.len:
    chunk = default(array[blockLen, byte])
    take = min(chunk.len, data.len - offset)
    i = 0
    while i < take:
      chunk[i] = byte(data[offset + i])
      i = i + 1
    if take < chunk.len:
      chunk[take] = 0x80'u8
    chunk[chunk.high] = chunk[chunk.high] xor byte(take)
    keyState = hchacha20(keyState, chunk)
    offset += take

proc buildMixMaterial(length: int, extraEntropy: openArray[uint8]): seq[uint8] =
  result = newSeqOfCap[uint8](rngContext.len + 16 + extraEntropy.len)
  appendStringBytes(result, rngContext)
  appendUint64Le(result, uint64(length))
  appendUint64Le(result, uint64(extraEntropy.len))
  appendBytes(result, extraEntropy)

proc cryptoRandomBytesInternal(length: int, extraEntropy: openArray[uint8]): seq[uint8] =
  var
    osSeed: seq[uint8]
    osOutput: seq[uint8]
    keyState: array[32, byte]
    nonceBase: array[16, byte]
    nonceDerive: array[16, byte]
    mixMaterial: seq[uint8]
    nonceTail: array[32, byte]
    streamNonce: array[xchacha20NonceSize, byte]
    stream: seq[uint8]
    i: int = 0
  if length < 0:
    raise newException(ValueError, "length must be >= 0")
  if length == 0:
    return @[]

  osSeed = urandom(seedLen)
  osOutput = urandom(length)

  keyState = toArray32(osSeed, 0)
  nonceBase = toArray16(osSeed, 32)
  nonceDerive = toArray16(osSeed, 48)

  mixMaterial = buildMixMaterial(length, extraEntropy)
  absorbEntropy(keyState, mixMaterial)

  nonceTail = hchacha20(keyState, nonceDerive)
  i = 0
  while i < nonceBase.len:
    streamNonce[i] = nonceBase[i]
    i = i + 1
  i = 0
  while i < 8:
    streamNonce[16 + i] = nonceTail[24 + i]
    i = i + 1

  stream = xchacha20Stream(keyState, streamNonce, length)
  result = newSeq[uint8](length)
  i = 0
  while i < length:
    result[i] = uint8(stream[i]) xor osOutput[i]
    i = i + 1

proc cryptoRandomBytes*(length: int): seq[uint8] =
  ## Generates cryptographically strong random bytes from OS randomness.
  cryptoRandomBytesInternal(length, @[])

proc cryptoRandomBytes*[T](length: int, extraEntropy: openArray[T]): seq[uint8] =
  ## Generates cryptographically strong random bytes and mixes in caller entropy.
  ## Use `extraEntropy` for high-variance data (for example user timing jitter or
  ## server runtime telemetry) to diversify the output stream.
  var extraBytes: seq[uint8]
  extraBytes = toByteSeq(extraEntropy)
  cryptoRandomBytesInternal(length, extraBytes)
