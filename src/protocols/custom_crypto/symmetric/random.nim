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
  let start = dst.len
  dst.setLen(start + value.len)
  for i, ch in value:
    dst[start + i] = uint8(ord(ch))

proc appendBytes(dst: var seq[uint8], value: openArray[uint8]) =
  if value.len == 0:
    return
  let start = dst.len
  dst.setLen(start + value.len)
  for i in 0 ..< value.len:
    dst[start + i] = value[i]

proc appendUint64Le(dst: var seq[uint8], value: uint64) =
  let start = dst.len
  dst.setLen(start + 8)
  for i in 0 ..< 8:
    dst[start + i] = uint8((value shr (i * 8)) and 0xff'u64)

proc toByteSeq[T](input: openArray[T]): seq[uint8] =
  static:
    doAssert sizeof(T) == 1, "extra entropy must use a 1-byte element type"
  result = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    result[i] = cast[uint8](input[i])

proc toArray32(data: openArray[uint8], start: int): array[32, byte] =
  for i in 0 ..< result.len:
    result[i] = byte(data[start + i])

proc toArray16(data: openArray[uint8], start: int): array[16, byte] =
  for i in 0 ..< result.len:
    result[i] = byte(data[start + i])

proc absorbEntropy(keyState: var array[32, byte], data: openArray[uint8]) =
  if data.len == 0:
    var chunk: array[blockLen, byte]
    chunk[0] = 0x80'u8
    keyState = hchacha20(keyState, chunk)
    return

  var offset = 0
  while offset < data.len:
    var chunk: array[blockLen, byte]
    let take = min(chunk.len, data.len - offset)
    for i in 0 ..< take:
      chunk[i] = byte(data[offset + i])
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
  if length < 0:
    raise newException(ValueError, "length must be >= 0")
  if length == 0:
    return @[]

  let osSeed = urandom(seedLen)
  let osOutput = urandom(length)

  var keyState = toArray32(osSeed, 0)
  let nonceBase = toArray16(osSeed, 32)
  let nonceDerive = toArray16(osSeed, 48)

  let mixMaterial = buildMixMaterial(length, extraEntropy)
  absorbEntropy(keyState, mixMaterial)

  let nonceTail = hchacha20(keyState, nonceDerive)
  var streamNonce: array[xchacha20NonceSize, byte]
  for i in 0 ..< nonceBase.len:
    streamNonce[i] = nonceBase[i]
  for i in 0 ..< 8:
    streamNonce[16 + i] = nonceTail[24 + i]

  let stream = xchacha20Stream(keyState, streamNonce, length)
  result = newSeq[uint8](length)
  for i in 0 ..< length:
    result[i] = uint8(stream[i]) xor osOutput[i]

proc cryptoRandomBytes*(length: int): seq[uint8] =
  ## Generates cryptographically strong random bytes from OS randomness.
  cryptoRandomBytesInternal(length, @[])

proc cryptoRandomBytes*[T](length: int, extraEntropy: openArray[T]): seq[uint8] =
  ## Generates cryptographically strong random bytes and mixes in caller entropy.
  ## Use `extraEntropy` for high-variance data (for example user timing jitter or
  ## server runtime telemetry) to diversify the output stream.
  let extraBytes = toByteSeq(extraEntropy)
  cryptoRandomBytesInternal(length, extraBytes)
