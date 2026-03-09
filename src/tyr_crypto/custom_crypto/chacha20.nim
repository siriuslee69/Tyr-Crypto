import std/bitops

const
  chacha20BlockSize* = 64
  sigma = [0x61707865'u32, 0x3320646e'u32, 0x79622d32'u32, 0x6b206574'u32]

proc load32Le(data: openArray[byte], offset: int): uint32 =
  result =
    (uint32(data[offset]) or
    (uint32(data[offset + 1]) shl 8) or
    (uint32(data[offset + 2]) shl 16) or
    (uint32(data[offset + 3]) shl 24))

proc quarterRound(a, b, c, d: var uint32) {.inline.} =
  a = a + b
  d = rotateLeftBits(d xor a, 16)
  c = c + d
  b = rotateLeftBits(b xor c, 12)
  a = a + b
  d = rotateLeftBits(d xor a, 8)
  c = c + d
  b = rotateLeftBits(b xor c, 7)

proc chacha20Block*(key: openArray[byte], nonce: openArray[byte], counter: uint32 = 0'u32): array[chacha20BlockSize, byte] =
  ## Returns a single 64-byte ChaCha20 keystream block using a 32-byte key,
  ## 12-byte nonce (IETF variant), and a 32-bit block counter.
  if key.len != 32:
    raise newException(ValueError, "ChaCha20 requires a 32-byte key")
  if nonce.len != 12:
    raise newException(ValueError, "ChaCha20 requires a 12-byte nonce")

  var state: array[16, uint32]
  for i in 0 .. 3:
    state[i] = sigma[i]
  for i in 0 .. 7:
    state[4 + i] = load32Le(key, i * 4)
  state[12] = counter
  state[13] = load32Le(nonce, 0)
  state[14] = load32Le(nonce, 4)
  state[15] = load32Le(nonce, 8)

  var working = state
  for _ in 0 ..< 10:
    quarterRound(working[0], working[4], working[8], working[12])
    quarterRound(working[1], working[5], working[9], working[13])
    quarterRound(working[2], working[6], working[10], working[14])
    quarterRound(working[3], working[7], working[11], working[15])

    quarterRound(working[0], working[5], working[10], working[15])
    quarterRound(working[1], working[6], working[11], working[12])
    quarterRound(working[2], working[7], working[8], working[13])
    quarterRound(working[3], working[4], working[9], working[14])

  for i in 0 ..< 16:
    working[i] = working[i] + state[i]
    let off = i * 4
    result[off] = byte(working[i] and 0xff'u32)
    result[off + 1] = byte((working[i] shr 8) and 0xff'u32)
    result[off + 2] = byte((working[i] shr 16) and 0xff'u32)
    result[off + 3] = byte((working[i] shr 24) and 0xff'u32)

proc chacha20Xor*(key, nonce: openArray[byte], initialCounter: uint32, input: openArray[byte]): seq[byte] =
  ## Encrypts/decrypts `input` with ChaCha20, returning a freshly allocated buffer.
  if key.len != 32:
    raise newException(ValueError, "ChaCha20 requires a 32-byte key")
  if nonce.len != 12:
    raise newException(ValueError, "ChaCha20 requires a 12-byte nonce")

  result = newSeq[byte](input.len)
  var blockCounter = initialCounter
  var offset = 0
  while offset < input.len:
    let keystream = chacha20Block(key, nonce, blockCounter)
    inc blockCounter
    let todo = min(chacha20BlockSize, input.len - offset)
    for i in 0 ..< todo:
      result[offset + i] = input[offset + i] xor keystream[i]
    offset += todo

proc chacha20Xor*(key, nonce: openArray[byte], input: openArray[byte]): seq[byte] =
  ## Convenience overload that starts from counter zero.
  chacha20Xor(key, nonce, 0'u32, input)

proc chacha20XorInPlace*(key, nonce: openArray[byte], initialCounter: uint32, buffer: var openArray[byte]) =
  ## In-place ChaCha20 transform to avoid an extra allocation.
  if key.len != 32:
    raise newException(ValueError, "ChaCha20 requires a 32-byte key")
  if nonce.len != 12:
    raise newException(ValueError, "ChaCha20 requires a 12-byte nonce")

  var blockCounter = initialCounter
  var offset = 0
  while offset < buffer.len:
    let keystream = chacha20Block(key, nonce, blockCounter)
    inc blockCounter
    let todo = min(chacha20BlockSize, buffer.len - offset)
    for i in 0 ..< todo:
      buffer[offset + i] = buffer[offset + i] xor keystream[i]
    offset += todo

when isMainModule:
  # RFC 8439 section 2.3.2 test vector
  const testKey: array[32, byte] = [
    byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  ]
  const testNonce: array[12, byte] = [
    byte 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
  ]
  let keystream = chacha20Block(testKey, testNonce, 1'u32)
  let expected: array[64, byte] = [
    byte 0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
    0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
    0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
    0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
    0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
  ]
  doAssert keystream == expected
