import std/bitops
import ./chacha20

const
  xchacha20NonceSize* = 24
  hchacha20InputSize = 16
  sigma = [0x61707865'u32, 0x3320646e'u32, 0x79622d32'u32, 0x6b206574'u32]

proc load32Le(data: openArray[byte], offset: int): uint32 =
  result =
    (uint32(data[offset]) or
    (uint32(data[offset + 1]) shl 8) or
    (uint32(data[offset + 2]) shl 16) or
    (uint32(data[offset + 3]) shl 24))

proc store32Le(dst: var array[32, byte], offset: int, value: uint32) {.inline.} =
  dst[offset] = byte(value and 0xff'u32)
  dst[offset + 1] = byte((value shr 8) and 0xff'u32)
  dst[offset + 2] = byte((value shr 16) and 0xff'u32)
  dst[offset + 3] = byte((value shr 24) and 0xff'u32)

proc quarterRound(a, b, c, d: var uint32) {.inline.} =
  a = a + b
  d = rotateLeftBits(d xor a, 16)
  c = c + d
  b = rotateLeftBits(b xor c, 12)
  a = a + b
  d = rotateLeftBits(d xor a, 8)
  c = c + d
  b = rotateLeftBits(b xor c, 7)

proc hchacha20*(key, nonce: openArray[byte]): array[32, byte] =
  ## HChaCha20 core to derive a subkey for XChaCha20.
  if key.len != 32:
    raise newException(ValueError, "HChaCha20 requires a 32-byte key")
  if nonce.len != hchacha20InputSize:
    raise newException(ValueError, "HChaCha20 requires a 16-byte nonce")

  var state: array[16, uint32]
  for i in 0 .. 3:
    state[i] = sigma[i]
  for i in 0 .. 7:
    state[4 + i] = load32Le(key, i * 4)
  for i in 0 .. 3:
    state[12 + i] = load32Le(nonce, i * 4)

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

  for i in 0 .. 3:
    store32Le(result, i * 4, working[i])
  for i in 0 .. 3:
    store32Le(result, 16 + i * 4, working[12 + i])

proc deriveXChaCha20Key(key, nonce: openArray[byte]): array[32, byte] =
  var hnonce: array[hchacha20InputSize, byte]
  for i in 0 ..< hnonce.len:
    hnonce[i] = nonce[i]
  hchacha20(key, hnonce)

proc buildChaChaNonce(nonce: openArray[byte]): array[12, byte] =
  for i in 0 ..< 8:
    result[4 + i] = nonce[16 + i]

proc xchacha20Xor*(key, nonce: openArray[byte], initialCounter: uint32,
                   input: openArray[byte]): seq[byte] =
  ## Encrypts/decrypts input using XChaCha20.
  if key.len != 32:
    raise newException(ValueError, "XChaCha20 requires a 32-byte key")
  if nonce.len != xchacha20NonceSize:
    raise newException(ValueError, "XChaCha20 requires a 24-byte nonce")

  let subkey = deriveXChaCha20Key(key, nonce)
  let chachaNonce = buildChaChaNonce(nonce)
  chacha20Xor(subkey, chachaNonce, initialCounter, input)

proc xchacha20Xor*(key, nonce: openArray[byte], input: openArray[byte]): seq[byte] =
  ## Convenience overload that starts from counter zero.
  xchacha20Xor(key, nonce, 0'u32, input)

proc xchacha20XorInPlace*(key, nonce: openArray[byte], initialCounter: uint32,
                          buffer: var openArray[byte]) =
  ## In-place XChaCha20 transform to avoid an extra allocation.
  if key.len != 32:
    raise newException(ValueError, "XChaCha20 requires a 32-byte key")
  if nonce.len != xchacha20NonceSize:
    raise newException(ValueError, "XChaCha20 requires a 24-byte nonce")

  let subkey = deriveXChaCha20Key(key, nonce)
  let chachaNonce = buildChaChaNonce(nonce)
  chacha20XorInPlace(subkey, chachaNonce, initialCounter, buffer)

proc xchacha20Stream*(key, nonce: openArray[byte], length: int,
                      initialCounter: uint32 = 0'u32): seq[byte] =
  ## Generates an XChaCha20 keystream of requested length.
  if length < 0:
    raise newException(ValueError, "length must be non-negative")
  var zeros = newSeq[byte](length)
  xchacha20Xor(key, nonce, initialCounter, zeros)
