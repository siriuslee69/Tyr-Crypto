## ---------------------------------------------------------------------
## SHA-256 <- incremental FIPS 180-4 hash plus HMAC and RFC 5869 HKDF
## ---------------------------------------------------------------------

import std/bitops
import metaPragmas
import ../secure_memory

const
  sha256BlockBytes* = 64
  sha256DigestBytes* = 32
  sha256Initial: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]
  sha256Round: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
    0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
    0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
    0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
    0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
    0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
    0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
    0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
    0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]

type
  Sha256Digest* = array[sha256DigestBytes, byte]
  Sha256Context* = object
    state: array[8, uint32]
    buffer: array[sha256BlockBytes, byte]
    bufferLen: int
    totalBytes: uint64

proc load32Be(A: openArray[byte], o: int): uint32 {.inline, role: {helper}.} =
  result = (uint32(A[o]) shl 24) or (uint32(A[o + 1]) shl 16) or
    (uint32(A[o + 2]) shl 8) or uint32(A[o + 3])

proc store32Be(A: var openArray[byte], o: int, v: uint32) {.inline, role: {helper}.} =
  A[o] = byte(v shr 24)
  A[o + 1] = byte(v shr 16)
  A[o + 2] = byte(v shr 8)
  A[o + 3] = byte(v)

proc compressSha256(S: var Sha256Context, A: openArray[byte], o: int) {.role: {math}.} =
  var
    W: array[64, uint32]
    a, b, c, d, e, f, g, h: uint32 = 0
    s0, s1, ch, maj, t0, t1: uint32 = 0
    i: int = 0
  defer:
    secureClearPod(W)
  while i < 16:
    W[i] = load32Be(A, o + i * 4)
    i = i + 1
  while i < 64:
    s0 = rotateRightBits(W[i - 15], 7) xor rotateRightBits(W[i - 15], 18) xor
      (W[i - 15] shr 3)
    s1 = rotateRightBits(W[i - 2], 17) xor rotateRightBits(W[i - 2], 19) xor
      (W[i - 2] shr 10)
    W[i] = W[i - 16] + s0 + W[i - 7] + s1
    i = i + 1
  a = S.state[0]
  b = S.state[1]
  c = S.state[2]
  d = S.state[3]
  e = S.state[4]
  f = S.state[5]
  g = S.state[6]
  h = S.state[7]
  i = 0
  while i < 64:
    s1 = rotateRightBits(e, 6) xor rotateRightBits(e, 11) xor rotateRightBits(e, 25)
    ch = (e and f) xor ((not e) and g)
    t0 = h + s1 + ch + sha256Round[i] + W[i]
    s0 = rotateRightBits(a, 2) xor rotateRightBits(a, 13) xor rotateRightBits(a, 22)
    maj = (a and b) xor (a and c) xor (b and c)
    t1 = s0 + maj
    h = g
    g = f
    f = e
    e = d + t0
    d = c
    c = b
    b = a
    a = t0 + t1
    i = i + 1
  S.state[0] = S.state[0] + a
  S.state[1] = S.state[1] + b
  S.state[2] = S.state[2] + c
  S.state[3] = S.state[3] + d
  S.state[4] = S.state[4] + e
  S.state[5] = S.state[5] + f
  S.state[6] = S.state[6] + g
  S.state[7] = S.state[7] + h

proc initSha256*(): Sha256Context {.role: {helper}.} =
  ## Initialize reusable incremental SHA-256 state.
  result.state = sha256Initial

proc updateSha256*(S: var Sha256Context, A: openArray[byte]) {.role: {math}.} =
  ## S: hash state to mutate. A: next message bytes.
  var
    o, n, i: int = 0
  if S.totalBytes > uint64.high div 8'u64 or
      uint64(A.len) > (uint64.high div 8'u64 - S.totalBytes):
    raise newException(ValueError, "SHA-256 input length overflow")
  S.totalBytes = S.totalBytes + uint64(A.len)
  while o < A.len:
    n = min(sha256BlockBytes - S.bufferLen, A.len - o)
    i = 0
    while i < n:
      S.buffer[S.bufferLen + i] = A[o + i]
      i = i + 1
    S.bufferLen = S.bufferLen + n
    o = o + n
    if S.bufferLen == sha256BlockBytes:
      compressSha256(S, S.buffer, 0)
      S.bufferLen = 0

proc finishSha256*(S: Sha256Context): Sha256Digest {.role: {math}.} =
  ## Finalize a copy so callers may clone transcript state by assignment.
  var
    T: Sha256Context = S
    bitLen: uint64 = 0
    i: int = 0
  bitLen = T.totalBytes * 8'u64
  T.buffer[T.bufferLen] = 0x80'u8
  T.bufferLen = T.bufferLen + 1
  if T.bufferLen > 56:
    while T.bufferLen < sha256BlockBytes:
      T.buffer[T.bufferLen] = 0'u8
      T.bufferLen = T.bufferLen + 1
    compressSha256(T, T.buffer, 0)
    T.bufferLen = 0
  while T.bufferLen < 56:
    T.buffer[T.bufferLen] = 0'u8
    T.bufferLen = T.bufferLen + 1
  i = 0
  while i < 8:
    T.buffer[63 - i] = byte(bitLen shr (i * 8))
    i = i + 1
  compressSha256(T, T.buffer, 0)
  i = 0
  while i < 8:
    store32Be(result, i * 4, T.state[i])
    i = i + 1
  secureClearPod(T)

proc sha256Hash*(A: openArray[byte]): Sha256Digest {.role: {math}.} =
  ## A: complete message to hash.
  var S: Sha256Context = initSha256()
  S.updateSha256(A)
  result = S.finishSha256()
  secureClearPod(S)

proc hmacSha256*(key, msg: openArray[byte]): Sha256Digest {.role: {math}.} =
  ## key/msg: RFC 2104 HMAC-SHA-256 inputs.
  var
    K, I, O: array[sha256BlockBytes, byte]
    D: Sha256Digest
    S: Sha256Context
    i: int = 0
  defer:
    secureClearBytes(K)
    secureClearBytes(I)
    secureClearBytes(O)
    secureClearBytes(D)
    secureClearPod(S)
  if key.len > sha256BlockBytes:
    D = sha256Hash(key)
    while i < D.len:
      K[i] = D[i]
      i = i + 1
  else:
    while i < key.len:
      K[i] = key[i]
      i = i + 1
  i = 0
  while i < sha256BlockBytes:
    I[i] = K[i] xor 0x36'u8
    O[i] = K[i] xor 0x5c'u8
    i = i + 1
  S = initSha256()
  S.updateSha256(I)
  S.updateSha256(msg)
  D = S.finishSha256()
  S = initSha256()
  S.updateSha256(O)
  S.updateSha256(D)
  result = S.finishSha256()

proc hkdfSha256Extract*(salt, ikm: openArray[byte]): Sha256Digest {.role: {math}.} =
  ## salt/ikm: RFC 5869 extraction inputs; an empty salt means 32 zero bytes.
  var Z: array[sha256DigestBytes, byte]
  if salt.len == 0:
    result = hmacSha256(Z, ikm)
  else:
    result = hmacSha256(salt, ikm)
  secureClearBytes(Z)

proc hkdfSha256Expand*(prk, info: openArray[byte], outLen: int): seq[byte] {.role: {math}.} =
  ## prk/info/outLen: RFC 5869 expansion inputs.
  var
    T: Sha256Digest
    M: seq[byte] = @[]
    generated, take, i: int = 0
    counter: byte = 1'u8
  if prk.len < sha256DigestBytes:
    raise newException(ValueError, "HKDF-SHA-256 PRK must be at least 32 bytes")
  if outLen < 0 or outLen > 255 * sha256DigestBytes:
    raise newException(ValueError, "HKDF-SHA-256 output length is invalid")
  result = newSeq[byte](outLen)
  while generated < outLen:
    M.setLen(0)
    if generated > 0:
      M.add(T)
    M.add(info)
    M.add(counter)
    T = hmacSha256(prk, M)
    take = min(T.len, outLen - generated)
    i = 0
    while i < take:
      result[generated + i] = T[i]
      i = i + 1
    generated = generated + take
    if generated < outLen:
      counter = counter + 1'u8
  secureClearBytes(T)
  secureClearBytes(M)

proc hkdfExpandLabelSha256*(secret: openArray[byte], label: string,
    context: openArray[byte], outLen: int): seq[byte] {.role: {dataWriter}.} =
  ## Build and expand the RFC 8446 HkdfLabel structure.
  var
    fullLabel: string = "tls13 " & label
    info: seq[byte] = @[]
    i: int = 0
  if outLen < 0 or outLen > 65535:
    raise newException(ValueError, "TLS HKDF label output length is invalid")
  if fullLabel.len < 7 or fullLabel.len > 255 or context.len > 255:
    raise newException(ValueError, "TLS HKDF label or context length is invalid")
  info.add(byte(outLen shr 8))
  info.add(byte(outLen))
  info.add(byte(fullLabel.len))
  while i < fullLabel.len:
    info.add(byte(ord(fullLabel[i])))
    i = i + 1
  info.add(byte(context.len))
  info.add(context)
  result = hkdfSha256Expand(secret, info, outLen)
  secureClearBytes(info)
