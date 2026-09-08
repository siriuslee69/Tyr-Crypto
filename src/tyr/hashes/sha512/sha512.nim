## ------------------------------------------------------------------
## SHA-512 / SHA-384 <- FIPS 180-4 64-bit digests for WebPKI signatures
## ------------------------------------------------------------------
##
## Needed because real certificate chains sign with `sha384WithRSA` and
## `ecdsa-with-SHA384`; SHA-384 is SHA-512 with a different initial state
## and a truncated output.

import tyrPragmas
import ../../kems/x25519/x25519_common

const
  sha512BlockBytes* = 128
  sha512DigestBytes* = 64
  sha384DigestBytes* = 48

  sha512Initial: array[8, uint64] = [
    0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64,
    0xa54ff53a5f1d36f1'u64, 0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
    0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
  ]

  sha384Initial: array[8, uint64] = [
    0xcbbb9d5dc1059ed8'u64, 0x629a292a367cd507'u64, 0x9159015a3070dd17'u64,
    0x152fecd8f70e5939'u64, 0x67332667ffc00b31'u64, 0x8eb44a8768581511'u64,
    0xdb0c2e0d64f98fa7'u64, 0x47b5481dbefa4fa4'u64
  ]

  sha512Round: array[80, uint64] = [
    0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64, 0xb5c0fbcfec4d3b2f'u64,
    0xe9b5dba58189dbbc'u64, 0x3956c25bf348b538'u64, 0x59f111f1b605d019'u64,
    0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64, 0xd807aa98a3030242'u64,
    0x12835b0145706fbe'u64, 0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64,
    0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64, 0x9bdc06a725c71235'u64,
    0xc19bf174cf692694'u64, 0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64,
    0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64, 0x2de92c6f592b0275'u64,
    0x4a7484aa6ea6e483'u64, 0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64,
    0x983e5152ee66dfab'u64, 0xa831c66d2db43210'u64, 0xb00327c898fb213f'u64,
    0xbf597fc7beef0ee4'u64, 0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64,
    0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64, 0x27b70a8546d22ffc'u64,
    0x2e1b21385c26c926'u64, 0x4d2c6dfc5ac42aed'u64, 0x53380d139d95b3df'u64,
    0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64, 0x81c2c92e47edaee6'u64,
    0x92722c851482353b'u64, 0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64,
    0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64, 0xd192e819d6ef5218'u64,
    0xd69906245565a910'u64, 0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64,
    0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64, 0x2748774cdf8eeb99'u64,
    0x34b0bcb5e19b48a8'u64, 0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64,
    0x5b9cca4f7763e373'u64, 0x682e6ff3d6b2b8a3'u64, 0x748f82ee5defb2fc'u64,
    0x78a5636f43172f60'u64, 0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
    0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64, 0xbef9a3f7b2c67915'u64,
    0xc67178f2e372532b'u64, 0xca273eceea26619c'u64, 0xd186b8c721c0c207'u64,
    0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64, 0x06f067aa72176fba'u64,
    0x0a637dc5a2c898a6'u64, 0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64,
    0x28db77f523047d84'u64, 0x32caab7b40c72493'u64, 0x3c9ebe0a15c9bebc'u64,
    0x431d67c49c100d4c'u64, 0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64,
    0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64
  ]

type
  Sha512Context* {.role: {memory}.} = object
    state*: array[8, uint64]
    buffer*: array[sha512BlockBytes, byte]
    bufferLen*: int
    lengthLow*: uint64   # message length in bits, low 64
    lengthHigh*: uint64  # message length in bits, high 64

  Sha512Digest* = array[sha512DigestBytes, byte]
  Sha384Digest* = array[sha384DigestBytes, byte]

proc rotr64(v: uint64, n: int): uint64 {.inline, role: {math}.} =
  ## v/n: value and rotation amount in the range 1..63.
  result = (v shr uint64(n)) or (v shl uint64(64 - n))

proc load64Be(A: openArray[byte], o: int): uint64 {.inline, role: {helper}.} =
  ## A/o: source bytes and big-endian word offset.
  var i: int = 0
  while i < 8:
    result = (result shl 8) or uint64(A[o + i])
    i = i + 1

proc store64Be(A: var openArray[byte], o: int, v: uint64) {.inline,
    role: {helper}.} =
  ## A/o/v: destination, big-endian word offset, and value.
  var i: int = 0
  while i < 8:
    A[o + i] = byte((v shr uint64(56 - 8 * i)) and 0xff'u64)
    i = i + 1

proc compressSha512(S: var Sha512Context, A: openArray[byte], o: int) {.
    role: {math}.} =
  ## S/A/o: running state, source bytes, and the offset of one 128-byte block.
  var
    W: array[80, uint64]
    a, b, c, d, e, f, g, h, s0, s1, ch, maj, t1, t2: uint64 = 0
    i: int = 0
  while i < 16:
    W[i] = load64Be(A, o + i * 8)
    i = i + 1
  while i < 80:
    s0 = rotr64(W[i - 15], 1) xor rotr64(W[i - 15], 8) xor (W[i - 15] shr 7'u64)
    s1 = rotr64(W[i - 2], 19) xor rotr64(W[i - 2], 61) xor (W[i - 2] shr 6'u64)
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
  while i < 80:
    s1 = rotr64(e, 14) xor rotr64(e, 18) xor rotr64(e, 41)
    ch = (e and f) xor ((not e) and g)
    t1 = h + s1 + ch + sha512Round[i] + W[i]
    s0 = rotr64(a, 28) xor rotr64(a, 34) xor rotr64(a, 39)
    maj = (a and b) xor (a and c) xor (b and c)
    t2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
    i = i + 1
  S.state[0] = S.state[0] + a
  S.state[1] = S.state[1] + b
  S.state[2] = S.state[2] + c
  S.state[3] = S.state[3] + d
  S.state[4] = S.state[4] + e
  S.state[5] = S.state[5] + f
  S.state[6] = S.state[6] + g
  S.state[7] = S.state[7] + h
  secureClearPod(W)

proc initSha512*(): Sha512Context {.role: {helper}.} =
  ## Return a context seeded with the SHA-512 initial state.
  result.state = sha512Initial
  result.bufferLen = 0

proc initSha384*(): Sha512Context {.role: {helper}.} =
  ## Return a context seeded with the SHA-384 initial state.
  result.state = sha384Initial
  result.bufferLen = 0

proc addSha512Length(S: var Sha512Context, n: int) {.role: {math}.} =
  ## S/n: running 128-bit bit length and the byte count to add.
  var
    addedLow: uint64 = uint64(n) shl 3'u64
    addedHigh: uint64 = uint64(n) shr 61'u64
    highAfterAdd: uint64 = 0
    carry: uint64 = 0
  if S.lengthLow > high(uint64) - addedLow:
    carry = 1'u64
  if S.lengthHigh > high(uint64) - addedHigh:
    raise newException(ValueError, "SHA-512 message length exceeds 2^128-1 bits")
  highAfterAdd = S.lengthHigh + addedHigh
  if carry != 0'u64 and highAfterAdd == high(uint64):
    raise newException(ValueError, "SHA-512 message length exceeds 2^128-1 bits")
  S.lengthLow = S.lengthLow + addedLow
  S.lengthHigh = highAfterAdd + carry

proc updateSha512*(S: var Sha512Context, A: openArray[byte]) {.role: {math}.} =
  ## S/A: running context and the next message chunk.
  var
    i, take: int = 0
  S.addSha512Length(A.len)
  while i < A.len:
    take = min(sha512BlockBytes - S.bufferLen, A.len - i)
    copyMem(addr S.buffer[S.bufferLen], unsafeAddr A[i], take)
    S.bufferLen = S.bufferLen + take
    i = i + take
    if S.bufferLen == sha512BlockBytes:
      compressSha512(S, S.buffer, 0)
      S.bufferLen = 0

proc finishSha512*(S: Sha512Context): Sha512Digest {.role: {math}.} =
  ## S: context copied so the caller's running state is left intact.
  var
    T: Sha512Context = S
    pad: int = 0
    i: int = 0
  # FIPS 180-4 padding: 0x80, zeroes, then a 128-bit big-endian bit length.
  T.buffer[T.bufferLen] = 0x80'u8
  T.bufferLen = T.bufferLen + 1
  if T.bufferLen > sha512BlockBytes - 16:
    pad = sha512BlockBytes - T.bufferLen
    while pad > 0:
      T.buffer[T.bufferLen] = 0'u8
      T.bufferLen = T.bufferLen + 1
      pad = pad - 1
    compressSha512(T, T.buffer, 0)
    T.bufferLen = 0
  while T.bufferLen < sha512BlockBytes - 16:
    T.buffer[T.bufferLen] = 0'u8
    T.bufferLen = T.bufferLen + 1
  store64Be(T.buffer, sha512BlockBytes - 16, T.lengthHigh)
  store64Be(T.buffer, sha512BlockBytes - 8, T.lengthLow)
  compressSha512(T, T.buffer, 0)
  i = 0
  while i < 8:
    store64Be(result, i * 8, T.state[i])
    i = i + 1
  secureClearPod(T)

proc finishSha384*(S: Sha512Context): Sha384Digest {.role: {math}.} =
  ## S: SHA-384 context copied and finalized to its 384-bit digest.
  var
    full: Sha512Digest = S.finishSha512()
    i: int = 0
  while i < result.len:
    result[i] = full[i]
    i = i + 1
  secureClearPod(full)

proc sha512Hash*(A: openArray[byte]): Sha512Digest {.role: {math}.} =
  ## A: complete message to hash.
  var S: Sha512Context = initSha512()
  S.updateSha512(A)
  result = S.finishSha512()
  secureClearPod(S)

proc sha384Hash*(A: openArray[byte]): Sha384Digest {.role: {math}.} =
  ## A: complete message to hash.
  var
    S: Sha512Context = initSha384()
  S.updateSha512(A)
  result = S.finishSha384()
  secureClearPod(S)
