## ---------------------------------------------------------
## SHA3 <- scalar Keccak-f[1600] hashing with fixed variants
## ---------------------------------------------------------

import std/bitops

type
  ## Supported fixed-output SHA3 variants.
  Sha3Variant* = enum
    svSha3_224,
    svSha3_256,
    svSha3_384,
    svSha3_512

  ## Raw Keccak-f[1600] state as 25 little-endian 64-bit lanes.
  Sha3State* = array[25, uint64]

const
  sha3DomainSuffix = 0x06'u8
  shakeDomainSuffix = 0x1f'u8
  keccakLaneBytes = 8
  keccakRoundConstants: array[24, uint64] = [
    0x0000000000000001'u64, 0x0000000000008082'u64,
    0x800000000000808a'u64, 0x8000000080008000'u64,
    0x000000000000808b'u64, 0x0000000080000001'u64,
    0x8000000080008081'u64, 0x8000000000008009'u64,
    0x000000000000008a'u64, 0x0000000000000088'u64,
    0x0000000080008009'u64, 0x000000008000000a'u64,
    0x000000008000808b'u64, 0x800000000000008b'u64,
    0x8000000000008089'u64, 0x8000000000008003'u64,
    0x8000000000008002'u64, 0x8000000000000080'u64,
    0x000000000000800a'u64, 0x800000008000000a'u64,
    0x8000000080008081'u64, 0x8000000000008080'u64,
    0x0000000080000001'u64, 0x8000000080008008'u64
  ]
  keccakRhoOffsets: array[25, int32] = [
    0'i32, 1'i32, 62'i32, 28'i32, 27'i32,
    36'i32, 44'i32, 6'i32, 55'i32, 20'i32,
    3'i32, 10'i32, 43'i32, 25'i32, 39'i32,
    41'i32, 45'i32, 15'i32, 21'i32, 8'i32,
    18'i32, 2'i32, 61'i32, 56'i32, 14'i32
  ]

proc sha3DigestBytes*(v: Sha3Variant): int =
  ## Return the digest length in bytes for a fixed SHA3 variant.
  case v
  of svSha3_224:
    result = 28
  of svSha3_256:
    result = 32
  of svSha3_384:
    result = 48
  of svSha3_512:
    result = 64

proc sha3RateBytes*(v: Sha3Variant): int =
  ## Return the sponge rate in bytes for a fixed SHA3 variant.
  case v
  of svSha3_224:
    result = 144
  of svSha3_256:
    result = 136
  of svSha3_384:
    result = 104
  of svSha3_512:
    result = 72

proc sha3VariantFromOutLen*(outLen: int): Sha3Variant =
  ## Map the legacy output-length selector to a fixed SHA3 variant.
  case outLen
  of 28:
    result = svSha3_224
  of 32:
    result = svSha3_256
  of 48:
    result = svSha3_384
  of 64:
    result = svSha3_512
  else:
    raise newException(ValueError,
      "sha3 output length must be one of 28, 32, 48, or 64")

proc laneIdx(x, y: int): int {.inline.} =
  result = x + y * 5

proc load64Le(A: openArray[byte], o: int): uint64 {.inline.} =
  result =
    uint64(A[o]) or
    (uint64(A[o + 1]) shl 8) or
    (uint64(A[o + 2]) shl 16) or
    (uint64(A[o + 3]) shl 24) or
    (uint64(A[o + 4]) shl 32) or
    (uint64(A[o + 5]) shl 40) or
    (uint64(A[o + 6]) shl 48) or
    (uint64(A[o + 7]) shl 56)

proc store64Le(A: var openArray[byte], o: int, v: uint64) {.inline.} =
  A[o] = byte(v and 0xff'u64)
  A[o + 1] = byte((v shr 8) and 0xff'u64)
  A[o + 2] = byte((v shr 16) and 0xff'u64)
  A[o + 3] = byte((v shr 24) and 0xff'u64)
  A[o + 4] = byte((v shr 32) and 0xff'u64)
  A[o + 5] = byte((v shr 40) and 0xff'u64)
  A[o + 6] = byte((v shr 48) and 0xff'u64)
  A[o + 7] = byte((v shr 56) and 0xff'u64)

proc absorbBlock(S: var Sha3State, A: openArray[byte], o, rateBytes: int) =
  var
    lane: int = 0
    laneCount: int = 0
  laneCount = rateBytes div keccakLaneBytes
  lane = 0
  while lane < laneCount:
    S[lane] = S[lane] xor load64Le(A, o + lane * keccakLaneBytes)
    lane = lane + 1

proc absorbFinalBlockWithDomain(S: var Sha3State, A: openArray[byte], o, rateBytes: int,
    domain: byte) =
  var
    blk: seq[byte] = @[]
    take: int = 0
    i: int = 0
  blk = newSeq[byte](rateBytes)
  take = A.len - o
  if take < 0:
    take = 0
  i = 0
  while i < take:
    blk[i] = A[o + i]
    i = i + 1
  blk[take] = blk[take] xor domain
  blk[rateBytes - 1] = blk[rateBytes - 1] xor 0x80'u8
  absorbBlock(S, blk, 0, rateBytes)

proc keccakF1600Ref*(S: var Sha3State)

proc squeezeBytes(S0: Sha3State, outLen, rateBytes: int): seq[byte] =
  var
    S = S0
    i: int = 0
    laneBytes: array[8, byte]
    produced: int = 0
    take: int = 0
    blockBytes: int = 0
  result = newSeq[byte](outLen)
  while produced < outLen:
    blockBytes = rateBytes
    if blockBytes > outLen - produced:
      blockBytes = outLen - produced
    i = 0
    while i * keccakLaneBytes < blockBytes:
      store64Le(laneBytes, 0, S[i])
      take = blockBytes - i * keccakLaneBytes
      if take > keccakLaneBytes:
        take = keccakLaneBytes
      for j in 0 ..< take:
        result[produced + i * keccakLaneBytes + j] = laneBytes[j]
      i = i + 1
    produced = produced + blockBytes
    if produced < outLen:
      keccakF1600Ref(S)

proc absorbFinalBlock(S: var Sha3State, A: openArray[byte], o, rateBytes: int) =
  absorbFinalBlockWithDomain(S, A, o, rateBytes, sha3DomainSuffix)

proc keccakF1600Ref*(S: var Sha3State) =
  ## Apply the scalar Keccak-f[1600] permutation to a 25-lane state.
  var
    c: array[5, uint64]
    d: array[5, uint64]
    b: Sha3State
    round: int = 0
    x: int = 0
    y: int = 0
  round = 0
  while round < keccakRoundConstants.len:
    x = 0
    while x < 5:
      c[x] = S[laneIdx(x, 0)] xor S[laneIdx(x, 1)] xor S[laneIdx(x, 2)] xor
        S[laneIdx(x, 3)] xor S[laneIdx(x, 4)]
      x = x + 1
    x = 0
    while x < 5:
      d[x] = c[(x + 4) mod 5] xor rotateLeftBits(c[(x + 1) mod 5], 1)
      x = x + 1
    y = 0
    while y < 5:
      x = 0
      while x < 5:
        S[laneIdx(x, y)] = S[laneIdx(x, y)] xor d[x]
        x = x + 1
      y = y + 1
    y = 0
    while y < 5:
      x = 0
      while x < 5:
        b[laneIdx(y, (2 * x + 3 * y) mod 5)] =
          rotateLeftBits(S[laneIdx(x, y)], keccakRhoOffsets[laneIdx(x, y)])
        x = x + 1
      y = y + 1
    y = 0
    while y < 5:
      x = 0
      while x < 5:
        S[laneIdx(x, y)] = b[laneIdx(x, y)] xor
          ((not b[laneIdx((x + 1) mod 5, y)]) and b[laneIdx((x + 2) mod 5, y)])
        x = x + 1
      y = y + 1
    S[0] = S[0] xor keccakRoundConstants[round]
    round = round + 1

proc sha3Digest*(A: openArray[byte], v: Sha3Variant): seq[byte] =
  ## Hash `A` with the selected fixed SHA3 variant.
  var
    S: Sha3State
    rateBytes: int = 0
    offset: int = 0
  rateBytes = sha3RateBytes(v)
  offset = 0
  while offset + rateBytes <= A.len:
    absorbBlock(S, A, offset, rateBytes)
    keccakF1600Ref(S)
    offset = offset + rateBytes
  absorbFinalBlock(S, A, offset, rateBytes)
  keccakF1600Ref(S)
  result = squeezeBytes(S, sha3DigestBytes(v), rateBytes)

proc shake256*(A: openArray[byte], outLen: int): seq[byte] =
  ## SHAKE256 XOF over `A` with arbitrary `outLen`.
  var
    S: Sha3State
    rateBytes = 136
    offset: int = 0
  if outLen < 0:
    raise newException(ValueError, "shake256 output length must be >= 0")
  while offset + rateBytes <= A.len:
    absorbBlock(S, A, offset, rateBytes)
    keccakF1600Ref(S)
    offset = offset + rateBytes
  absorbFinalBlockWithDomain(S, A, offset, rateBytes, shakeDomainSuffix)
  keccakF1600Ref(S)
  result = squeezeBytes(S, outLen, rateBytes)

proc sha3_224*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-224.
  result = sha3Digest(A, svSha3_224)

proc sha3_256*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-256.
  result = sha3Digest(A, svSha3_256)

proc sha3_384*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-384.
  result = sha3Digest(A, svSha3_384)

proc sha3_512*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-512.
  result = sha3Digest(A, svSha3_512)

proc sha3Hash*(A: openArray[byte], outLen: int = 32): seq[byte] =
  ## Compatibility wrapper that selects a fixed SHA3 variant from `outLen`.
  result = sha3Digest(A, sha3VariantFromOutLen(outLen))

when defined(amd64) or defined(i386):
  import ./sha3_simd
  export sha3_simd
