## ---------------------------------------------------------
## OTP Ops <- HOTP/TOTP over Blake3/Gimli/ChaCha backends
## ---------------------------------------------------------

import ./blake3
import ./gimli
import ./xchacha20
import ./xchacha20_simd

type
  OtpAlgo* = enum
    oaBlake3,
    oaGimli,
    oaChaCha

  OtpBackend* = enum
    obScalar,
    obSimdAuto,
    obSimdSse2,
    obSimdAvx2

const
  blake3OtpIv: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

proc load32Le(data: openArray[byte], offset: int): uint32 {.inline.} =
  result =
    (uint32(data[offset]) or
    (uint32(data[offset + 1]) shl 8) or
    (uint32(data[offset + 2]) shl 16) or
    (uint32(data[offset + 3]) shl 24))

proc counterBytes(counter: uint64): array[8, byte] {.inline.} =
  var i = 0
  while i < 8:
    result[i] = byte((counter shr (i * 8)) and 0xff'u64)
    i.inc

proc mixMaterial(secret: openArray[byte], counter: uint64; label: string;
    outLen: int): seq[byte] =
  ## Deterministic material expansion for backend-local state setup.
  var
    src = newSeq[byte](secret.len + 8 + label.len)
    cb = counterBytes(counter)
    i = 0
    j = 0
  while i < secret.len:
    src[i] = secret[i]
    i.inc
  while j < 8:
    src[i + j] = cb[j]
    j.inc
  j = 0
  while j < label.len:
    src[i + 8 + j] = byte(label[j])
    j.inc
  result = newSeq[byte](outLen)
  if src.len == 0:
    return
  i = 0
  while i < outLen:
    let a = src[i mod src.len]
    let b = byte((i * 131) and 0xff)
    result[i] = a xor b xor byte((counter shr ((i mod 8) * 8)) and 0xff'u64)
    i.inc

proc writeWordLe(dst: var seq[byte], offset: int; w: uint32) {.inline.} =
  dst[offset] = byte(w and 0xff'u32)
  dst[offset + 1] = byte((w shr 8) and 0xff'u32)
  dst[offset + 2] = byte((w shr 16) and 0xff'u32)
  dst[offset + 3] = byte((w shr 24) and 0xff'u32)

proc blake3BlockFromBytes(bs: openArray[byte]): array[16, uint32] =
  var
    padded = newSeq[byte](64)
    i = 0
  while i < 64:
    padded[i] = bs[i mod max(1, bs.len)]
    i.inc
  i = 0
  while i < 16:
    result[i] = load32Le(padded, i * 4)
    i.inc

proc blake3OutToBytes(outWords: array[16, uint32]): seq[byte] =
  result = newSeq[byte](64)
  var i = 0
  while i < 16:
    writeWordLe(result, i * 4, outWords[i])
    i.inc

proc resolveBlake3Backend(b: OtpBackend): Blake3CompressBackend =
  case b
  of obSimdAuto:
    result = bcbAuto
  of obSimdSse2:
    result = bcbSse2
  of obSimdAvx2:
    result = bcbAvx2
  of obScalar:
    result = bcbScalar

proc resolveXChaChaBackend(b: OtpBackend): XChaChaBackend =
  case b
  of obSimdAuto:
    result = xcbAuto
  of obSimdSse2:
    result = xcbSse2
  of obSimdAvx2:
    result = xcbAvx2
  of obScalar:
    result = xcbScalar

proc digestBlake3Scalar(secret: openArray[byte], counter: uint64): seq[byte] =
  let blk = blake3BlockFromBytes(mixMaterial(secret, counter, "otp:blake3", 64))
  let outWords = blake3Compress(blake3OtpIv, blk, counter, 64'u32, 0'u32)
  result = blake3OutToBytes(outWords)

proc digestBlake3Simd(secret: openArray[byte], counter: uint64; b: OtpBackend): seq[byte] =
  let
    blk = blake3BlockFromBytes(mixMaterial(secret, counter, "otp:blake3", 64))
    outs = blake3CompressBatch(@[blake3OtpIv], @[blk], counter, 64'u32, 0'u32,
      resolveBlake3Backend(b))
  result = blake3OutToBytes(outs[0])

proc bytesToGimliState(bs: openArray[byte]): Gimli_Block =
  var
    i = 0
    padded = newSeq[byte](48)
  while i < 48:
    padded[i] = bs[i mod max(1, bs.len)]
    i.inc
  i = 0
  while i < 12:
    result[i] = load32Le(padded, i * 4)
    i.inc

proc gimliStateToBytes(st: Gimli_Block): seq[byte] =
  result = newSeq[byte](48)
  var i = 0
  while i < 12:
    writeWordLe(result, i * 4, st[i])
    i.inc

proc digestGimliScalar(secret: openArray[byte], counter: uint64): seq[byte] =
  var st = bytesToGimliState(mixMaterial(secret, counter, "otp:gimli", 48))
  gimliPermute(st)
  result = gimliStateToBytes(st)

proc digestGimliSimd(secret: openArray[byte], counter: uint64; b: OtpBackend): seq[byte] =
  var st = bytesToGimliState(mixMaterial(secret, counter, "otp:gimli", 48))
  case b
  of obScalar:
    gimliPermute(st)
  of obSimdSse2:
    when declared(gimliPermuteSse):
      gimliPermuteSse(st)
    else:
      gimliPermute(st)
  of obSimdAvx2:
    when declared(gimliPermuteSse):
      gimliPermuteSse(st)
    else:
      gimliPermute(st)
  of obSimdAuto:
    # Keep OTP single-block dispatch on the stable SSE path for now.
    when declared(gimliPermuteSse):
      gimliPermuteSse(st)
    else:
      gimliPermute(st)
  result = gimliStateToBytes(st)

proc digestGimliBatchSimd(secret: openArray[byte], counters: openArray[uint64];
    b: OtpBackend): seq[seq[byte]] =
  ## SIMD batch Gimli OTP digest path with one distinct counter per lane.
  result = newSeq[seq[byte]](counters.len)
  if counters.len == 0:
    return
  var i = 0
  # Keep batch OTP dispatch on the stable SSE-lane path for now.
  when declared(gimliPermuteSse4x):
    if b != obScalar:
      while i + 4 <= counters.len:
        var
          batch: array[4, Gimli_Block]
          j = 0
        while j < 4:
          batch[j] = bytesToGimliState(mixMaterial(secret, counters[i + j], "otp:gimli", 48))
          j.inc
        gimliPermuteSse4x(batch)
        j = 0
        while j < 4:
          result[i + j] = gimliStateToBytes(batch[j])
          j.inc
        i = i + 4
  while i < counters.len:
    if b == obScalar:
      result[i] = digestGimliScalar(secret, counters[i])
    else:
      result[i] = digestGimliSimd(secret, counters[i], b)
    i.inc

proc chachaKeyNonce(secret: openArray[byte], counter: uint64): tuple[key: seq[byte],
    nonce: seq[byte]] =
  let mat = mixMaterial(secret, counter, "otp:chacha", 56)
  result.key = mat[0 ..< 32]
  result.nonce = mat[32 ..< 56]

proc digestChaChaScalar(secret: openArray[byte], counter: uint64): seq[byte] =
  let kn = chachaKeyNonce(secret, counter)
  result = xchacha20Stream(kn.key, kn.nonce, 64, 0'u32)

proc digestChaChaSimd(secret: openArray[byte], counter: uint64; b: OtpBackend): seq[byte] =
  let kn = chachaKeyNonce(secret, counter)
  result = xchacha20StreamSimd(kn.key, kn.nonce, 64, 0'u32, resolveXChaChaBackend(b))

proc ensureDigestLen(ds: seq[byte]): seq[byte] =
  if ds.len >= 20:
    return ds
  result = newSeq[byte](20)
  if ds.len == 0:
    return
  var i = 0
  while i < 20:
    result[i] = ds[i mod ds.len]
    i.inc

proc pow10(n: int): uint32 =
  result = 1'u32
  var i = 0
  while i < n:
    result = result * 10'u32
    i.inc

proc otpFromDigest(ds: seq[byte], digits: int): string =
  let digest = ensureDigestLen(ds)
  var offset = int(digest[^1] and 0x0f)
  if offset + 4 > digest.len:
    offset = digest.len - 4
  let code =
    ((uint32(digest[offset]) and 0x7f'u32) shl 24) or
    (uint32(digest[offset + 1]) shl 16) or
    (uint32(digest[offset + 2]) shl 8) or
    uint32(digest[offset + 3])
  let modBase = pow10(max(1, digits))
  let n = code mod modBase
  result = $n
  while result.len < digits:
    result = "0" & result

proc otpDigest*(algo: OtpAlgo; secret: openArray[byte]; counter: uint64;
    b: OtpBackend = obScalar): seq[byte] =
  ## algo: OTP backend primitive.
  ## secret: shared OTP secret bytes.
  ## counter: HOTP/TOTP counter value.
  ## b: scalar or SIMD backend selector.
  case algo
  of oaBlake3:
    if b == obScalar:
      result = digestBlake3Scalar(secret, counter)
    else:
      result = digestBlake3Simd(secret, counter, b)
  of oaGimli:
    if b == obScalar:
      result = digestGimliScalar(secret, counter)
    else:
      result = digestGimliSimd(secret, counter, b)
  of oaChaCha:
    if b == obScalar:
      result = digestChaChaScalar(secret, counter)
    else:
      result = digestChaChaSimd(secret, counter, b)

proc otpDigestBatch*(algo: OtpAlgo; secret: openArray[byte];
    counters: openArray[uint64]; b: OtpBackend = obScalar): seq[seq[byte]] =
  ## Batch digest generation over many counters/nonces.
  result = newSeq[seq[byte]](counters.len)
  if counters.len == 0:
    return
  case algo
  of oaGimli:
    if b == obScalar:
      var i = 0
      while i < counters.len:
        result[i] = digestGimliScalar(secret, counters[i])
        i.inc
    else:
      result = digestGimliBatchSimd(secret, counters, b)
  of oaBlake3:
    var i = 0
    while i < counters.len:
      if b == obScalar:
        result[i] = digestBlake3Scalar(secret, counters[i])
      else:
        result[i] = digestBlake3Simd(secret, counters[i], b)
      i.inc
  of oaChaCha:
    var i = 0
    while i < counters.len:
      if b == obScalar:
        result[i] = digestChaChaScalar(secret, counters[i])
      else:
        result[i] = digestChaChaSimd(secret, counters[i], b)
      i.inc

proc otpDigestNonces*(algo: OtpAlgo; secret: openArray[byte];
    nonces: openArray[uint64]; b: OtpBackend = obScalar): seq[seq[byte]] =
  ## Alias for batch digest generation when caller models counters as nonces.
  result = otpDigestBatch(algo, secret, nonces, b)

proc hotp*(algo: OtpAlgo; secret: openArray[byte]; counter: uint64;
    digits: int = 6; b: OtpBackend = obScalar): string =
  ## HOTP from selected custom-crypto primitive.
  let d = min(10, max(4, digits))
  result = otpFromDigest(otpDigest(algo, secret, counter, b), d)

proc hotpBatch*(algo: OtpAlgo; secret: openArray[byte];
    counters: openArray[uint64]; digits: int = 6;
    b: OtpBackend = obScalar): seq[string] =
  ## Batch HOTP generation over many counters/nonces.
  let d = min(10, max(4, digits))
  result = newSeq[string](counters.len)
  let digests = otpDigestBatch(algo, secret, counters, b)
  var i = 0
  while i < digests.len:
    result[i] = otpFromDigest(digests[i], d)
    i.inc

proc hotpNonces*(algo: OtpAlgo; secret: openArray[byte];
    nonces: openArray[uint64]; digits: int = 6;
    b: OtpBackend = obScalar): seq[string] =
  ## Alias for batch HOTP generation when caller models counters as nonces.
  result = hotpBatch(algo, secret, nonces, digits, b)

proc totp*(algo: OtpAlgo; secret: openArray[byte]; unixTime: int64;
    stepSec: int64 = 30'i64; digits: int = 6; t0: int64 = 0'i64;
    b: OtpBackend = obScalar): string =
  ## TOTP from selected custom-crypto primitive.
  if stepSec <= 0:
    raise newException(ValueError, "stepSec must be positive")
  if unixTime < t0:
    raise newException(ValueError, "unixTime must be >= t0")
  let ctr = uint64((unixTime - t0) div stepSec)
  result = hotp(algo, secret, ctr, digits, b)

proc hotpSimd*(algo: OtpAlgo; secret: openArray[byte]; counter: uint64;
    digits: int = 6; b: OtpBackend = obSimdAuto): string =
  ## Convenience wrapper for SIMD-enabled HOTP.
  result = hotp(algo, secret, counter, digits, b)

proc hotpSimdBatch*(algo: OtpAlgo; secret: openArray[byte];
    counters: openArray[uint64]; digits: int = 6;
    b: OtpBackend = obSimdAuto): seq[string] =
  ## Convenience wrapper for SIMD-enabled HOTP batch generation.
  result = hotpBatch(algo, secret, counters, digits, b)

proc totpSimd*(algo: OtpAlgo; secret: openArray[byte]; unixTime: int64;
    stepSec: int64 = 30'i64; digits: int = 6; t0: int64 = 0'i64;
    b: OtpBackend = obSimdAuto): string =
  ## Convenience wrapper for SIMD-enabled TOTP.
  result = totp(algo, secret, unixTime, stepSec, digits, t0, b)
