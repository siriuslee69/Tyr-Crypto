import std/unittest

import ../src/protocols/custom_crypto/sha3 as custom_sha3

proc fromHex(s: string): seq[byte] =
  proc hexVal(c: char): int =
    case c
    of '0' .. '9':
      result = ord(c) - ord('0')
    of 'a' .. 'f':
      result = ord(c) - ord('a') + 10
    of 'A' .. 'F':
      result = ord(c) - ord('A') + 10
    else:
      raise newException(ValueError, "invalid hex digit")

  var i: int = 0
  if (s.len and 1) != 0:
    raise newException(ValueError, "hex string length must be even")
  result = newSeq[byte](s.len div 2)
  i = 0
  while i < s.len:
    result[i shr 1] = byte((hexVal(s[i]) shl 4) or hexVal(s[i + 1]))
    i = i + 2

proc buildSha3State(seed: uint64): custom_sha3.Sha3State =
  var
    i: int = 0
  while i < result.len:
    result[i] = seed + uint64(i) * 0x0102030405060708'u64
    i = i + 1

suite "sha3 simd":
  test "scalar SHA3 and SHAKE vectors match known outputs":
    var
      shakeOut: array[16, byte]
    check custom_sha3.sha3_256(@[]) ==
      fromHex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    check custom_sha3.sha3_256(@[byte 'a', byte 'b', byte 'c']) ==
      fromHex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    custom_sha3.shake256Into(shakeOut, @[])
    check @shakeOut == fromHex("46b9dd2b0ba88d13233b3feb743eeb24")

  when defined(amd64) or defined(i386):
    test "SSE2x Keccak permutation matches reference":
      var
        ss: array[2, custom_sha3.Sha3State]
        rs: array[2, custom_sha3.Sha3State]
        i: int = 0
      ss[0] = buildSha3State(0x0102030405060708'u64)
      ss[1] = buildSha3State(0x1112131415161718'u64)
      rs = ss
      i = 0
      while i < rs.len:
        keccakF1600Ref(rs[i])
        i = i + 1
      custom_sha3.keccakF1600Sse2x(ss)
      check ss == rs

    test "SSE2x SHA3 hash batch matches scalar":
      var
        msgs: array[2, seq[byte]]
        outs: array[2, seq[byte]]
      msgs[0] = @[byte 1, 2, 3, 4, 5, 6, 7, 8]
      msgs[1] = @[byte 8, 7, 6, 5, 4, 3, 2, 1]
      outs = custom_sha3.sha3HashSse2x(msgs, 32)
      check outs[0] == custom_sha3.sha3Hash(msgs[0], 32)
      check outs[1] == custom_sha3.sha3Hash(msgs[1], 32)

    test "SSE2x fixed one-block SHAKE256 matches scalar":
      var
        msgs64: array[2, array[64, byte]]
        msgs80: array[2, array[80, byte]]
        simd64: array[2, array[16, byte]]
        simd80: array[2, array[16, byte]]
        scalar64: array[16, byte]
        scalar80: array[16, byte]
        i: int = 0
      i = 0
      while i < 64:
        msgs64[0][i] = byte((i * 3 + 1) mod 256)
        msgs64[1][i] = byte((i * 5 + 7) mod 256)
        i = i + 1
      i = 0
      while i < 80:
        msgs80[0][i] = byte((i * 7 + 9) mod 256)
        msgs80[1][i] = byte((i * 11 + 13) mod 256)
        i = i + 1
      custom_sha3.shake256OneBlockAlignedSse2xInto(simd64, msgs64)
      custom_sha3.shake256OneBlockAlignedSse2xInto(simd80, msgs80)
      custom_sha3.shake256OneBlockAlignedInto(scalar64, msgs64[0])
      check simd64[0] == scalar64
      custom_sha3.shake256OneBlockAlignedInto(scalar64, msgs64[1])
      check simd64[1] == scalar64
      custom_sha3.shake256OneBlockAlignedInto(scalar80, msgs80[0])
      check simd80[0] == scalar80
      custom_sha3.shake256OneBlockAlignedInto(scalar80, msgs80[1])
      check simd80[1] == scalar80

    test "SSE2x SHAKE edge lengths below the rate match scalar":
      var
        msgs128: array[2, array[167, byte]]
        statesSimd: array[2, custom_sha3.Sha3State]
        statesScalar: array[2, custom_sha3.Sha3State]
        shakeMsgs: array[2, array[135, byte]]
        simdOut: array[2, array[32, byte]]
        scalarOut: array[32, byte]
        lane: int = 0
        i: int = 0
      lane = 0
      while lane < 2:
        i = 0
        while i < 167:
          msgs128[lane][i] = byte((lane * 17 + i * 9 + 3) mod 256)
          i = i + 1
        i = 0
        while i < 135:
          shakeMsgs[lane][i] = byte((lane * 19 + i * 7 + 5) mod 256)
          i = i + 1
        custom_sha3.shake128AbsorbOnce(statesScalar[lane], msgs128[lane])
        lane = lane + 1
      custom_sha3.shake128AbsorbOnceSse2x(statesSimd, msgs128)
      check statesSimd == statesScalar
      custom_sha3.shake256Sse2xInto(simdOut, shakeMsgs)
      lane = 0
      while lane < 2:
        custom_sha3.shake256Into(scalarOut, shakeMsgs[lane])
        check simdOut[lane] == scalarOut
        lane = lane + 1

  when defined(avx2):
    test "AVX4x SHA3 hash batch matches scalar":
      var
        msgs: array[4, seq[byte]]
        outs: array[4, seq[byte]]
        i: int = 0
      while i < 4:
        msgs[i] = newSeq[byte](12)
        for j in 0 ..< msgs[i].len:
          msgs[i][j] = uint8((i * 33 + j) mod 256)
        i = i + 1
      outs = custom_sha3.sha3HashAvx4x(msgs, 32)
      i = 0
      while i < 4:
        check outs[i] == custom_sha3.sha3Hash(msgs[i], 32)
        i = i + 1

    test "AVX4x fixed one-block SHAKE256 matches scalar":
      var
        msgs64: array[4, array[64, byte]]
        msgs80: array[4, array[80, byte]]
        simd64: array[4, array[16, byte]]
        simd80: array[4, array[16, byte]]
        scalar: array[16, byte]
        lane: int = 0
        i: int = 0
      lane = 0
      while lane < 4:
        i = 0
        while i < 64:
          msgs64[lane][i] = byte((lane * 41 + i * 3 + 17) mod 256)
          i = i + 1
        i = 0
        while i < 80:
          msgs80[lane][i] = byte((lane * 53 + i * 5 + 19) mod 256)
          i = i + 1
        lane = lane + 1
      custom_sha3.shake256OneBlockAlignedAvx4xInto(simd64, msgs64)
      custom_sha3.shake256OneBlockAlignedAvx4xInto(simd80, msgs80)
      lane = 0
      while lane < 4:
        custom_sha3.shake256OneBlockAlignedInto(scalar, msgs64[lane])
        check simd64[lane] == scalar
        custom_sha3.shake256OneBlockAlignedInto(scalar, msgs80[lane])
        check simd80[lane] == scalar
        lane = lane + 1

    test "AVX4x SHAKE edge lengths below the rate match scalar":
      var
        msgs128: array[4, array[167, byte]]
        statesSimd: array[4, custom_sha3.Sha3State]
        statesScalar: array[4, custom_sha3.Sha3State]
        shakeMsgs: array[4, array[135, byte]]
        simdOut: array[4, array[32, byte]]
        scalarOut: array[32, byte]
        lane: int = 0
        i: int = 0
      lane = 0
      while lane < 4:
        i = 0
        while i < 167:
          msgs128[lane][i] = byte((lane * 23 + i * 11 + 7) mod 256)
          i = i + 1
        i = 0
        while i < 135:
          shakeMsgs[lane][i] = byte((lane * 29 + i * 13 + 9) mod 256)
          i = i + 1
        custom_sha3.shake128AbsorbOnce(statesScalar[lane], msgs128[lane])
        lane = lane + 1
      custom_sha3.shake128AbsorbOnceAvx4x(statesSimd, msgs128)
      check statesSimd == statesScalar
      custom_sha3.shake256Avx4xInto(simdOut, shakeMsgs)
      lane = 0
      while lane < 4:
        custom_sha3.shake256Into(scalarOut, shakeMsgs[lane])
        check simdOut[lane] == scalarOut
        lane = lane + 1
