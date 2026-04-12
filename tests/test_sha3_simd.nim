import std/unittest

import ../src/protocols/custom_crypto/sha3 as custom_sha3

proc buildSha3State(seed: uint64): custom_sha3.Sha3State =
  var
    i: int = 0
  while i < result.len:
    result[i] = seed + uint64(i) * 0x0102030405060708'u64
    i = i + 1

suite "sha3 simd":
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
