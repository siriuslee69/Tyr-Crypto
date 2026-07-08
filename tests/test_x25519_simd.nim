import std/unittest

import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_impl]

proc buildDeterministicInputs2(secretKeys, publicKeys: var array[2, X25519Bytes32]) =
  var
    lane: int = 0
    i: int = 0
    seedA: seq[byte]
    seedB: seq[byte]
  lane = 0
  while lane < 2:
    seedA = newSeq[byte](32)
    seedB = newSeq[byte](32)
    i = 0
    while i < 32:
      seedA[i] = byte((31 * lane + 7 * i + 11) and 0xff)
      seedB[i] = byte((97 + 19 * lane + 5 * i) and 0xff)
      i = i + 1
    let
      kpA = x25519TyrKeypairFromSeed(seedA)
      kpB = x25519TyrKeypairFromSeed(seedB)
    secretKeys[lane] = toFixed32(kpA.secretKey)
    publicKeys[lane] = toFixed32(kpB.publicKey)
    lane = lane + 1

when defined(avx2):
  proc buildDeterministicInputs4(secretKeys, publicKeys: var array[4, X25519Bytes32]) =
    var
      lane: int = 0
      i: int = 0
      seedA: seq[byte]
      seedB: seq[byte]
    lane = 0
    while lane < 4:
      seedA = newSeq[byte](32)
      seedB = newSeq[byte](32)
      i = 0
      while i < 32:
        seedA[i] = byte((13 + 41 * lane + 9 * i) and 0xff)
        seedB[i] = byte((173 + 23 * lane + 3 * i) and 0xff)
        i = i + 1
      let
        kpA = x25519TyrKeypairFromSeed(seedA)
        kpB = x25519TyrKeypairFromSeed(seedB)
      secretKeys[lane] = toFixed32(kpA.secretKey)
      publicKeys[lane] = toFixed32(kpB.publicKey)
      lane = lane + 1

suite "x25519 simd":
  when defined(amd64) or defined(i386):
    test "SSE2x batch matches scalar":
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        outShared: array[2, X25519Bytes32]
        ok: array[2, bool]
        lane: int = 0
      buildDeterministicInputs2(secretKeys, publicKeys)
      ok = x25519ScalarmultBatchSse2x(outShared, secretKeys, publicKeys)
      lane = 0
      while lane < 2:
        let
          sk = toSeqBytes(secretKeys[lane])
          pk = toSeqBytes(publicKeys[lane])
        check ok[lane]
        check toSeqBytes(outShared[lane]) == x25519TyrShared(sk, pk)
        lane = lane + 1

    test "SSE2x batch isolates small-order lanes":
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        outShared: array[2, X25519Bytes32]
        ok: array[2, bool]
      buildDeterministicInputs2(secretKeys, publicKeys)
      publicKeys[0] = smallOrderBlocklist[0]
      ok = x25519ScalarmultBatchSse2x(outShared, secretKeys, publicKeys)
      check not ok[0]
      check ok[1]
      check toSeqBytes(outShared[1]) == x25519TyrShared(toSeqBytes(secretKeys[1]), toSeqBytes(publicKeys[1]))

  when defined(neon) or defined(arm64) or defined(aarch64):
    test "NEON2x batch matches scalar":
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        outShared: array[2, X25519Bytes32]
        ok: array[2, bool]
        lane: int = 0
      buildDeterministicInputs2(secretKeys, publicKeys)
      ok = x25519ScalarmultBatchNeon2x(outShared, secretKeys, publicKeys)
      lane = 0
      while lane < 2:
        let
          sk = toSeqBytes(secretKeys[lane])
          pk = toSeqBytes(publicKeys[lane])
        check ok[lane]
        check toSeqBytes(outShared[lane]) == x25519TyrShared(sk, pk)
        lane = lane + 1

    test "NEON2x batch isolates small-order lanes":
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        outShared: array[2, X25519Bytes32]
        ok: array[2, bool]
      buildDeterministicInputs2(secretKeys, publicKeys)
      publicKeys[0] = smallOrderBlocklist[0]
      ok = x25519ScalarmultBatchNeon2x(outShared, secretKeys, publicKeys)
      check not ok[0]
      check ok[1]
      check toSeqBytes(outShared[1]) == x25519TyrShared(toSeqBytes(secretKeys[1]), toSeqBytes(publicKeys[1]))

  when defined(avx2):
    test "AVX4x batch matches scalar":
      var
        secretKeys: array[4, X25519Bytes32]
        publicKeys: array[4, X25519Bytes32]
        outShared: array[4, X25519Bytes32]
        ok: array[4, bool]
        lane: int = 0
      buildDeterministicInputs4(secretKeys, publicKeys)
      ok = x25519ScalarmultBatchAvx4x(outShared, secretKeys, publicKeys)
      lane = 0
      while lane < 4:
        let
          sk = toSeqBytes(secretKeys[lane])
          pk = toSeqBytes(publicKeys[lane])
        check ok[lane]
        check toSeqBytes(outShared[lane]) == x25519TyrShared(sk, pk)
        lane = lane + 1

    test "AVX4x batch isolates small-order lanes":
      var
        secretKeys: array[4, X25519Bytes32]
        publicKeys: array[4, X25519Bytes32]
        outShared: array[4, X25519Bytes32]
        ok: array[4, bool]
        lane: int = 1
      buildDeterministicInputs4(secretKeys, publicKeys)
      publicKeys[0] = smallOrderBlocklist[0]
      ok = x25519ScalarmultBatchAvx4x(outShared, secretKeys, publicKeys)
      check not ok[0]
      while lane < 4:
        check ok[lane]
        check toSeqBytes(outShared[lane]) == x25519TyrShared(toSeqBytes(secretKeys[lane]), toSeqBytes(publicKeys[lane]))
        lane = lane + 1
