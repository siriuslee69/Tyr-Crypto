import std/unittest

import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_pass1, x25519_pass2, x25519_pass3, x25519_pass4]

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
      kpA = x25519_pass4.x25519TyrKeypairFromSeed(seedA)
      kpB = x25519_pass4.x25519TyrKeypairFromSeed(seedB)
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
        kpA = x25519_pass4.x25519TyrKeypairFromSeed(seedA)
        kpB = x25519_pass4.x25519TyrKeypairFromSeed(seedB)
      secretKeys[lane] = toFixed32(kpA.secretKey)
      publicKeys[lane] = toFixed32(kpB.publicKey)
      lane = lane + 1

suite "x25519 simd":
  when defined(amd64) or defined(i386):
    test "SSE2x batch matches scalar across all passes":
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        out1: array[2, X25519Bytes32]
        out2: array[2, X25519Bytes32]
        out3: array[2, X25519Bytes32]
        out4: array[2, X25519Bytes32]
        ok1: array[2, bool]
        ok2: array[2, bool]
        ok3: array[2, bool]
        ok4: array[2, bool]
        lane: int = 0
      buildDeterministicInputs2(secretKeys, publicKeys)
      ok1 = x25519_pass1.x25519ScalarmultBatchSse2x(out1, secretKeys, publicKeys)
      ok2 = x25519_pass2.x25519ScalarmultBatchSse2x(out2, secretKeys, publicKeys)
      ok3 = x25519_pass3.x25519ScalarmultBatchSse2x(out3, secretKeys, publicKeys)
      ok4 = x25519_pass4.x25519ScalarmultBatchSse2x(out4, secretKeys, publicKeys)
      lane = 0
      while lane < 2:
        let
          sk = toSeqBytes(secretKeys[lane])
          pk = toSeqBytes(publicKeys[lane])
        check ok1[lane]
        check ok2[lane]
        check ok3[lane]
        check ok4[lane]
        check toSeqBytes(out1[lane]) == x25519_pass1.x25519TyrShared(sk, pk)
        check toSeqBytes(out2[lane]) == x25519_pass2.x25519TyrShared(sk, pk)
        check toSeqBytes(out3[lane]) == x25519_pass3.x25519TyrShared(sk, pk)
        check toSeqBytes(out4[lane]) == x25519_pass4.x25519TyrShared(sk, pk)
        lane = lane + 1

  when defined(neon) or defined(arm64) or defined(aarch64):
    test "NEON2x batch matches scalar across all passes":
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        out1: array[2, X25519Bytes32]
        out2: array[2, X25519Bytes32]
        out3: array[2, X25519Bytes32]
        out4: array[2, X25519Bytes32]
        ok1: array[2, bool]
        ok2: array[2, bool]
        ok3: array[2, bool]
        ok4: array[2, bool]
        lane: int = 0
      buildDeterministicInputs2(secretKeys, publicKeys)
      ok1 = x25519_pass1.x25519ScalarmultBatchNeon2x(out1, secretKeys, publicKeys)
      ok2 = x25519_pass2.x25519ScalarmultBatchNeon2x(out2, secretKeys, publicKeys)
      ok3 = x25519_pass3.x25519ScalarmultBatchNeon2x(out3, secretKeys, publicKeys)
      ok4 = x25519_pass4.x25519ScalarmultBatchNeon2x(out4, secretKeys, publicKeys)
      lane = 0
      while lane < 2:
        let
          sk = toSeqBytes(secretKeys[lane])
          pk = toSeqBytes(publicKeys[lane])
        check ok1[lane]
        check ok2[lane]
        check ok3[lane]
        check ok4[lane]
        check toSeqBytes(out1[lane]) == x25519_pass1.x25519TyrShared(sk, pk)
        check toSeqBytes(out2[lane]) == x25519_pass2.x25519TyrShared(sk, pk)
        check toSeqBytes(out3[lane]) == x25519_pass3.x25519TyrShared(sk, pk)
        check toSeqBytes(out4[lane]) == x25519_pass4.x25519TyrShared(sk, pk)
        lane = lane + 1

  when defined(avx2):
    test "AVX4x batch matches scalar across all passes":
      var
        secretKeys: array[4, X25519Bytes32]
        publicKeys: array[4, X25519Bytes32]
        out1: array[4, X25519Bytes32]
        out2: array[4, X25519Bytes32]
        out3: array[4, X25519Bytes32]
        out4: array[4, X25519Bytes32]
        ok1: array[4, bool]
        ok2: array[4, bool]
        ok3: array[4, bool]
        ok4: array[4, bool]
        lane: int = 0
      buildDeterministicInputs4(secretKeys, publicKeys)
      ok1 = x25519_pass1.x25519ScalarmultBatchAvx4x(out1, secretKeys, publicKeys)
      ok2 = x25519_pass2.x25519ScalarmultBatchAvx4x(out2, secretKeys, publicKeys)
      ok3 = x25519_pass3.x25519ScalarmultBatchAvx4x(out3, secretKeys, publicKeys)
      ok4 = x25519_pass4.x25519ScalarmultBatchAvx4x(out4, secretKeys, publicKeys)
      lane = 0
      while lane < 4:
        let
          sk = toSeqBytes(secretKeys[lane])
          pk = toSeqBytes(publicKeys[lane])
        check ok1[lane]
        check ok2[lane]
        check ok3[lane]
        check ok4[lane]
        check toSeqBytes(out1[lane]) == x25519_pass1.x25519TyrShared(sk, pk)
        check toSeqBytes(out2[lane]) == x25519_pass2.x25519TyrShared(sk, pk)
        check toSeqBytes(out3[lane]) == x25519_pass3.x25519TyrShared(sk, pk)
        check toSeqBytes(out4[lane]) == x25519_pass4.x25519TyrShared(sk, pk)
        lane = lane + 1
