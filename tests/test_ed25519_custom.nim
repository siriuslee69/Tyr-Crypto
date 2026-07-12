import std/unittest

import ../src/protocols/custom_crypto/ed25519 as customEd25519
import ./helpers

suite "custom ed25519":
  test "RFC 8032 test 1 signs empty message":
    var seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    var publicKey = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    var signature = hexToBytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" &
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    var kp = customEd25519.ed25519TyrKeypairFromSeed(seed)
    check kp.publicKey == publicKey
    check customEd25519.ed25519TyrSign(@[], kp.secretKey) == signature
    check customEd25519.ed25519TyrVerify(@[], signature, publicKey)

  test "RFC 8032 test 2 signs one byte message":
    var seed = hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    var message = hexToBytes("72")
    var publicKey = hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    var signature = hexToBytes(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" &
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    var kp = customEd25519.ed25519TyrKeypairFromSeed(seed)
    check kp.publicKey == publicKey
    check customEd25519.ed25519TyrSign(message, kp.secretKey) == signature
    check customEd25519.ed25519TyrVerify(message, signature, publicKey)

  test "roundtrip rejects tampered signature and message":
    var seed = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    var message = toBytes("tyr ed25519 custom roundtrip")
    var kp = customEd25519.ed25519TyrKeypairFromSeed(seed)
    var sig = customEd25519.ed25519TyrSign(message, kp.secretKey)
    check customEd25519.ed25519TyrVerify(message, sig, kp.publicKey)
    sig[0] = sig[0] xor 1'u8
    check not customEd25519.ed25519TyrVerify(message, sig, kp.publicKey)
    sig[0] = sig[0] xor 1'u8
    message[0] = message[0] xor 1'u8
    check not customEd25519.ed25519TyrVerify(message, sig, kp.publicKey)

  test "strict verification rejects identity-key universal forgery":
    ## RFC 8032's uncofactored equation alone accepts R=B, S=1 for the
    ## identity public key, independently of the message. Strict verification
    ## must reject the torsion key before evaluating that equation.
    var
      identityKey = newSeq[byte](32)
      forgedSignature = newSeq[byte](64)
      message = toBytes("identity keys must not verify")
    identityKey[0] = 1'u8
    forgedSignature[0] = 0x58'u8
    for i in 1 ..< 32:
      forgedSignature[i] = 0x66'u8
    forgedSignature[32] = 1'u8
    check not customEd25519.ed25519TyrVerify(message, forgedSignature, identityKey)

  test "strict verification rejects a valid-equation mixed-order public key":
    ## A = B + T includes the nonzero order-2 point T. For the selected message
    ## h is even, so R=B and S=1+h satisfy the unchecked group equation because
    ## [h]T=0. Only an actual [L]A subgroup check rejects this forgery.
    var
      publicKey = hexToBytes(
        "9599999999999999999999999999999999999999999999999999999999999999")
      message = toBytes("mixed-order-regression-0")
      forgedSignature = hexToBytes(
        "5866666666666666666666666666666666666666666666666666666666666666" &
        "9f72fa17c273fbe3fced2d0c4c94e0cbbf8d87af72ed1bc67ffe5d83db561603")
    check not customEd25519.ed25519TyrVerify(message, forgedSignature, publicKey)

  when defined(amd64) or defined(i386):
    test "SSE2x batch api matches scalar":
      var messages: array[2, seq[byte]]
      var secretKeys: array[2, seq[byte]]
      var publicKeys: array[2, seq[byte]]
      var signatures: array[2, seq[byte]]
      var lane: int = 0
      while lane < 2:
        var seed = newSeq[byte](32)
        var i: int = 0
        while i < 32:
          seed[i] = byte((17 + lane * 29 + i * 7) and 0xff)
          inc i
        var kp = customEd25519.ed25519TyrKeypairFromSeed(seed)
        messages[lane] = toBytes("ed25519-sse-lane-" & $lane)
        secretKeys[lane] = kp.secretKey
        publicKeys[lane] = kp.publicKey
        inc lane
      signatures = customEd25519.ed25519TyrSignSse2x(messages, secretKeys)
      var ok = customEd25519.ed25519TyrVerifySse2x(messages, signatures, publicKeys)
      check ok[0]
      check ok[1]

  when defined(avx2):
    test "AVX4x batch api matches scalar":
      var messages: array[4, seq[byte]]
      var secretKeys: array[4, seq[byte]]
      var publicKeys: array[4, seq[byte]]
      var signatures: array[4, seq[byte]]
      var lane: int = 0
      while lane < 4:
        var seed = newSeq[byte](32)
        var i: int = 0
        while i < 32:
          seed[i] = byte((93 + lane * 11 + i * 5) and 0xff)
          inc i
        var kp = customEd25519.ed25519TyrKeypairFromSeed(seed)
        messages[lane] = toBytes("ed25519-avx-lane-" & $lane)
        secretKeys[lane] = kp.secretKey
        publicKeys[lane] = kp.publicKey
        inc lane
      signatures = customEd25519.ed25519TyrSignAvx4x(messages, secretKeys)
      var ok = customEd25519.ed25519TyrVerifyAvx4x(messages, signatures, publicKeys)
      lane = 0
      while lane < 4:
        check ok[lane]
        inc lane
