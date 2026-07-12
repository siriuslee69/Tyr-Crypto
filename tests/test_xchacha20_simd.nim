import std/unittest
import ../src/protocols/custom_crypto/chacha20 as chacha
import ../src/protocols/custom_crypto/symmetric/chacha/chacha20_scalar as scalar
import ../src/protocols/custom_crypto/xchacha20 as xchacha
import ../src/protocols/custom_crypto/xchacha20_simd
import ./helpers

suite "xchacha20 simd":
  test "canonical chacha APIs match scalar core across SIMD boundaries":
    var
      key = toBytes("0123456789abcdef0123456789abcdef")
      nonce = toBytes("abcdefghijkl")
      lengths = [0, 1, 63, 64, 255, 256, 511, 512, 777]
      input: seq[byte] = @[]
      expected: seq[byte] = @[]
      stream: seq[byte] = @[]
      cipher: seq[byte] = @[]
      inPlace: seq[byte] = @[]
    for length in lengths:
      input = newSeq[byte](length)
      expected = scalar.chacha20Stream(key, nonce, length, 3'u32)
      stream = chacha.chacha20Stream(key, nonce, length, 3'u32)
      cipher = chacha.chacha20Xor(key, nonce, 3'u32, input)
      inPlace = input
      check stream == expected
      check cipher == expected
      chacha.chacha20XorInPlace(key, nonce, 3'u32, inPlace)
      check inPlace == expected

  test "auto matches scalar":
    let key = toBytes("0123456789abcdef0123456789abcdef")
    let nonce = toBytes("abcdefghijklmnopqrstuvwx")
    let stream0 = xchacha20StreamSimd(key, nonce, 128, 1'u32, xcbScalar)
    let stream1 = xchacha20StreamSimd(key, nonce, 128, 1'u32, xcbAuto)
    check stream1 == stream0

  test "simd stream refuses counter wrap before backend dispatch":
    let
      key = toBytes("0123456789abcdef0123456789abcdef")
      nonce = toBytes("abcdefghijklmnopqrstuvwx")
    check xchacha20StreamSimd(key, nonce, 64, uint32.high, xcbAuto).len == 64
    expect ValueError:
      discard xchacha20StreamSimd(key, nonce, 65, uint32.high, xcbAuto)

  when defined(sse2):
    test "sse2 matches scalar":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnopqrstuvwx")
      let stream0 = xchacha.xchacha20Stream(key, nonce, 256, 5'u32)
      let stream1 = xchacha20StreamSimd(key, nonce, 256, 5'u32, xcbSse2)
      check stream1 == stream0

  when defined(avx2):
    test "avx2 matches scalar":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnopqrstuvwx")
      let stream0 = xchacha.xchacha20Stream(key, nonce, 512, 9'u32)
      let stream1 = xchacha20StreamSimd(key, nonce, 512, 9'u32, xcbAvx2)
      check stream1 == stream0

  when defined(neon) or defined(arm64) or defined(aarch64):
    test "neon matches scalar":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnopqrstuvwx")
      let stream0 = xchacha.xchacha20Stream(key, nonce, 256, 7'u32)
      let stream1 = xchacha20StreamSimd(key, nonce, 256, 7'u32, xcbNeon)
      check stream1 == stream0
