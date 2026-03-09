import std/unittest
import ../src/tyr_crypto/custom_crypto/xchacha20
import ../src/tyr_crypto/custom_crypto/xchacha20_simd
import ./helpers

suite "xchacha20 simd":
  test "auto matches scalar":
    let key = toBytes("0123456789abcdef0123456789abcdef")
    let nonce = toBytes("abcdefghijklmnopqrstuvwx")
    let stream0 = xchacha20Stream(key, nonce, 128, 1'u32)
    let stream1 = xchacha20StreamSimd(key, nonce, 128, 1'u32, xcbAuto)
    check stream1 == stream0

  when defined(sse2):
    test "sse2 matches scalar":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnopqrstuvwx")
      let stream0 = xchacha20Stream(key, nonce, 256, 5'u32)
      let stream1 = xchacha20StreamSimd(key, nonce, 256, 5'u32, xcbSse2)
      check stream1 == stream0

  when defined(avx2):
    test "avx2 matches scalar":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnopqrstuvwx")
      let stream0 = xchacha20Stream(key, nonce, 512, 9'u32)
      let stream1 = xchacha20StreamSimd(key, nonce, 512, 9'u32, xcbAvx2)
      check stream1 == stream0
