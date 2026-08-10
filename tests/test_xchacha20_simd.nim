import std/unittest
import ../src/protocols/custom_crypto/chacha20 as chacha
import ../src/protocols/custom_crypto/symmetric/chacha/chacha20_scalar as scalar
import ../src/protocols/custom_crypto/xchacha20 as xchacha
import ../src/protocols/custom_crypto/xchacha20_simd
import ../src/protocols/custom_crypto/xchacha20_batch
import ./helpers

proc checkBackendBoundaries(b: XChaChaBackend, L: openArray[int]) =
  ## b: Forced XChaCha20 backend under test.
  ## L: Stream lengths around that backend's SIMD batch width.
  var
    key = toBytes("0123456789abcdef0123456789abcdef")
    nonce = toBytes("abcdefghijklmnopqrstuvwx")
    scalarBytes: seq[byte] = @[]
    backendBytes: seq[byte] = @[]
    i: int = 0
  while i < L.len:
    scalarBytes = xchacha.xchacha20Stream(key, nonce, L[i], 5'u32)
    backendBytes = xchacha20StreamSimd(key, nonce, L[i], 5'u32, b)
    check backendBytes == scalarBytes
    i = i + 1

proc checkCounterBoundary(b: XChaChaBackend, a, r: int, c: uint32) =
  ## b: Forced XChaCha20 backend under test.
  ## a: Accepted byte length at the final available counters.
  ## r: Rejected byte length that would wrap the counter.
  ## c: Initial counter for the boundary case.
  var
    key = toBytes("0123456789abcdef0123456789abcdef")
    nonce = toBytes("abcdefghijklmnopqrstuvwx")
    scalarBytes: seq[byte] = @[]
    backendBytes: seq[byte] = @[]
  scalarBytes = xchacha.xchacha20Stream(key, nonce, a, c)
  backendBytes = xchacha20StreamSimd(key, nonce, a, c, b)
  check backendBytes == scalarBytes
  expect ValueError:
    discard xchacha20StreamSimd(key, nonce, r, c, b)

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

  test "independent stream batches match scalar across lane and block tails":
    var
      keys: seq[seq[byte]] = @[]
      nonces: seq[seq[byte]] = @[]
      streams: seq[seq[byte]] = @[]
      expected: seq[byte] = @[]
      key: seq[byte] = @[]
      nonce: seq[byte] = @[]
      lengths: array[8, int] = [0, 1, 31, 63, 64, 65, 256, 513]
      i: int = 0
      j: int = 0
    while i < 13:
      key = newSeq[byte](32)
      nonce = newSeq[byte](24)
      key[0] = byte(i + 1)
      key[31] = byte(i + 17)
      nonce[0] = byte(i + 33)
      nonce[23] = byte(i + 49)
      keys.add(key)
      nonces.add(nonce)
      i = i + 1
    while j < lengths.len:
      streams = xchacha20BatchStreams(keys, nonces, lengths[j], 7'u32)
      i = 0
      while i < streams.len:
        expected = xchacha.xchacha20Stream(keys[i], nonces[i], lengths[j],
          7'u32)
        check streams[i] == expected
        i = i + 1
      j = j + 1

  test "independent stream batch validates rows and counter range":
    var
      keys: seq[seq[byte]] = @[newSeq[byte](32)]
      nonces: seq[seq[byte]] = @[newSeq[byte](24)]
    check xchacha20BatchStreams(keys, nonces, 64, uint32.high).len == 1
    expect ValueError:
      discard xchacha20BatchStreams(keys, nonces, 65, uint32.high)
    nonces[0].setLen(23)
    expect ValueError:
      discard xchacha20BatchStreams(keys, nonces, 1)
    nonces.setLen(0)
    expect ValueError:
      discard xchacha20BatchStreams(keys, nonces, 1)

  when defined(sse2):
    test "sse2 boundary matrix matches scalar":
      checkBackendBoundaries(xcbSse2, [255, 256, 257])
      checkCounterBoundary(xcbSse2, 256, 257, uint32.high - 3'u32)

  when defined(avx2):
    test "avx2 boundary matrix matches scalar":
      checkBackendBoundaries(xcbAvx2, [511, 512, 513])
      checkCounterBoundary(xcbAvx2, 512, 513, uint32.high - 7'u32)

  when defined(neon) or defined(arm64) or defined(aarch64):
    test "neon boundary matrix matches scalar":
      checkBackendBoundaries(xcbNeon, [255, 256, 257])
      checkCounterBoundary(xcbNeon, 256, 257, uint32.high - 3'u32)
