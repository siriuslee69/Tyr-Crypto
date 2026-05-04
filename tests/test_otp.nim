import std/unittest
import ../src/protocols/custom_crypto/otp
import ./helpers

suite "otp custom crypto":
  test "rfc4226 hotp matches published sha1 vectors":
    let
      secret = toBytes("12345678901234567890")
      expected = [
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489"
      ]
    for i in 0 ..< expected.len:
      check hotpRfc4226(secret, uint64(i), 6) == expected[i]
      check hotpRfc(secret, uint64(i), 6) == expected[i]

  test "rfc6238 totp matches published sha1 vectors":
    let
      secret = toBytes("12345678901234567890")
      times = [59'i64, 1111111109'i64, 1111111111'i64, 1234567890'i64,
        2000000000'i64, 20000000000'i64]
      expected = ["94287082", "07081804", "14050471", "89005924",
        "69279037", "65353130"]
    for i in 0 ..< expected.len:
      check totpRfc6238(secret, times[i], 30'i64, 8, 0'i64) == expected[i]
      check totpRfc(secret, times[i], 30'i64, 8, 0'i64) == expected[i]

  test "hotp is deterministic and length-bounded":
    let secret = toBytes("otp-secret-seed-0123456789")
    for algo in OtpAlgo:
      let c0 = hotp(algo, secret, 42'u64, 6, obScalar)
      let c1 = hotp(algo, secret, 42'u64, 6, obScalar)
      let c2 = hotp(algo, secret, 43'u64, 6, obScalar)
      check c0 == c1
      check c0.len == 6
      check c0 != c2

  test "totp remains stable inside one step window":
    let
      secret = toBytes("otp-secret-window")
      # Keep start aligned to a 30s boundary to avoid cross-step flakiness.
      t0 = 1_700_000_010'i64
    for algo in OtpAlgo:
      let a = totp(algo, secret, t0, 30'i64, 8, 0'i64, obScalar)
      let b = totp(algo, secret, t0 + 29'i64, 30'i64, 8, 0'i64, obScalar)
      let c = totp(algo, secret, t0 + 30'i64, 30'i64, 8, 0'i64, obScalar)
      check a == b
      check a.len == 8
      check a != c

  test "simd auto matches scalar":
    let secret = toBytes("otp-secret-simd-auto")
    for algo in OtpAlgo:
      let scalar = hotp(algo, secret, 777'u64, 7, obScalar)
      let simd = hotpSimd(algo, secret, 777'u64, 7, obSimdAuto)
      check simd == scalar

  test "batch hotp matches single hotp":
    let
      secret = toBytes("otp-secret-batch")
      nonces: seq[uint64] = @[1'u64, 2'u64, 3'u64, 255'u64, 1024'u64]
    for algo in OtpAlgo:
      let batch = hotpBatch(algo, secret, nonces, 8, obScalar)
      check batch.len == nonces.len
      for i in 0 ..< nonces.len:
        let one = hotp(algo, secret, nonces[i], 8, obScalar)
        check batch[i] == one

  test "batch nonce alias matches counter api":
    let
      secret = toBytes("otp-secret-nonce-alias")
      nonces: seq[uint64] = @[9'u64, 10'u64, 11'u64]
    for algo in OtpAlgo:
      let a = hotpBatch(algo, secret, nonces, 6, obScalar)
      let b = hotpNonces(algo, secret, nonces, 6, obScalar)
      check a == b

  when defined(sse2):
    test "simd sse2 matches scalar":
      let secret = toBytes("otp-secret-sse2")
      for algo in OtpAlgo:
        let scalar = hotp(algo, secret, 888'u64, 7, obScalar)
        let simd = hotpSimd(algo, secret, 888'u64, 7, obSimdSse2)
        check simd == scalar

    test "gimli sse batch matches scalar batch":
      let
        secret = toBytes("otp-secret-gimli-sse-batch")
        nonces: seq[uint64] = @[101'u64, 102'u64, 103'u64, 104'u64, 105'u64]
      let scalar = hotpBatch(oaGimli, secret, nonces, 8, obScalar)
      let simd = hotpSimdBatch(oaGimli, secret, nonces, 8, obSimdSse2)
      check simd == scalar

  when defined(avx2):
    test "simd avx2 matches scalar":
      let secret = toBytes("otp-secret-avx2")
      for algo in OtpAlgo:
        let scalar = hotp(algo, secret, 999'u64, 7, obScalar)
        let simd = hotpSimd(algo, secret, 999'u64, 7, obSimdAvx2)
        check simd == scalar

    test "gimli avx batch matches scalar batch":
      let
        secret = toBytes("otp-secret-gimli-avx-batch")
        nonces: seq[uint64] = @[200'u64, 201'u64, 202'u64, 203'u64, 204'u64,
          205'u64, 206'u64, 207'u64, 208'u64]
      let scalar = hotpBatch(oaGimli, secret, nonces, 8, obScalar)
      let simd = hotpSimdBatch(oaGimli, secret, nonces, 8, obSimdAvx2)
      check simd == scalar
