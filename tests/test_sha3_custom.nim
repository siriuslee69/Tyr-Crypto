import std/unittest

import ../src/protocols/custom_crypto/symmetric/sha3/sha3
import ./helpers

suite "sha3 custom crypto":
  test "SHA3-256 empty vector":
    let expected = hexToBytes("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    check sha3Hash(@[], 32) == expected

  test "SHA3-256 abc vector":
    let expected = hexToBytes("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    check sha3Hash(@[byte('a'), byte('b'), byte('c')], 32) == expected

  test "SHA3-512 empty vector":
    let expected = hexToBytes(
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" &
      "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")
    check sha3Hash(@[], 64) == expected

  test "SHA3 rejects unsupported output length":
    expect ValueError:
      discard sha3Hash(@[byte 1, 2, 3], 31)

  test "SHAKE absorb-once resets reusable caller state":
    var
      msg = @[byte 1, 2, 3, 4, 5]
      S: Sha3State
      out1280: array[shake128RateBytes, byte]
      out1281: array[shake128RateBytes, byte]
      out2560: array[shake256RateBytes, byte]
      out2561: array[shake256RateBytes, byte]
    shake128AbsorbOnce(S, msg)
    shake128SqueezeBlocksInto(S, out1280)
    shake128AbsorbOnce(S, msg)
    shake128SqueezeBlocksInto(S, out1281)
    check out1280 == out1281
    check @out1280 == shake128(msg, shake128RateBytes)
    shake256AbsorbOnce(S, msg)
    shake256SqueezeBlocksInto(S, out2560)
    shake256AbsorbOnce(S, msg)
    shake256SqueezeBlocksInto(S, out2561)
    check out2560 == out2561
    check @out2560 == shake256(msg, shake256RateBytes)
