import std/unittest

import ../src/protocols/custom_crypto/poly1305
import ./helpers

suite "poly1305 custom crypto":
  test "RFC 8439 Poly1305 vector":
    let
      key = hexToBytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
      msg = toBytes("Cryptographic Forum Research Group")
      expected = hexToBytes("a8061dc1305136c6c22b8baf0c0127a9")
    check poly1305Tag(key, msg) == expected
    check poly1305Verify(key, msg, expected)

  test "Poly1305 tag changes when message changes":
    let
      key = hexToBytes("1111111111111111111111111111111111111111111111111111111111111111")
      msg = toBytes("poly1305 scalar message")
    var
      tag = poly1305Tag(key, msg)
      bad = toBytes("poly1305 scalar message")
    bad[0] = bad[0] xor 0x01'u8
    check not poly1305Verify(key, bad, tag)

  test "Poly1305 rejects wrong key length":
    expect ValueError:
      discard poly1305Tag(@[byte 1, 2, 3], @[byte 4, 5, 6])
