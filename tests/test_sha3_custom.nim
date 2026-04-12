import std/unittest

import ../src/protocols/custom_crypto/sha3
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
