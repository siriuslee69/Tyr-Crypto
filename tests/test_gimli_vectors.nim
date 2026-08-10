import std/unittest
import ../src/protocols/custom_crypto/gimli

suite "gimli vectors":
  test "c-ref test vector matches":
    var
      st: Gimli_Block
      i: int = 0
      expected: array[12, uint32]
    i = 0
    while i < 12:
      st[i] = uint32(i * i * i) + uint32(i) * 0x9e3779b9'u32
      i = i + 1
    expected[0] = 0xba11c85a'u32
    expected[1] = 0x91bad119'u32
    expected[2] = 0x380ce880'u32
    expected[3] = 0xd24c2c68'u32
    expected[4] = 0x3eceffea'u32
    expected[5] = 0x277a921c'u32
    expected[6] = 0x4f73a0bd'u32
    expected[7] = 0xda5a9cd8'u32
    expected[8] = 0x84b673f0'u32
    expected[9] = 0x34e52ff7'u32
    expected[10] = 0x9e2bef49'u32
    expected[11] = 0xf41bb8d6'u32
    gimliPermute(st)
    check st == expected
