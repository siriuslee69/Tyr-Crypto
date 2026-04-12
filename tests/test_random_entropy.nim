import std/unittest
import ../src/protocols/custom_crypto/random

suite "entropy-mixed crypto random":
  test "returns requested length without extra entropy":
    let bytes = cryptoRandomBytes(64)
    check bytes.len == 64

  test "returns requested length with byte-array entropy":
    let entropy: array[8, byte] = [1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8]
    let bytes = cryptoRandomBytes(48, entropy)
    check bytes.len == 48

  test "accepts char-based entropy":
    let bytes = cryptoRandomBytes(48, "user-jitter-and-runtime-stats")
    check bytes.len == 48

  test "accepts int8-based entropy":
    let entropy: array[6, int8] = [int8(-5), int8(2), int8(7), int8(11), int8(0), int8(99)]
    let bytes = cryptoRandomBytes(32, entropy)
    check bytes.len == 32

  test "two invocations are distinct even with same entropy":
    let entropy = "cpu=72;mem=65;req=11384"
    let a = cryptoRandomBytes(32, entropy)
    let b = cryptoRandomBytes(32, entropy)
    check a != b

  test "rejects negative lengths":
    expect ValueError:
      discard cryptoRandomBytes(-1)
