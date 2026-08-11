## ------------------------------------------------------------------
## | Cipher Runtime Tests <- the runtime pick must match a direct call |
## ------------------------------------------------------------------

import std/unittest

import ../src/protocols/ciphers

suite "cipher runtime selection":

  test "every cipher round-trips through the runtime case":
    var
      k: seq[byte] = newSeq[byte](32)
      n: seq[byte] = @[]
      msg: seq[byte] = @[]
      ct: seq[byte] = @[]
      i: int = 0
    i = 0
    while i < 32:
      k[i] = byte(i * 7 + 1)
      i = i + 1
    i = 0
    while i < 200:
      msg.add byte(i)
      i = i + 1
    for c in TyrCipher:
      n = newSeq[byte](nonceBytes(c))
      i = 0
      while i < n.len:
        n[i] = byte(255 - i)
        i = i + 1
      ct = tyrCipherEncrypt(c, k, n, msg)
      check ct.len == msg.len
      check ct != msg
      check tyrCipherDecrypt(c, k, n, ct) == msg

  test "runtime pick equals calling the algorithm directly":
    var
      k: seq[byte] = newSeq[byte](32)
      msg: seq[byte] = @[9'u8, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    check tyrCipherXor(tcXChaCha20, k, newSeq[byte](24), msg) ==
      xchacha20Xor(k, newSeq[byte](24), msg)
    check tyrCipherXor(tcChaCha20, k, newSeq[byte](12), msg) ==
      chacha20Xor(k, newSeq[byte](12), msg)
    check tyrCipherXor(tcAesCtr, k, newSeq[byte](16), msg) ==
      aesCtrXor(k, newSeq[byte](16), msg)
    check tyrCipherXor(tcGimliStream, k, newSeq[byte](24), msg) ==
      gimliStreamXor(k, newSeq[byte](24), msg)

  test "names survive a write-then-read trip":
    for c in TyrCipher:
      check parseTyrCipher(cipherName(c)) == c
    expect ValueError:
      discard parseTyrCipher("no-such-cipher")

  test "wrong key or nonce size is refused before any cipher runs":
    var k: seq[byte] = newSeq[byte](32)
    for c in TyrCipher:
      expect ValueError:
        discard tyrCipherXor(c, newSeq[byte](31), newSeq[byte](nonceBytes(c)), @[1'u8])
      expect ValueError:
        discard tyrCipherXor(c, k, newSeq[byte](nonceBytes(c) + 1), @[1'u8])

  test "declared sizes match what the ciphers accept":
    check nonceBytes(tcXChaCha20) == 24
    check nonceBytes(tcChaCha20) == 12
    check nonceBytes(tcAesCtr) == 16
    check nonceBytes(tcGimliStream) == 24
    for c in TyrCipher:
      check keyBytes(c) == 32
