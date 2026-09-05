## ------------------------------------------------------------------
## | Cipher Runtime Tests <- the runtime pick must match a direct call |
## ------------------------------------------------------------------

import std/unittest

import ../../src/tyr/ciphers
import ../../src/tyr/ciphers/dynamic

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
    for c in CipherFamily:
      n = newSeq[byte](nonceBytes(c))
      i = 0
      while i < n.len:
        n[i] = byte(255 - i)
        i = i + 1
      ct = encryptOf(c, k, n, msg)
      check ct.len == msg.len
      check ct != msg
      check decryptOf(c, k, n, ct) == msg

  test "runtime pick equals calling the algorithm directly":
    var
      k: seq[byte] = newSeq[byte](32)
      msg: seq[byte] = @[9'u8, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    check cipherXorOf(cfXChaCha20, k, newSeq[byte](24), msg) ==
      xchacha20Xor(k, newSeq[byte](24), msg)
    check cipherXorOf(cfChaCha20, k, newSeq[byte](12), msg) ==
      chacha20Xor(k, newSeq[byte](12), msg)
    check cipherXorOf(cfAesCtr, k, newSeq[byte](16), msg) ==
      aesCtrXor(k, newSeq[byte](16), msg)
    check cipherXorOf(cfGimliStream, k, newSeq[byte](24), msg) ==
      gimliStreamXor(k, newSeq[byte](24), msg)

  test "names survive a write-then-read trip":
    for c in CipherFamily:
      check parseCipherFamily(familyName(c)) == c
    expect ValueError:
      discard parseCipherFamily("no-such-cipher")

  test "wrong key or nonce size is refused before any cipher runs":
    var k: seq[byte] = newSeq[byte](32)
    for c in CipherFamily:
      expect ValueError:
        discard cipherXorOf(c, newSeq[byte](31), newSeq[byte](nonceBytes(c)), @[1'u8])
      expect ValueError:
        discard cipherXorOf(c, k, newSeq[byte](nonceBytes(c) + 1), @[1'u8])

  test "declared sizes match what the ciphers accept":
    check nonceBytes(cfXChaCha20) == 24
    check nonceBytes(cfChaCha20) == 12
    check nonceBytes(cfAesCtr) == 16
    check nonceBytes(cfGimliStream) == 24
    for c in CipherFamily:
      check keyBytes(c) == 32
