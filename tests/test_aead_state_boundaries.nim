## AEAD state boundaries <- reject mutated state before using crypto keys.
import std/unittest

import ../src/tyr/aeads

proc stateFor(a: CipherSuite): AeadState =
  ## a: suite whose correctly sized keys and nonce are needed by the test.
  var
    K = newSeq[seq[byte]](keyCount(a))
  for i in 0 ..< K.len:
    K[i] = newSeq[byte](32)
  result = initAeadState(a, K, newSeq[byte](nonceBytes(a)))

suite "AEAD state boundaries":
  # {.testKind: tkRegression, covers: "open", pins: "mutable zero-length BLAKE3 authentication tag".}
  test "a mutated zero-length tag cannot authenticate forged bytes":
    var
      S = stateFor(csXChaCha20Blake3)
      C = AeadCiphertext(ciphertext: @[1'u8], auth: @[], authType: atBlake3)
    S.tagBytes = 0
    expect ValueError:
      discard open(C, S)

  # {.testKind: tkEdgeCase, covers: "seal".}
  test "mutated key count is rejected as input":
    var
      S = stateFor(csXChaCha20Blake3)
    S.keys = @[]
    expect ValueError:
      discard seal(@[1'u8], S)

  # {.testKind: tkEdgeCase, covers: "compositeCipher".}
  test "nil and short nonce states fail before indexing":
    var
      S = stateFor(csAesGimli)
    expect ValueError:
      discard compositeCipher(@[1'u8], nil)
    S.nonce = @[]
    expect ValueError:
      discard compositeCipher(@[1'u8], S)

  when defined(hasNimcrypto):
    # {.testKind: tkRegression, covers: "gcmSeal", pins: "direct GCM nonce reuse".}
    test "direct GCM sealing also spends its nonce":
      var
        S = stateFor(csAes256Gcm)
      discard gcmSeal(@[1'u8], S)
      expect ValueError:
        discard gcmSeal(@[2'u8], S)
