## AEAD state boundaries <- reject mutated state before using crypto keys.
import std/unittest
import tyrPragmas

import ../../src/tyr/aeads

proc stateFor(a: CipherSuite): AeadState {.role: {truthBuilder}.} =
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

  # {.testKind: tkEdgeCase, covers: "validateAeadState".}
  test "unresolved tags and mutated keys are rejected everywhere":
    var
      S: AeadState
      C = AeadCiphertext()
    for a in CipherSuite:
      S = stateFor(a)
      S.tagBytes = 0
      expect ValueError: validateAeadState(S)
      expect ValueError: discard seal(@[], S)
      expect ValueError: discard open(C, S)
      expect ValueError: discard compositeTag(@[], S)
      expect ValueError: discard authFrame(@[], S)
      S = stateFor(a)
      S.keys[0] = @[]
      expect ValueError: validateAeadState(S)

  # {.testKind: tkEdgeCase, covers: "gcmSeal, gcmOpen".}
  test "direct GCM rejects nil and non-GCM state":
    var
      C = AeadCiphertext(auth: newSeq[byte](16), authType: atAeadTag)
    expect ValueError: discard gcmSeal(@[], nil)
    expect ValueError: discard gcmOpen(C, nil)
    expect ValueError: discard gcmSeal(@[], stateFor(csXChaCha20Blake3))
    expect ValueError: discard gcmOpen(C, stateFor(csXChaCha20Blake3))
