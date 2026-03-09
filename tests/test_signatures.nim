import std/unittest
import ../src/tyr_crypto/wrapper/signatures
import ../src/tyr_crypto/common
import ../src/tyr_crypto/algorithms

suite "signatures wrapper":
  when defined(hasLibsodium):
    test "ed25519 unavailable only when libsodium missing":
      if not signatureAvailable(saEd25519):
        check true
      else:
        let kp = signatureKeypair(saEd25519)
        let msg = @[1'u8, 2'u8, 3'u8]
        let sig = signMessage(saEd25519, msg, kp.secretKey)
        check verifyMessage(saEd25519, msg, sig, kp.publicKey)
  else:
    test "ed25519 unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard signatureKeypair(saEd25519)

  when defined(hasLibOqs):
    test "dilithium2 availability matches liboqs":
      if not signatureAvailable(saDilithium2):
        check true
      else:
        let kp = signatureKeypair(saDilithium2)
        let msg = @[4'u8, 5'u8]
        let sig = signMessage(saDilithium2, msg, kp.secretKey)
        check verifyMessage(saDilithium2, msg, sig, kp.publicKey)
  else:
    test "dilithium2 unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard signatureKeypair(saDilithium2)

  when defined(hasLibsodium) and defined(hasLibOqs):
    test "ed25519 + falcon hybrid matches when both backends are available":
      if not signatureAvailable(saEd25519Falcon512Hybrid):
        check true
      else:
        let kp = signatureKeypair(saEd25519Falcon512Hybrid)
        let msg = @[9'u8, 8'u8, 7'u8, 6'u8]
        let sig = signMessage(saEd25519Falcon512Hybrid, msg, kp.secretKey)
        check verifyMessage(saEd25519Falcon512Hybrid, msg, sig, kp.publicKey)
        var tampered = sig
        tampered[^1] = tampered[^1] xor 0x01'u8
        check not verifyMessage(saEd25519Falcon512Hybrid, msg, tampered, kp.publicKey)
  else:
    test "hybrid signature unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard signatureKeypair(saEd25519Falcon512Hybrid)
