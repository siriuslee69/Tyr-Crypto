import std/unittest
import ../src/tyr_crypto/wrapper/pin_key
import ../src/tyr_crypto/common

when defined(hasLibsodium):
  import ../src/tyr_crypto/wrapper/crypto
  import ../src/tyr_crypto/bindings/libsodium
  proc sodiumAvailable(): bool =
    try:
      if not ensureLibSodiumLoaded():
        return false
      ensureSodiumInitialised()
      return true
    except LibraryUnavailableError, OSError, IOError, CryptoOperationError:
      return false

  if not sodiumAvailable():
    suite "pin key wrapper unavailable":
      test "libsodium unavailable at runtime":
        check true
  else:
    suite "pin key wrapper":
      test "derive key and encrypt with pin KDF":
        var key = deriveKeyFromPassword("test-password", "1234")
        check key.encryptedMasterKey.len > 0
        check key.masterKeyNonce.len > 0
        check key.pinKdf.len > 0
        check key.pinOpsLimit > 0'u64
        check key.pinMemLimit > 0

        let plaintext = @[1'u8, 2, 3, 4, 5]
        let sealed = encryptWithKey(key, plaintext)
        check sealed.nonce.len == 24
        check sealed.ciphertext.len == plaintext.len
        check sealed.hmac.len == 16
        check key.pinKdf.len == 0

      test "missing pin KDF raises error":
        var key = deriveKeyFromPassword("test-password", "5678")
        key.pinKdf.setLen(0)
        expect ValueError:
          discard encryptWithKey(key, @[9'u8])

      test "derive symmetric keys from password":
        let derived = deriveSymmetricKeysFromString(xchacha20Gimli, "pw", @[], 0'u16)
        check derived.state.keys.len == 2
        check derived.state.keys[0].key.len == 32
        check derived.state.keys[1].key.len == 32
        check derived.state.nonce.len == 24
        check derived.kdf.argon2Salt.len == int crypto_pwhash_saltbytes()

      test "derive layered symmetric keys from password":
        let aesGimliKeys = deriveSymmetricKeysFromString(aesGimli, "pw", @[], 0'u16)
        check aesGimliKeys.state.keys.len == 2
        check aesGimliKeys.state.nonce.len == 24
        let dualMacKeys = deriveSymmetricKeysFromString(
          xchacha20AesGimliPoly1305, "pw", @[], 0'u16)
        check dualMacKeys.state.keys.len == 4
        check dualMacKeys.state.nonce.len == 24

      test "derive symmetric keys deterministic with salt":
        let salt = deriveSymmetricKeysFromString(chacha20, "pw", @[], 0'u16).kdf.argon2Salt
        let d0 = deriveSymmetricKeysFromBytesWithSalt(chacha20, @[byte 1, 2, 3], salt, 0'u64, 0, @[], 0'u16)
        let d1 = deriveSymmetricKeysFromBytesWithSalt(chacha20, @[byte 1, 2, 3], salt, 0'u64, 0, @[], 0'u16)
        check d0.state.keys[0].key == d1.state.keys[0].key

      test "derive hybrid kex seed from password":
        let seed = deriveHybridKexDuoSeedFromString("pw")
        check seed.x25519Seed.len == int crypto_kx_seedbytes()
else:
  suite "pin key wrapper unavailable":
    test "libsodium unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard deriveKeyFromPassword("pw", "1234")
