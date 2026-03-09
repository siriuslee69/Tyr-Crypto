import std/unittest
import ../src/tyr_crypto/common
import ../src/tyr_crypto/bindings/libsodium

when defined(hasLibsodium):
  import ./helpers
  import ./crypto_vectors

suite "libsodium bindings":
  when defined(hasLibsodium):
    proc ensureSodiumAvailable(): bool =
      try:
        if not ensureLibSodiumLoaded():
          echo "libsodium shared library unavailable at runtime; skipping libsodium tests."
          return false
        ensureSodiumInitialised()
        true
      except LibraryUnavailableError, OSError:
        echo "libsodium shared library unavailable at runtime; skipping libsodium tests."
        false

    test "XChaCha20-Poly1305 encrypt/decrypt roundtrip":
      let available = ensureSodiumAvailable()
      if not available:
        check true
      else:
        let keyLen = int crypto_aead_xchacha20poly1305_ietf_keybytes()
        let nonceLen = int crypto_aead_xchacha20poly1305_ietf_npubbytes()
        check keyLen > 0
        check nonceLen > 0

        var key = newSeq[byte](keyLen)
        var nonce = newSeq[byte](nonceLen)
        for i in 0 ..< key.len:
          key[i] = byte(i)
        for i in 0 ..< nonce.len:
          nonce[i] = byte(i + 10)

        let plaintextStr = "postquantum mail payload"
        var plaintext = newSeq[byte](plaintextStr.len)
        for i, ch in plaintextStr:
          plaintext[i] = byte(ord(ch))
        var ciphertext = newSeq[byte](plaintext.len + 16)
        var ciphertextLen: culonglong = 0

        let encStatus = crypto_aead_xchacha20poly1305_ietf_encrypt(
          if ciphertext.len > 0: addr ciphertext[0] else: nil,
          addr ciphertextLen,
          if plaintext.len > 0: addr plaintext[0] else: nil,
          culonglong(plaintext.len),
          nil,
          0,
          nil,
          if nonce.len > 0: addr nonce[0] else: nil,
          if key.len > 0: addr key[0] else: nil
        )
        check encStatus == 0
        ciphertext.setLen(int ciphertextLen)

        var tag = newSeq[byte](16)
        for i in 0 ..< tag.len:
          tag[i] = byte(ciphertext[ciphertext.len - tag.len + i])

        echo "libsodium ciphertext: ", toHex(ciphertext)
        echo "libsodium tag: ", toHex(tag)

        var decrypted = newSeq[byte](plaintext.len)
        var decryptedLen: culonglong = 0
        let decStatus = crypto_aead_xchacha20poly1305_ietf_decrypt(
          if decrypted.len > 0: addr decrypted[0] else: nil,
          addr decryptedLen,
          nil,
          if ciphertext.len > 0: addr ciphertext[0] else: nil,
          culonglong(ciphertext.len),
          nil,
          0,
          if nonce.len > 0: addr nonce[0] else: nil,
          if key.len > 0: addr key[0] else: nil
        )
        check decStatus == 0
        decrypted.setLen(int decryptedLen)
        check decrypted == plaintext

    test "XChaCha20-Poly1305 matches libsodium vector":
      let available = ensureSodiumAvailable()
      if not available:
        check true
      else:
        let vec = xchacha20Poly1305Vector
        let key = hexToBytes(vec.keyHex)
        let nonce = hexToBytes(vec.nonceHex)
        let ad = hexToBytes(vec.adHex)

        var plaintext = newSeq[byte](vec.message.len)
        for i, ch in vec.message:
          plaintext[i] = byte(ord(ch))

        var ciphertext = newSeq[byte](plaintext.len + 16)
        var ciphertextLen: culonglong = 0
        let encStatus = crypto_aead_xchacha20poly1305_ietf_encrypt(
          if ciphertext.len > 0: addr ciphertext[0] else: nil,
          addr ciphertextLen,
          if plaintext.len > 0: addr plaintext[0] else: nil,
          culonglong(plaintext.len),
          if ad.len > 0: unsafeAddr ad[0] else: nil,
          culonglong(ad.len),
          nil,
          if nonce.len > 0: unsafeAddr nonce[0] else: nil,
          if key.len > 0: unsafeAddr key[0] else: nil
        )
        check encStatus == 0
        ciphertext.setLen(int ciphertextLen)
        check toHex(ciphertext) == vec.cipherHex

        var decrypted = newSeq[byte](plaintext.len)
        var decryptedLen: culonglong = 0
        let decStatus = crypto_aead_xchacha20poly1305_ietf_decrypt(
          if decrypted.len > 0: addr decrypted[0] else: nil,
          addr decryptedLen,
          nil,
          if ciphertext.len > 0: addr ciphertext[0] else: nil,
          culonglong(ciphertext.len),
          if ad.len > 0: unsafeAddr ad[0] else: nil,
          culonglong(ad.len),
          if nonce.len > 0: unsafeAddr nonce[0] else: nil,
          if key.len > 0: unsafeAddr key[0] else: nil
        )
        check decStatus == 0
        decrypted.setLen(int decryptedLen)
        check decrypted == plaintext

    test "Argon2id string vectors verify":
      let available = ensureSodiumAvailable()
      if not available:
        check true
      else:
        for vec in argon2idVectors:
          let status = crypto_pwhash_str_verify(
            cstring(vec.encoded),
            cstring(vec.password),
            culonglong(vec.password.len)
          )
          if vec.shouldPass:
            check status == 0
          else:
            check status != 0

    test "Curve25519 scalarmult matches vector":
      let available = ensureSodiumAvailable()
      if not available:
        check true
      else:
        let vec = curve25519Vector
        let sk = hexToBytes(vec.skHex)
        let pk = hexToBytes(vec.pkHex)
        let expected = hexToBytes(vec.sharedHex)

        var shared = newSeq[byte](expected.len)
        check crypto_scalarmult_curve25519(addr shared[0], unsafeAddr sk[0], unsafeAddr pk[0]) == 0
        check shared == expected

    test "Curve25519 key exchange roundtrip":
      let available = ensureSodiumAvailable()
      if not available:
        check true
      else:
        var pkA = newSeq[byte](32)
        var pkB = newSeq[byte](32)
        var skA = newSeq[byte](32)
        var skB = newSeq[byte](32)
        check crypto_kx_keypair(addr pkA[0], addr skA[0]) == 0
        check crypto_kx_keypair(addr pkB[0], addr skB[0]) == 0

        var sharedA = newSeq[byte](32)
        var sharedB = newSeq[byte](32)
        check crypto_scalarmult_curve25519(addr sharedA[0], addr skA[0], addr pkB[0]) == 0
        check crypto_scalarmult_curve25519(addr sharedB[0], addr skB[0], addr pkA[0]) == 0
        check sharedA == sharedB
  else:
    test "libsodium unavailable raises descriptive error":
      expect LibraryUnavailableError:
        ensureSodiumInitialised()
