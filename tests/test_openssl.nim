import std/unittest
import ../src/tyr_crypto/common
import ../src/tyr_crypto/bindings/openssl

when defined(hasOpenSSL3):
  import ./helpers

suite "OpenSSL bindings":
  when defined(hasOpenSSL3):
    proc ensureOpenSslAvailable(): bool =
      try:
        if not ensureOpenSslLoaded():
          echo "OpenSSL shared library unavailable at runtime; skipping OpenSSL tests."
          return false
        discard OpenSSL_version_num()
        true
      except LibraryUnavailableError, OSError:
        echo "OpenSSL shared library unavailable at runtime; skipping OpenSSL tests."
        false

    test "Ed448 sign/verify roundtrip":
      let available = ensureOpenSslAvailable()
      if not available:
        check true
      else:
        var priv = newSeq[uint8](57)
        for i in 0 ..< priv.len:
          priv[i] = uint8(i)

        let pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, nil, addr priv[0], csize_t(priv.len))
        if pkey == nil:
          echo "OpenSSL Ed448 unavailable; skipping signature test."
          check true
        else:
          defer:
            if pkey != nil:
              EVP_PKEY_free(pkey)

          var pub = newSeq[uint8](57)
          var pubLen = csize_t(pub.len)
          requireOk(EVP_PKEY_get_raw_public_key(pkey, addr pub[0], addr pubLen), "EVP_PKEY_get_raw_public_key")
          pub.setLen(int(pubLen))

          let verifyKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nil, addr pub[0], csize_t(pub.len))
          if verifyKey == nil:
            echo "OpenSSL Ed448 public key creation unavailable; skipping signature test."
            check true
          else:
            defer:
              if verifyKey != nil:
                EVP_PKEY_free(verifyKey)

            const msgStr = "openssl ed448 test"
            var msg = newSeq[uint8](msgStr.len)
            for i, ch in msgStr:
              msg[i] = uint8(ord(ch))

            var signCtx = EVP_MD_CTX_new()
            check signCtx != nil
            defer:
              if signCtx != nil:
                EVP_MD_CTX_free(signCtx)

            var signPctx: ptr EVP_PKEY_CTX = nil
            requireOk(EVP_DigestSignInit_ex(signCtx, addr signPctx, nil, nil, pkey), "EVP_DigestSignInit_ex")

            var sigLen: csize_t = 0
            requireOk(EVP_DigestSign(signCtx, nil, addr sigLen, addr msg[0], csize_t(msg.len)), "EVP_DigestSign(length)")
            var signature = newSeq[uint8](int sigLen)
            requireOk(EVP_DigestSign(signCtx, addr signature[0], addr sigLen, addr msg[0], csize_t(msg.len)), "EVP_DigestSign(data)")
            signature.setLen(int sigLen)

            echo "openssl signature: ", toHex(signature)

            var verifyCtx = EVP_MD_CTX_new()
            check verifyCtx != nil
            defer:
              if verifyCtx != nil:
                EVP_MD_CTX_free(verifyCtx)

            var verifyPctx: ptr EVP_PKEY_CTX = nil
            requireOk(EVP_DigestVerifyInit_ex(verifyCtx, addr verifyPctx, nil, nil, verifyKey), "EVP_DigestVerifyInit_ex")
            requireOk(EVP_DigestVerify(verifyCtx, addr signature[0], csize_t(signature.len), addr msg[0], csize_t(msg.len)), "EVP_DigestVerify")
  else:
    test "OpenSSL unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard OpenSSL_version_num()
