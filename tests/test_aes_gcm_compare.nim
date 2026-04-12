import std/unittest

when defined(hasLibsodium):
  import ../src/protocols/common
  import ../src/protocols/bindings/nimcrypto
  import ../src/protocols/bindings/libsodium
  import ./helpers

  proc ensureSodiumAvailable(): bool =
    try:
      if not ensureLibSodiumLoaded():
        echo "libsodium unavailable; skipping AES-GCM compare."
        return false
      discard sodium_init()
      true
    except LibraryUnavailableError, OSError:
      echo "libsodium unavailable; skipping AES-GCM compare."
      false

  suite "aes gcm compare":
    test "nimcrypto matches libsodium aes256gcm":
      let available = ensureSodiumAvailable()
      if not available:
        check true
      else:
        if crypto_aead_aes256gcm_is_available() != 1:
          check true
        else:
          let key = toBytes("0123456789abcdef0123456789abcdef")
          let nonce = toBytes("abcdefghijkl")
          let msg = toBytes("aes gcm compare payload")
          var
            clen: culonglong = 0
            cbuf = newSeq[uint8](msg.len + 16)
            status: cint = 0
          status = crypto_aead_aes256gcm_encrypt(
            cast[ptr uint8](addr cbuf[0]),
            addr clen,
            cast[ptr uint8](unsafeAddr msg[0]),
            culonglong(msg.len),
            nil,
            0,
            nil,
            cast[ptr uint8](unsafeAddr nonce[0]),
            cast[ptr uint8](unsafeAddr key[0])
          )
          check status == 0
          check clen == culonglong(msg.len + 16)
          let libCipher = cbuf[0 ..< msg.len]
          let libTag = cbuf[msg.len ..< msg.len + 16]
          var ctx: Aes256GcmContext
          ctx.init(key, nonce)
          let nimCipher = ctx.encrypt(msg)
          let tagArr = ctx.tag()
          var nimTag = newSeq[uint8](tagArr.len)
          for i, b in tagArr:
            nimTag[i] = b
          check nimCipher == libCipher
          check nimTag == libTag
else:
  suite "aes gcm compare":
    test "libsodium unavailable":
      check true
