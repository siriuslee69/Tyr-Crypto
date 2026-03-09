import std/unittest
import ../src/tyr_crypto/common
import ../src/tyr_crypto/bindings/liboqs

when defined(hasLibOqs):
  import ./helpers

  proc previewHex(data: openArray[byte]; head = 20; tail = 20): string =
    let hex = toHex(data)
    if hex.len <= head + tail + 3:
      return hex
    result = hex[0 ..< head] & "..." & hex[hex.len - tail ..< hex.len]

  proc exerciseKem(algId: string) =
    let kem = OQS_KEM_new(algId)
    if kem == nil:
      echo "KEM " & algId & " unavailable; skipping."
      return
    defer:
      OQS_KEM_free(kem)

    let pubLen = int kem[].length_public_key
    let secLen = int kem[].length_secret_key
    let ctLen = int kem[].length_ciphertext
    let sharedLen = int kem[].length_shared_secret

    var pk = newSeq[uint8](pubLen)
    var sk = newSeq[uint8](secLen)
    requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "OQS_KEM_keypair(" & algId & ")")

    var ciphertext = newSeq[uint8](ctLen)
    var sharedSecretEnc = newSeq[uint8](sharedLen)

    requireSuccess(OQS_KEM_encaps(kem, addr ciphertext[0], addr sharedSecretEnc[0], addr pk[0]), "OQS_KEM_encaps(" & algId & ")")

    var sharedSecretDec = newSeq[uint8](sharedLen)
    requireSuccess(OQS_KEM_decaps(kem, addr sharedSecretDec[0], addr ciphertext[0], addr sk[0]), "OQS_KEM_decaps(" & algId & ")")
    echo "liboqs " & algId & " key sizes: pk=" & $pk.len & " bytes, sk=" & $sk.len & " bytes"
    echo "liboqs " & algId & " ciphertext size: " & $ciphertext.len & " bytes"
    echo "liboqs " & algId & " shared secret size: " & $sharedSecretEnc.len & " bytes"

    echo "liboqs " & algId & " ciphertext: ", previewHex(ciphertext)
    echo "liboqs " & algId & " shared secret: ", toHex(sharedSecretEnc)
    check sharedSecretEnc == sharedSecretDec

suite "liboqs bindings":
  when defined(hasLibOqs):
    proc ensureLibOqsAvailable(): bool =
      try:
        if not ensureLibOqsLoaded():
          echo "liboqs shared library unavailable at runtime; skipping liboqs tests."
          return false
        let testKem = OQS_KEM_new(oqsAlgKyber768)
        if testKem != nil:
          OQS_KEM_free(testKem)
        return testKem != nil
      except LibraryUnavailableError, OSError, IOError:
        echo "liboqs shared library unavailable at runtime; skipping liboqs tests."
        return false

    test "Kyber768 encapsulation/decapsulation":
      let available = ensureLibOqsAvailable()
      if available:
        exerciseKem(oqsAlgKyber768)

    test "Additional KEM encapsulation/decapsulation":
      let available = ensureLibOqsAvailable()
      if available:
        for alg in [
          oqsAlgKyber1024,
          oqsAlgFrodoKEM976,
          oqsAlgClassicMcEliece6688128f,
          oqsAlgClassicMcEliece6688128,
          oqsAlgClassicMcEliece6960119f,
          oqsAlgClassicMcEliece8192128f,
          oqsAlgNtruPrimeSntrup653,
          oqsAlgBIKEL2
        ]:
          exerciseKem(alg)

    test "Dilithium2 signature sign/verify":
      let available = ensureLibOqsAvailable()
      if available:
        let sig = OQS_SIG_new(oqsSigDilithium2)
        if sig == nil:
          echo "liboqs Dilithium2 implementation unavailable; skipping signature test."
        else:
          defer:
            OQS_SIG_free(sig)

          var pk = newSeq[uint8](int sig[].length_public_key)
          var sk = newSeq[uint8](int sig[].length_secret_key)
          requireSuccess(OQS_SIG_keypair(sig, addr pk[0], addr sk[0]), "OQS_SIG_keypair")

          const messageStr = "liboqs signature test"
          var msg = newSeq[uint8](messageStr.len)
          for i, ch in messageStr:
            msg[i] = uint8(ord(ch))

          var sigLen: csize_t = 0
          var signature = newSeq[uint8](int sig[].length_signature)
          requireSuccess(OQS_SIG_sign(sig, addr signature[0], addr sigLen, addr msg[0], csize_t(msg.len), addr sk[0]), "OQS_SIG_sign")
          signature.setLen(int sigLen)

          echo "liboqs Dilithium2 key sizes: pk=" & $pk.len & " bytes, sk=" & $sk.len & " bytes"
          echo "liboqs Dilithium2 signature size: " & $signature.len & " bytes"
          echo "liboqs signature: ", toHex(signature)
          requireSuccess(OQS_SIG_verify(sig, addr msg[0], csize_t(msg.len), addr signature[0], csize_t(signature.len), addr pk[0]), "OQS_SIG_verify")
  else:
    test "liboqs unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard OQS_KEM_new(oqsAlgKyber768)
