## ------------------------------------------------------------
## Ed25519 <- public facade for pure Nim Ed25519 operations
## ------------------------------------------------------------

import ./asymmetric/none_pq/ed25519_impl

export Ed25519Keypair, Ed25519Bytes32, Ed25519Bytes64
export ed25519SeedBytes, ed25519PublicKeyBytes, ed25519SecretKeyBytes,
  ed25519SignatureBytes

proc ed25519TyrPublicKey*(seed: openArray[byte]): seq[byte] =
  result = ed25519_impl.ed25519TyrPublicKey(seed)

proc ed25519TyrKeypairFromSeed*(seed: openArray[byte]): Ed25519Keypair =
  result = ed25519_impl.ed25519TyrKeypairFromSeed(seed)

proc ed25519TyrKeypair*(): Ed25519Keypair =
  result = ed25519_impl.ed25519TyrKeypair()

proc ed25519TyrSign*(message, secretKey: openArray[byte]): seq[byte] =
  result = ed25519_impl.ed25519TyrSign(message, secretKey)

proc ed25519TyrVerify*(message, signature, publicKey: openArray[byte]): bool =
  result = ed25519_impl.ed25519TyrVerify(message, signature, publicKey)

when defined(amd64) or defined(i386):
  proc ed25519TyrSignSse2x*(messages: array[2, seq[byte]],
      secretKeys: array[2, seq[byte]]): array[2, seq[byte]] =
    result = ed25519_impl.ed25519TyrSignSse2x(messages, secretKeys)

  proc ed25519TyrVerifySse2x*(messages, signatures,
      publicKeys: array[2, seq[byte]]): array[2, bool] =
    result = ed25519_impl.ed25519TyrVerifySse2x(messages, signatures, publicKeys)

when defined(avx2):
  proc ed25519TyrSignAvx4x*(messages: array[4, seq[byte]],
      secretKeys: array[4, seq[byte]]): array[4, seq[byte]] =
    result = ed25519_impl.ed25519TyrSignAvx4x(messages, secretKeys)

  proc ed25519TyrVerifyAvx4x*(messages, signatures,
      publicKeys: array[4, seq[byte]]): array[4, bool] =
    result = ed25519_impl.ed25519TyrVerifyAvx4x(messages, signatures, publicKeys)
