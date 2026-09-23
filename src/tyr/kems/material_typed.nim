## Typed KEM material wrappers included by material.nim.
##
## These wrappers share material.nim's imports and dispatch helpers.

## ╭⟢ Sealing and opening from typed material

proc seal*(m: x25519SendM): AsymCipher =
  ## Encapsulate or derive a shared secret using typed X25519 send material.
  result = encaps(kaX25519, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: x25519OpenM): seq[byte] =
  ## Recover a shared secret using typed X25519 open material.
  result = decaps(kaX25519, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber0SendM): AsymCipher =
  result = encaps(kaKyber0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: kyber0OpenM): seq[byte] =
  result = decaps(kaKyber0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber1SendM): AsymCipher =
  result = encaps(kaKyber1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: kyber1OpenM): seq[byte] =
  result = decaps(kaKyber1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr Kyber tier-0 backend.
  var env = customKyber.kyberTyrEncaps(customKyber.kyber768, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: kyber0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr Kyber tier-0 backend.
  result = customKyber.kyberTyrDecaps(customKyber.kyber768,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: kyber1TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr Kyber tier-1 backend.
  var env = customKyber.kyberTyrEncaps(customKyber.kyber1024, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: kyber1TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr Kyber tier-1 backend.
  result = customKyber.kyberTyrDecaps(customKyber.kyber1024,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece0SendM): AsymCipher =
  result = encaps(kaMcEliece0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece0OpenM): seq[byte] =
  result = decaps(kaMcEliece0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece1SendM): AsymCipher =
  result = encaps(kaMcEliece1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece1OpenM): seq[byte] =
  result = decaps(kaMcEliece1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece2SendM): AsymCipher =
  result = encaps(kaMcEliece2, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece2OpenM): seq[byte] =
  result = decaps(kaMcEliece2, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece1TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece1TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece2TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece2TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc buildFrodoTyrSeal(v: customFrodo.FrodoVariant, pk: openArray[byte]): AsymCipher =
  var env = customFrodo.frodoTyrEncaps(v, toSeqBytes(pk))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc buildFrodoTyrOpen(v: customFrodo.FrodoVariant, sk: openArray[byte],
    env: AsymEnvelope): seq[byte] =
  result = customFrodo.frodoTyrDecaps(v, toSeqBytes(sk), env.ciphertext)

proc seal*(m: frodo0AesSendM): AsymCipher =
  result = encaps(kaFrodo0Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo0AesOpenM): seq[byte] =
  result = decaps(kaFrodo0Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo0ShakeSendM): AsymCipher =
  result = encaps(kaFrodo0Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo0ShakeOpenM): seq[byte] =
  result = decaps(kaFrodo0Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo1AesSendM): AsymCipher =
  result = encaps(kaFrodo1Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo1AesOpenM): seq[byte] =
  result = decaps(kaFrodo1Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo1ShakeSendM): AsymCipher =
  result = encaps(kaFrodo1Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo1ShakeOpenM): seq[byte] =
  result = decaps(kaFrodo1Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo2AesSendM): AsymCipher =
  result = encaps(kaFrodo2Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo2AesOpenM): seq[byte] =
  result = decaps(kaFrodo2Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo2ShakeSendM): AsymCipher =
  result = encaps(kaFrodo2Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo2ShakeOpenM): seq[byte] =
  result = decaps(kaFrodo2Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo0AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo640aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo0AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo640aes, m.receiverSecretKey, env)

proc seal*(m: frodo0ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo640shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo0ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo640shake, m.receiverSecretKey, env)

proc seal*(m: frodo1AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo976aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo1AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo976aes, m.receiverSecretKey, env)

proc seal*(m: frodo1ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo976shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo1ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo976shake, m.receiverSecretKey, env)

proc seal*(m: frodo2AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo1344aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo2AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo1344aes, m.receiverSecretKey, env)

proc seal*(m: frodo2ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo1344shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo2ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo1344shake, m.receiverSecretKey, env)

proc seal*(m: ntruprime0SendM): AsymCipher =
  result = encaps(kaNtruPrime0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: ntruprime0OpenM): seq[byte] =
  result = decaps(kaNtruPrime0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: bike0SendM): AsymCipher =
  result = encaps(kaBike0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: bike0OpenM): seq[byte] =
  result = decaps(kaBike0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: bike0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr BIKE tier-0 backend.
  var env = customBike.bikeTyrEncaps(customBike.bikeL1, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: bike0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr BIKE tier-0 backend.
  result = customBike.bikeTyrDecaps(customBike.bikeL1,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

## ╭⟢ Tyr-only families, one template per variant
##
## Each call below writes the six routines a material pair needs:
##
##   algorithmOf(SendT)  algorithmOf(OpenT)   -> the layout-table entry
##   genKeypair(SendT)   genKeypair(OpenT)    -> fresh keys from system entropy
##   seal(SendT)                              -> ciphertext + shared secret
##   open(envelope, OpenT)                    -> the same shared secret
##
## The family's own routines do the work; this only moves bytes between
## the fixed-size material and the family's seq-based API.

template tyrKemMaterial(SendT, OpenT: untyped, sendKind, openKind: AlgorithmKind,
    variant: untyped, keypairFn, encapsFn, decapsFn: untyped) =
  proc algorithmOf*(T: typedesc[SendT]): AlgorithmKind {.role: {helper}.} = sendKind
  proc algorithmOf*(T: typedesc[OpenT]): AlgorithmKind {.role: {helper}.} = openKind

  proc genKeypair*(T: typedesc[SendT]): AsymKeypair {.role: {orchestrator}.} =
    ## T: the send-side material type. Keys come from system entropy.
    var
      kp = keypairFn(variant)
    result.publicKey = kp.publicKey
    result.secretKey = kp.secretKey

  proc genKeypair*(T: typedesc[OpenT]): AsymKeypair {.role: {orchestrator}.} =
    ## T: the open-side material type; same keys as the send side.
    result = genKeypair(SendT)

  proc seal*(m: SendT): AsymCipher {.role: {encryptor}.} =
    ## m: the receiver's public key. Only `.envelope` goes on the wire.
    var
      env = encapsFn(variant, toSeqBytes(m.receiverPublicKey))
    result.envelope.ciphertext = env.ciphertext
    result.envelope.senderPublicKey = @[]
    result.sharedSecret = env.sharedSecret

  proc open*(env: AsymEnvelope, m: OpenT): seq[byte] {.role: {decryptor}.} =
    ## env/m: the received envelope and your secret key.
    result = decapsFn(variant, toSeqBytes(m.receiverSecretKey), env.ciphertext)

tyrKemMaterial(ntru0TyrSendM, ntru0TyrOpenM, akNtru0TyrSend, akNtru0TyrOpen,
  customNtru.ntruHps2048509, customNtru.ntruTyrKeypair,
  customNtru.ntruTyrEncaps, customNtru.ntruTyrDecaps)
tyrKemMaterial(ntru1TyrSendM, ntru1TyrOpenM, akNtru1TyrSend, akNtru1TyrOpen,
  customNtru.ntruHps2048677, customNtru.ntruTyrKeypair,
  customNtru.ntruTyrEncaps, customNtru.ntruTyrDecaps)
tyrKemMaterial(ntru2TyrSendM, ntru2TyrOpenM, akNtru2TyrSend, akNtru2TyrOpen,
  customNtru.ntruHps4096821, customNtru.ntruTyrKeypair,
  customNtru.ntruTyrEncaps, customNtru.ntruTyrDecaps)
tyrKemMaterial(ntruHrss0TyrSendM, ntruHrss0TyrOpenM, akNtruHrss0TyrSend, akNtruHrss0TyrOpen,
  customNtru.ntruHrss701, customNtru.ntruTyrKeypair,
  customNtru.ntruTyrEncaps, customNtru.ntruTyrDecaps)
tyrKemMaterial(saber0TyrSendM, saber0TyrOpenM, akSaber0TyrSend, akSaber0TyrOpen,
  customSaber.lightSaber, customSaber.saberTyrKeypair,
  customSaber.saberTyrEncaps, customSaber.saberTyrDecaps)
tyrKemMaterial(saber1TyrSendM, saber1TyrOpenM, akSaber1TyrSend, akSaber1TyrOpen,
  customSaber.saber, customSaber.saberTyrKeypair,
  customSaber.saberTyrEncaps, customSaber.saberTyrDecaps)
tyrKemMaterial(saber2TyrSendM, saber2TyrOpenM, akSaber2TyrSend, akSaber2TyrOpen,
  customSaber.fireSaber, customSaber.saberTyrKeypair,
  customSaber.saberTyrEncaps, customSaber.saberTyrDecaps)
tyrKemMaterial(hqc0TyrSendM, hqc0TyrOpenM, akHqc0TyrSend, akHqc0TyrOpen,
  customHqc.hqc1, customHqc.hqcTyrKeypair,
  customHqc.hqcTyrEncaps, customHqc.hqcTyrDecaps)
tyrKemMaterial(hqc1TyrSendM, hqc1TyrOpenM, akHqc1TyrSend, akHqc1TyrOpen,
  customHqc.hqc3, customHqc.hqcTyrKeypair,
  customHqc.hqcTyrEncaps, customHqc.hqcTyrDecaps)
tyrKemMaterial(hqc2TyrSendM, hqc2TyrOpenM, akHqc2TyrSend, akHqc2TyrOpen,
  customHqc.hqc5, customHqc.hqcTyrKeypair,
  customHqc.hqcTyrEncaps, customHqc.hqcTyrDecaps)

proc open*[T](cipher: AsymCipher, m: T): seq[byte] =
  ## Recover a shared secret from the public envelope inside a local result.
  result = open(cipher.envelope, m)

proc seal*[A, B](a: A, b: B): array[2, AsymCipher] =
  ## Convenience helper for composing two independent KEM/ECDH sends.
  result[0] = seal(a)
  result[1] = seal(b)

proc seal*[A, B, C](a: A, b: B, c: C): array[3, AsymCipher] =
  ## Convenience helper for composing three independent KEM/ECDH sends.
  result[0] = seal(a)
  result[1] = seal(b)
  result[2] = seal(c)

proc open*[A, B](envs: array[2, AsymEnvelope], a: A, b: B): array[2, seq[byte]] =
  ## Convenience helper for opening two public KEM/ECDH envelopes.
  result[0] = open(envs[0], a)
  result[1] = open(envs[1], b)

proc open*[A, B](ciphers: array[2, AsymCipher], a: A, b: B): array[2, seq[byte]] =
  ## Convenience helper for opening two local KEM/ECDH results.
  result[0] = open(ciphers[0], a)
  result[1] = open(ciphers[1], b)

proc open*[A, B, C](envs: array[3, AsymEnvelope], a: A, b: B,
    c: C): array[3, seq[byte]] =
  ## Convenience helper for opening three public KEM/ECDH envelopes.
  result[0] = open(envs[0], a)
  result[1] = open(envs[1], b)
  result[2] = open(envs[2], c)

proc open*[A, B, C](ciphers: array[3, AsymCipher], a: A, b: B,
    c: C): array[3, seq[byte]] =
  ## Convenience helper for opening three local KEM/ECDH results.
  result[0] = open(ciphers[0], a)
  result[1] = open(ciphers[1], b)
  result[2] = open(ciphers[2], c)
