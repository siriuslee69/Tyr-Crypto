## ==================================================
## | Hybrid KEX (Triple: Kyber + McEliece + X25519) |
## |-----------------------------------------------|
## | Maximum hedge across PQ + classical systems.  |
## ==================================================

import ../common
import ../algorithms
import ../bindings/liboqs
import ../bindings/libsodium
import ./hybrid_kex_support

const
  hybridContext = "hybrid-kex-v2"

type
  HybridKexOffer* = object
    kyberVariant*: KyberVariant
    mcElieceVariant*: McElieceVariant
    kyberPublicKey*: seq[uint8]
    mcEliecePublicKey*: seq[uint8]
    x25519PublicKey*: seq[uint8]

  HybridKexState* = object
    offer*: HybridKexOffer
    kyberSecretKey*: seq[uint8]
    mcElieceSecretKey*: seq[uint8]
    x25519SecretKey*: seq[uint8]

  HybridKexResponse* = object
    kyberCiphertext*: seq[uint8]
    mcElieceCiphertext*: seq[uint8]
    x25519PublicKey*: seq[uint8]

proc tripleSecret(kyberAlg, mcElieceAlg: string, kyberShared, mcElieceShared,
    x25519SharedSecret: openArray[uint8]): seq[uint8] =
  result = combineLabeledSecrets(hybridContext, [
    (label: kyberAlg, secret: @kyberShared),
    (label: mcElieceAlg, secret: @mcElieceShared),
    (label: "X25519", secret: @x25519SharedSecret)
  ])

proc hybridKexAvailable*(kyberVariant: KyberVariant = kvKyber768,
    mcElieceVariant: McElieceVariant = mvClassicMcEliece6688128): bool =
  try:
    if not ensureLibOqsLoaded() or not ensureLibSodiumLoaded():
      return false
    ensureSodiumInitialised()
    let kyber = OQS_KEM_new(kyberAlgId(kyberVariant).cstring)
    if kyber == nil:
      return false
    OQS_KEM_free(kyber)
    let mcEliece = OQS_KEM_new(mcElieceAlgId(mcElieceVariant).cstring)
    if mcEliece == nil:
      return false
    OQS_KEM_free(mcEliece)
    result = true
  except LibraryUnavailableError, OSError, IOError, CryptoOperationError:
    result = false

proc createHybridKexOffer*(kyberVariant: KyberVariant = kvKyber768,
    mcElieceVariant: McElieceVariant = mvClassicMcEliece6688128): HybridKexState =
  requireHybridKexLibraries()
  let kyber = kemKeypair(kyberAlgId(kyberVariant))
  let mcEliece = kemKeypair(mcElieceAlgId(mcElieceVariant))
  let x25519 = x25519Keypair()
  result = HybridKexState(
    offer: HybridKexOffer(
      kyberVariant: kyberVariant,
      mcElieceVariant: mcElieceVariant,
      kyberPublicKey: kyber.pk,
      mcEliecePublicKey: mcEliece.pk,
      x25519PublicKey: x25519.pk
    ),
    kyberSecretKey: kyber.sk,
    mcElieceSecretKey: mcEliece.sk,
    x25519SecretKey: x25519.sk
  )

proc createHybridKexOfferWithEntropy*[T](kyberVariant: KyberVariant = kvKyber768,
    mcElieceVariant: McElieceVariant = mvClassicMcEliece6688128,
    extraEntropy: openArray[T]): HybridKexState =
  requireHybridKexLibraries()
  let entropyBytes = toEntropyBytes(extraEntropy)
  let kyber = kemKeypair(kyberAlgId(kyberVariant), entropyBytes)
  let mcEliece = kemKeypair(mcElieceAlgId(mcElieceVariant), entropyBytes)
  let x25519 = x25519Keypair()
  result = HybridKexState(
    offer: HybridKexOffer(
      kyberVariant: kyberVariant,
      mcElieceVariant: mcElieceVariant,
      kyberPublicKey: kyber.pk,
      mcEliecePublicKey: mcEliece.pk,
      x25519PublicKey: x25519.pk
    ),
    kyberSecretKey: kyber.sk,
    mcElieceSecretKey: mcEliece.sk,
    x25519SecretKey: x25519.sk
  )

proc createHybridKexOfferFromSeed*(seed: openArray[uint8],
    kyberVariant: KyberVariant = kvKyber768,
    mcElieceVariant: McElieceVariant = mvClassicMcEliece6688128): HybridKexState =
  requireHybridKexLibraries()
  let kyber = kemKeypair(kyberAlgId(kyberVariant))
  let mcEliece = kemKeypair(mcElieceAlgId(mcElieceVariant))
  let x25519 = x25519KeypairFromSeed(seed)
  result = HybridKexState(
    offer: HybridKexOffer(
      kyberVariant: kyberVariant,
      mcElieceVariant: mcElieceVariant,
      kyberPublicKey: kyber.pk,
      mcEliecePublicKey: mcEliece.pk,
      x25519PublicKey: x25519.pk
    ),
    kyberSecretKey: kyber.sk,
    mcElieceSecretKey: mcEliece.sk,
    x25519SecretKey: x25519.sk
  )

proc respondHybridKexOffer*(offer: HybridKexOffer): tuple[
    response: HybridKexResponse, sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let kyberAlg = kyberAlgId(offer.kyberVariant)
  let mcElieceAlg = mcElieceAlgId(offer.mcElieceVariant)
  let kyber = kemEncaps(kyberAlg, offer.kyberPublicKey)
  let mcEliece = kemEncaps(mcElieceAlg, offer.mcEliecePublicKey)
  let eph = x25519Keypair()
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: HybridKexResponse(
      kyberCiphertext: kyber.ciphertext,
      mcElieceCiphertext: mcEliece.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: tripleSecret(kyberAlg, mcElieceAlg, kyber.shared,
      mcEliece.shared, sharedX25519)
  )

proc respondHybridKexOfferWithEntropy*[T](offer: HybridKexOffer,
    extraEntropy: openArray[T]): tuple[response: HybridKexResponse,
    sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let kyberAlg = kyberAlgId(offer.kyberVariant)
  let mcElieceAlg = mcElieceAlgId(offer.mcElieceVariant)
  let entropyBytes = toEntropyBytes(extraEntropy)
  let kyber = kemEncaps(kyberAlg, offer.kyberPublicKey, entropyBytes)
  let mcEliece = kemEncaps(mcElieceAlg, offer.mcEliecePublicKey, entropyBytes)
  let eph = x25519Keypair()
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: HybridKexResponse(
      kyberCiphertext: kyber.ciphertext,
      mcElieceCiphertext: mcEliece.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: tripleSecret(kyberAlg, mcElieceAlg, kyber.shared,
      mcEliece.shared, sharedX25519)
  )

proc respondHybridKexOfferFromSeed*(offer: HybridKexOffer,
    seed: openArray[uint8]): tuple[response: HybridKexResponse,
    sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let kyberAlg = kyberAlgId(offer.kyberVariant)
  let mcElieceAlg = mcElieceAlgId(offer.mcElieceVariant)
  let kyber = kemEncaps(kyberAlg, offer.kyberPublicKey)
  let mcEliece = kemEncaps(mcElieceAlg, offer.mcEliecePublicKey)
  let eph = x25519KeypairFromSeed(seed)
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: HybridKexResponse(
      kyberCiphertext: kyber.ciphertext,
      mcElieceCiphertext: mcEliece.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: tripleSecret(kyberAlg, mcElieceAlg, kyber.shared,
      mcEliece.shared, sharedX25519)
  )

proc finalizeHybridKex*(state: HybridKexState,
    response: HybridKexResponse): seq[uint8] =
  requireHybridKexLibraries()
  if response.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let kyberAlg = kyberAlgId(state.offer.kyberVariant)
  let mcElieceAlg = mcElieceAlgId(state.offer.mcElieceVariant)
  let kyberShared = kemDecaps(kyberAlg, response.kyberCiphertext,
    state.kyberSecretKey)
  let mcElieceShared = kemDecaps(mcElieceAlg, response.mcElieceCiphertext,
    state.mcElieceSecretKey)
  let sharedX25519 = x25519Shared(state.x25519SecretKey, response.x25519PublicKey)
  result = tripleSecret(kyberAlg, mcElieceAlg, kyberShared, mcElieceShared,
    sharedX25519)
