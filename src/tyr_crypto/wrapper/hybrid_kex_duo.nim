# ==================================================
# | Hybrid KEX Duo (Kyber/McEliece + X25519)        |
# |-------------------------------------------------|
# | Bandwidth-friendly hybrid KEX variants.         |
# ==================================================

import ../common
import ../algorithms
import ../bindings/liboqs
import ../bindings/libsodium
import ./hybrid_kex_support

const
  kyberX25519Context = "hybrid-kex-kyber-x25519-v2"
  mcElieceX25519Context = "hybrid-kex-mceliece-x25519-v1"

type
  KyberX25519KexOffer* = object
    kyberVariant*: KyberVariant
    kyberPublicKey*: seq[uint8]
    x25519PublicKey*: seq[uint8]

  KyberX25519KexState* = object
    offer*: KyberX25519KexOffer
    kyberSecretKey*: seq[uint8]
    x25519SecretKey*: seq[uint8]

  KyberX25519KexResponse* = object
    kyberCiphertext*: seq[uint8]
    x25519PublicKey*: seq[uint8]

  McElieceX25519KexOffer* = object
    mcElieceVariant*: McElieceVariant
    mcEliecePublicKey*: seq[uint8]
    x25519PublicKey*: seq[uint8]

  McElieceX25519KexState* = object
    offer*: McElieceX25519KexOffer
    mcElieceSecretKey*: seq[uint8]
    x25519SecretKey*: seq[uint8]

  McElieceX25519KexResponse* = object
    mcElieceCiphertext*: seq[uint8]
    x25519PublicKey*: seq[uint8]

proc duoSecret(algId, context: string, kemShared,
    x25519SharedSecret: openArray[uint8]): seq[uint8] =
  result = combineLabeledSecrets(context, [
    (label: algId, secret: @kemShared),
    (label: "X25519", secret: @x25519SharedSecret)
  ])

proc kyberX25519KexAvailable*(variant: KyberVariant = kvKyber768): bool =
  try:
    if not ensureLibOqsLoaded() or not ensureLibSodiumLoaded():
      return false
    ensureSodiumInitialised()
    let kyber = OQS_KEM_new(kyberAlgId(variant).cstring)
    if kyber == nil:
      return false
    OQS_KEM_free(kyber)
    result = true
  except LibraryUnavailableError, OSError, IOError, CryptoOperationError:
    result = false

proc mcElieceX25519KexAvailable*(
    variant: McElieceVariant = mvClassicMcEliece6688128): bool =
  try:
    if not ensureLibOqsLoaded() or not ensureLibSodiumLoaded():
      return false
    ensureSodiumInitialised()
    let mcEliece = OQS_KEM_new(mcElieceAlgId(variant).cstring)
    if mcEliece == nil:
      return false
    OQS_KEM_free(mcEliece)
    result = true
  except LibraryUnavailableError, OSError, IOError, CryptoOperationError:
    result = false

proc createKyberX25519KexOffer*(variant: KyberVariant = kvKyber768): KyberX25519KexState =
  requireHybridKexLibraries()
  let kyber = kemKeypair(kyberAlgId(variant))
  let x25519 = x25519Keypair()
  result = KyberX25519KexState(
    offer: KyberX25519KexOffer(
      kyberVariant: variant,
      kyberPublicKey: kyber.pk,
      x25519PublicKey: x25519.pk
    ),
    kyberSecretKey: kyber.sk,
    x25519SecretKey: x25519.sk
  )

proc createKyberX25519KexOfferWithEntropy*[T](
    variant: KyberVariant = kvKyber768,
    extraEntropy: openArray[T]): KyberX25519KexState =
  requireHybridKexLibraries()
  let entropyBytes = toEntropyBytes(extraEntropy)
  let kyber = kemKeypair(kyberAlgId(variant), entropyBytes)
  let x25519 = x25519Keypair()
  result = KyberX25519KexState(
    offer: KyberX25519KexOffer(
      kyberVariant: variant,
      kyberPublicKey: kyber.pk,
      x25519PublicKey: x25519.pk
    ),
    kyberSecretKey: kyber.sk,
    x25519SecretKey: x25519.sk
  )

proc createKyberX25519KexOfferFromSeed*(seed: openArray[uint8],
    variant: KyberVariant = kvKyber768): KyberX25519KexState =
  requireHybridKexLibraries()
  let kyber = kemKeypair(kyberAlgId(variant))
  let x25519 = x25519KeypairFromSeed(seed)
  result = KyberX25519KexState(
    offer: KyberX25519KexOffer(
      kyberVariant: variant,
      kyberPublicKey: kyber.pk,
      x25519PublicKey: x25519.pk
    ),
    kyberSecretKey: kyber.sk,
    x25519SecretKey: x25519.sk
  )

proc respondKyberX25519KexOffer*(offer: KyberX25519KexOffer): tuple[
    response: KyberX25519KexResponse, sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = kyberAlgId(offer.kyberVariant)
  let kyber = kemEncaps(algId, offer.kyberPublicKey)
  let eph = x25519Keypair()
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: KyberX25519KexResponse(
      kyberCiphertext: kyber.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: duoSecret(algId, kyberX25519Context, kyber.shared, sharedX25519)
  )

proc respondKyberX25519KexOfferWithEntropy*[T](offer: KyberX25519KexOffer,
    extraEntropy: openArray[T]): tuple[response: KyberX25519KexResponse,
    sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = kyberAlgId(offer.kyberVariant)
  let entropyBytes = toEntropyBytes(extraEntropy)
  let kyber = kemEncaps(algId, offer.kyberPublicKey, entropyBytes)
  let eph = x25519Keypair()
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: KyberX25519KexResponse(
      kyberCiphertext: kyber.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: duoSecret(algId, kyberX25519Context, kyber.shared, sharedX25519)
  )

proc respondKyberX25519KexOfferFromSeed*(offer: KyberX25519KexOffer,
    seed: openArray[uint8]): tuple[response: KyberX25519KexResponse,
    sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = kyberAlgId(offer.kyberVariant)
  let kyber = kemEncaps(algId, offer.kyberPublicKey)
  let eph = x25519KeypairFromSeed(seed)
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: KyberX25519KexResponse(
      kyberCiphertext: kyber.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: duoSecret(algId, kyberX25519Context, kyber.shared, sharedX25519)
  )

proc finalizeKyberX25519Kex*(state: KyberX25519KexState,
    response: KyberX25519KexResponse): seq[uint8] =
  requireHybridKexLibraries()
  if response.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = kyberAlgId(state.offer.kyberVariant)
  let kyberShared = kemDecaps(algId, response.kyberCiphertext, state.kyberSecretKey)
  let sharedX25519 = x25519Shared(state.x25519SecretKey, response.x25519PublicKey)
  result = duoSecret(algId, kyberX25519Context, kyberShared, sharedX25519)

proc createMcElieceX25519KexOffer*(
    variant: McElieceVariant = mvClassicMcEliece6688128): McElieceX25519KexState =
  requireHybridKexLibraries()
  let mcEliece = kemKeypair(mcElieceAlgId(variant))
  let x25519 = x25519Keypair()
  result = McElieceX25519KexState(
    offer: McElieceX25519KexOffer(
      mcElieceVariant: variant,
      mcEliecePublicKey: mcEliece.pk,
      x25519PublicKey: x25519.pk
    ),
    mcElieceSecretKey: mcEliece.sk,
    x25519SecretKey: x25519.sk
  )

proc createMcElieceX25519KexOfferWithEntropy*[T](
    variant: McElieceVariant = mvClassicMcEliece6688128,
    extraEntropy: openArray[T]): McElieceX25519KexState =
  requireHybridKexLibraries()
  let entropyBytes = toEntropyBytes(extraEntropy)
  let mcEliece = kemKeypair(mcElieceAlgId(variant), entropyBytes)
  let x25519 = x25519Keypair()
  result = McElieceX25519KexState(
    offer: McElieceX25519KexOffer(
      mcElieceVariant: variant,
      mcEliecePublicKey: mcEliece.pk,
      x25519PublicKey: x25519.pk
    ),
    mcElieceSecretKey: mcEliece.sk,
    x25519SecretKey: x25519.sk
  )

proc createMcElieceX25519KexOfferFromSeed*(seed: openArray[uint8],
    variant: McElieceVariant = mvClassicMcEliece6688128): McElieceX25519KexState =
  requireHybridKexLibraries()
  let mcEliece = kemKeypair(mcElieceAlgId(variant))
  let x25519 = x25519KeypairFromSeed(seed)
  result = McElieceX25519KexState(
    offer: McElieceX25519KexOffer(
      mcElieceVariant: variant,
      mcEliecePublicKey: mcEliece.pk,
      x25519PublicKey: x25519.pk
    ),
    mcElieceSecretKey: mcEliece.sk,
    x25519SecretKey: x25519.sk
  )

proc respondMcElieceX25519KexOffer*(offer: McElieceX25519KexOffer): tuple[
    response: McElieceX25519KexResponse, sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = mcElieceAlgId(offer.mcElieceVariant)
  let mcEliece = kemEncaps(algId, offer.mcEliecePublicKey)
  let eph = x25519Keypair()
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: McElieceX25519KexResponse(
      mcElieceCiphertext: mcEliece.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: duoSecret(algId, mcElieceX25519Context, mcEliece.shared, sharedX25519)
  )

proc respondMcElieceX25519KexOfferWithEntropy*[T](
    offer: McElieceX25519KexOffer, extraEntropy: openArray[T]): tuple[
    response: McElieceX25519KexResponse, sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = mcElieceAlgId(offer.mcElieceVariant)
  let entropyBytes = toEntropyBytes(extraEntropy)
  let mcEliece = kemEncaps(algId, offer.mcEliecePublicKey, entropyBytes)
  let eph = x25519Keypair()
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: McElieceX25519KexResponse(
      mcElieceCiphertext: mcEliece.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: duoSecret(algId, mcElieceX25519Context, mcEliece.shared,
      sharedX25519)
  )

proc respondMcElieceX25519KexOfferFromSeed*(offer: McElieceX25519KexOffer,
    seed: openArray[uint8]): tuple[response: McElieceX25519KexResponse,
    sharedSecret: seq[uint8]] =
  requireHybridKexLibraries()
  if offer.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = mcElieceAlgId(offer.mcElieceVariant)
  let mcEliece = kemEncaps(algId, offer.mcEliecePublicKey)
  let eph = x25519KeypairFromSeed(seed)
  let sharedX25519 = x25519Shared(eph.sk, offer.x25519PublicKey)
  result = (
    response: McElieceX25519KexResponse(
      mcElieceCiphertext: mcEliece.ciphertext,
      x25519PublicKey: eph.pk
    ),
    sharedSecret: duoSecret(algId, mcElieceX25519Context, mcEliece.shared, sharedX25519)
  )

proc finalizeMcElieceX25519Kex*(state: McElieceX25519KexState,
    response: McElieceX25519KexResponse): seq[uint8] =
  requireHybridKexLibraries()
  if response.x25519PublicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 public key length")
  let algId = mcElieceAlgId(state.offer.mcElieceVariant)
  let mcElieceShared = kemDecaps(algId, response.mcElieceCiphertext,
    state.mcElieceSecretKey)
  let sharedX25519 = x25519Shared(state.x25519SecretKey, response.x25519PublicKey)
  result = duoSecret(algId, mcElieceX25519Context, mcElieceShared, sharedX25519)
