## ---------------------------------------------------------------------
## | X-Wing <- ML-KEM-768 + X25519 glued into ONE KEM                   |
## | draft-connolly-cfrg-xwing-kem-11 (2026-09-23)                      |
## ---------------------------------------------------------------------
##
## What it is
## ----------
## Two key exchanges run side by side. One resists quantum computers
## (ML-KEM-768), one is the well-tested classical one (X25519). Their two
## secrets are hashed into one. An attacker has to break BOTH to learn it.
##
##   secret key   32 bytes   (only a seed; everything else is re-derived)
##   public key   1216 bytes [ ML-KEM-768 public key 1184 | X25519 public 32 ]
##   ciphertext   1120 bytes [ ML-KEM-768 ciphertext 1088 | X25519 ephem. 32 ]
##   shared       32 bytes
##
## How the 32-byte secret key grows into both keys
## -----------------------------------------------
##
##   sk (32) --SHAKE256--> 96 bytes
##                          [ 0..31  d  ] --+
##                          [ 32..63 z  ] --+--> ML-KEM-768 keypair
##                          [ 64..95 sX ] -----> X25519 secret
##
## How the shared secret is made
## -----------------------------
##
##   ss = SHA3-256( ssM | ssX | ctX | pkX | 5c 2e 2f 2f 5e 5c )
##                  32    32    32    32    "\./" "/^\" label
##
## ssM: ML-KEM secret. ssX: X25519 secret. ctX: the sender's throwaway
## X25519 public key. pkX: the receiver's X25519 public key. The ML-KEM
## ciphertext is NOT hashed in; FIPS 203 ML-KEM already ties its secret to
## its ciphertext strongly enough (draft section 6).
##
## Not the same as Bifrost's own ML-KEM + X25519 slots: Bifrost mixes its
## secrets with its own key schedule. Use X-Wing to talk to other X-Wing
## software (HPKE and friends), where the exact bytes above matter.

import ../../helpers/secure_memory
import ../../hashes/sha3
import ../../helpers/random
import ../mlkem/operations
import ../x25519/x25519_common
import ../x25519/x25519_impl

const
  xwingSecretKeyBytes* = 32
  xwingPublicKeyBytes* = 1216
  xwingCiphertextBytes* = 1120
  xwingSharedSecretBytes* = 32
  xwingEncapsSeedBytes* = 64
  xwingMlKemPublicKeyBytes = 1184
  xwingMlKemCiphertextBytes = 1088
  xwingLabel: array[6, byte] = [0x5c'u8, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]

type
  ## Which X-Wing. Only one exists; the enum keeps the family API shape
  ## (`keypair(xwing768)`) the same as every other KEM in Tyr.
  XWingVariant* = enum
    xwing768 ## ML-KEM-768 + X25519 + SHA3-256

  ## Public/secret keypair. `secretKey` is the 32-byte seed itself.
  XWingTyrKeypair* = object
    variant*: XWingVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Ciphertext to send, shared secret to keep.
  XWingTyrCipher* = object
    variant*: XWingVariant
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]

  ## The four parts one secret key expands into. Lives for one call.
  XWingExpanded = object
    mlkem: MlKemTyrKeypair
    skX: X25519Bytes32
    pkX: X25519Bytes32

## Reference: [XWING-11] section 5.2 expandDecapsulationKey; pitfall: wipe the 96-byte expansion.
proc expandSecretKey(sk: openArray[byte]): XWingExpanded =
  ## sk: the 32-byte X-Wing secret key.
  var
    expanded: array[96, byte] = default(array[96, byte])
  if sk.len != xwingSecretKeyBytes:
    raise newException(ValueError, "X-Wing secret key must be 32 bytes")
  shake256Into(expanded, sk)
  result.mlkem = mlkemTyrKeypairFromParts(mlkem768,
    expanded.toOpenArray(0, 31), expanded.toOpenArray(32, 63))
  copyMem(addr result.skX[0], addr expanded[64], 32)
  secureClearBytes(expanded)
  if not x25519ScalarmultBaseRaw(result.pkX, result.skX):
    raise newException(ValueError, "X-Wing X25519 public key derivation failed")

## Reference: [XWING-11] section 5.3 Combiner; pitfall: keep the input order exact.
proc combine(ssM, ssX, ctX, pkX: openArray[byte]): seq[byte] =
  ## ssM/ssX/ctX/pkX: the four 32-byte inputs, in the order the draft fixes.
  var
    material: array[134, byte] = default(array[134, byte])
  copyMem(addr material[0], unsafeAddr ssM[0], 32)
  copyMem(addr material[32], unsafeAddr ssX[0], 32)
  copyMem(addr material[64], unsafeAddr ctX[0], 32)
  copyMem(addr material[96], unsafeAddr pkX[0], 32)
  copyMem(addr material[128], unsafeAddr xwingLabel[0], 6)
  result = newSeq[byte](xwingSharedSecretBytes)
  sha3_256Into(result, material)
  secureClearBytes(material)

## Reference: [XWING-11] section 5.2 GenerateKeyPairDerand; pitfall: the seed IS the secret key.
proc xwingTyrKeypair*(v: XWingVariant = xwing768, seed: seq[byte] = @[]): XWingTyrKeypair =
  ## v: which X-Wing. seed: optional 32-byte secret key (tests); random if empty.
  var
    e: XWingExpanded = default(XWingExpanded)
  if seed.len != 0 and seed.len != xwingSecretKeyBytes:
    raise newException(ValueError, "X-Wing seeded keypair requires a 32-byte seed")
  result.variant = v
  if seed.len == 0:
    result.secretKey = cryptoRandomBytes(xwingSecretKeyBytes)
  else:
    result.secretKey = seed
  e = expandSecretKey(result.secretKey)
  result.publicKey = e.mlkem.publicKey & @(e.pkX)
  secureClearBytes(e.mlkem.secretKey)
  secureClearPod(e.skX)

## Reference: [XWING-11] section 5.4.1 EncapsulateDerand; pitfall: eseed[0..31] is ML-KEM m, eseed[32..63] the X25519 scalar.
proc xwingTyrEncaps*(v: XWingVariant, pk: openArray[byte], seed: seq[byte] = @[]): XWingTyrCipher =
  ## v/pk: which X-Wing and the receiver's 1216-byte public key.
  ## seed: optional 64-byte eseed (tests); random if empty.
  var
    eseed: seq[byte] = @[]
    ekX: X25519Bytes32 = default(X25519Bytes32)
    ctX: X25519Bytes32 = default(X25519Bytes32)
    pkX: X25519Bytes32 = default(X25519Bytes32)
    ssX: X25519Bytes32 = default(X25519Bytes32)
    m: MlKemTyrCipher = default(MlKemTyrCipher)
  if pk.len != xwingPublicKeyBytes:
    raise newException(ValueError, "X-Wing public key must be 1216 bytes")
  if seed.len != 0 and seed.len != xwingEncapsSeedBytes:
    raise newException(ValueError, "X-Wing seeded encapsulation requires a 64-byte seed")
  if seed.len == 0:
    eseed = cryptoRandomBytes(xwingEncapsSeedBytes)
  else:
    eseed = seed
  copyMem(addr ekX[0], addr eseed[32], 32)
  copyMem(addr pkX[0], unsafeAddr pk[xwingMlKemPublicKeyBytes], 32)
  if not x25519ScalarmultBaseRaw(ctX, ekX):
    raise newException(ValueError, "X-Wing X25519 ephemeral key derivation failed")
  if not x25519ScalarmultRaw(ssX, ekX, pkX):
    raise newException(ValueError, "X-Wing X25519 public key is invalid")
  m = mlkemTyrEncaps(mlkem768, pk.toOpenArray(0, xwingMlKemPublicKeyBytes - 1),
    eseed[0 ..< 32])
  result.variant = v
  result.sharedSecret = combine(m.sharedSecret, ssX, ctX, pkX)
  result.ciphertext = m.ciphertext & @ctX
  secureClearBytes(eseed)
  secureClearBytes(m.sharedSecret)
  secureClearPod(ekX)
  secureClearPod(ssX)

## Reference: [XWING-11] section 5.5 Decapsulate; pitfall: a bad ML-KEM part is rejected implicitly, never reported.
proc xwingTyrDecaps*(v: XWingVariant, sk, ct: openArray[byte]): seq[byte] =
  ## v/sk/ct: which X-Wing, the 32-byte secret key, the 1120-byte ciphertext.
  ## A tampered ML-KEM part gives a wrong, random-looking secret (no error).
  ## A small-order X25519 part raises ValueError: that only depends on public
  ## bytes, so refusing it reveals nothing about the key.
  var
    e: XWingExpanded = default(XWingExpanded)
    ctX: X25519Bytes32 = default(X25519Bytes32)
    ssX: X25519Bytes32 = default(X25519Bytes32)
    ssM: seq[byte] = @[]
  if ct.len != xwingCiphertextBytes:
    raise newException(ValueError, "X-Wing ciphertext must be 1120 bytes")
  e = expandSecretKey(sk)
  copyMem(addr ctX[0], unsafeAddr ct[xwingMlKemCiphertextBytes], 32)
  ssM = mlkemTyrDecaps(mlkem768, e.mlkem.secretKey,
    ct.toOpenArray(0, xwingMlKemCiphertextBytes - 1))
  if not x25519ScalarmultRaw(ssX, e.skX, ctX):
    secureClearBytes(e.mlkem.secretKey)
    secureClearPod(e.skX)
    secureClearBytes(ssM)
    raise newException(ValueError, "X-Wing X25519 ciphertext part is invalid")
  result = combine(ssM, ssX, ctX, e.pkX)
  secureClearBytes(e.mlkem.secretKey)
  secureClearPod(e.skX)
  secureClearPod(ssX)
  secureClearBytes(ssM)
