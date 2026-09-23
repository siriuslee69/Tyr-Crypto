## ---------------------------------------------------------------------
## | KEM Dynamic <- choose the family from a VALUE while the program runs |
## | AnyKem value -> case -> the matching family's code                   |
## ---------------------------------------------------------------------
##
## When you need this
## ------------------
## The default tier (`tyr/kems`) settles the choice while compiling:
##
##   keypair(kyber768)        <- "kyber768" is written in the source
##
## That is no help when the choice arrives at runtime, from a config file
## or a message header. Nim cannot pick an overload from a value, so this
## file wraps the choice in one type carrying a tag, and switches on it:
##
##   AnyKem(family: kfKyber, kyber: kyber768)
##          ^^^^^^^^^^^^^^^ the tag the `case` reads
##
## The names here end in `Of` (`keypairOf`, `encapsOf`, `decapsOf`) so all
## three tiers can be imported side by side without clashing.
##
## Cost: every family is compiled in, because any of them could be chosen.
## If that is too much, use `single.nim` instead.

import ./types
import ./kyber
import ./mceliece
import ./frodo
import ./bike
import ./ntru
import ./saber
import ./hqc

export types

type
  ## One KEM choice, carrying the family tag plus that family's variant.
  AnyKem* = object
    case family*: KemFamily
    of kfKyber:    kyber*: KyberVariant
    of kfMcEliece: mceliece*: McElieceVariant
    of kfFrodo:    frodo*: FrodoVariant
    of kfBike:     bike*: BikeVariant
    of kfNtru:     ntru*: NtruVariant
    of kfSaber:    saber*: SaberVariant
    of kfHqc:      hqc*: HqcVariant

proc keypairOf*(a: AnyKem, seed: seq[byte] = @[]): KemKeypair =
  ## a/seed: the runtime choice, and optional fixed randomness for tests.
  ## Generate a fresh public/secret pair for whichever family `a` names.
  case a.family
  of kfKyber:
    var t = kyberTyrKeypair(a.kyber, seed)
    result = KemKeypair(family: kfKyber, public: t.publicKey, secret: t.secretKey)
  of kfMcEliece:
    var t = mcelieceTyrKeypair(a.mceliece, seed)
    result = KemKeypair(family: kfMcEliece, public: t.publicKey, secret: t.secretKey)
  of kfFrodo:
    var t = frodoTyrKeypair(a.frodo, seed)
    result = KemKeypair(family: kfFrodo, public: t.publicKey, secret: t.secretKey)
  of kfBike:
    var t = bikeTyrKeypair(a.bike, seed)
    result = KemKeypair(family: kfBike, public: t.publicKey, secret: t.secretKey)
  of kfNtru:
    var t = ntruTyrKeypair(a.ntru, seed)
    result = KemKeypair(family: kfNtru, public: t.publicKey, secret: t.secretKey)
  of kfSaber:
    var t = saberTyrKeypair(a.saber, seed)
    result = KemKeypair(family: kfSaber, public: t.publicKey, secret: t.secretKey)
  of kfHqc:
    var t = hqcTyrKeypair(a.hqc, seed)
    result = KemKeypair(family: kfHqc, public: t.publicKey, secret: t.secretKey)

proc encapsOf*(a: AnyKem, pk: openArray[byte], seed: seq[byte] = @[]): KemCiphertext =
  ## a/pk/seed: the runtime choice, recipient's public key, optional randomness.
  ## Produce a ciphertext to send plus the shared secret to keep.
  case a.family
  of kfKyber:
    var t = kyberTyrEncaps(a.kyber, pk, seed)
    result = KemCiphertext(family: kfKyber, ciphertext: t.ciphertext, shared: t.sharedSecret)
  of kfMcEliece:
    var t: McElieceTyrCipher = default(McElieceTyrCipher)
    if seed.len == 0: t = mcelieceTyrEncaps(a.mceliece, pk)
    else: t = mcelieceTyrEncapsDerand(a.mceliece, pk, seed)
    result = KemCiphertext(family: kfMcEliece, ciphertext: t.ciphertext, shared: t.sharedSecret)
  of kfFrodo:
    var t = frodoTyrEncaps(a.frodo, pk, seed)
    result = KemCiphertext(family: kfFrodo, ciphertext: t.ciphertext, shared: t.sharedSecret)
  of kfBike:
    var t = bikeTyrEncaps(a.bike, pk, seed)
    result = KemCiphertext(family: kfBike, ciphertext: t.ciphertext, shared: t.sharedSecret)
  of kfNtru:
    var t = ntruTyrEncaps(a.ntru, pk, seed)
    result = KemCiphertext(family: kfNtru, ciphertext: t.ciphertext, shared: t.sharedSecret)
  of kfSaber:
    var t = saberTyrEncaps(a.saber, pk, seed)
    result = KemCiphertext(family: kfSaber, ciphertext: t.ciphertext, shared: t.sharedSecret)
  of kfHqc:
    var t = hqcTyrEncaps(a.hqc, pk, seed)
    result = KemCiphertext(family: kfHqc, ciphertext: t.ciphertext, shared: t.sharedSecret)

proc decapsOf*(a: AnyKem, sk, ct: openArray[byte]): seq[byte] =
  ## a/sk/ct: the runtime choice, your secret key, the ciphertext received.
  ## Recover the same shared secret the sender produced.
  case a.family
  of kfKyber:    result = kyberTyrDecaps(a.kyber, sk, ct)
  of kfMcEliece: result = mcelieceTyrDecaps(a.mceliece, sk, ct)
  of kfFrodo:    result = frodoTyrDecaps(a.frodo, sk, ct)
  of kfBike:     result = bikeTyrDecaps(a.bike, sk, ct)
  of kfNtru:     result = ntruTyrDecaps(a.ntru, sk, ct)
  of kfSaber:    result = saberTyrDecaps(a.saber, sk, ct)
  of kfHqc:      result = hqcTyrDecaps(a.hqc, sk, ct)
