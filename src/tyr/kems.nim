## ---------------------------------------------------------------------
## | KEMs <- default tier: one name per operation, picked by overloading |
## | keypair(v) / encaps(v, pk) / decaps(v, sk, ct)                      |
## ---------------------------------------------------------------------
##
## The three call shapes Tyr offers
## --------------------------------
##
##   import tyr/kems              <- THIS FILE. every family, one name each,
##                                   the compiler picks by the variant type
##                                     keypair(kyber768)
##                                     keypair(mceliece6688128f)
##
##   import tyr/kems/mceliece     <- one family only, called by its own name
##                                     mcelieceTyrKeypair(mceliece6688128f)
##
##   import tyr/kems/dynamic      <- choose from a VALUE while running
##                                     keypairOf(AnyKem(family: kfKyber, ...))
##
##   import tyr/kems/single       <- one family, chosen by a -d: build flag,
##      -d:tyrKemKyber               nothing else compiled. For IoT.
##
## Why overloading works here
## --------------------------
## Every family names its variants with its own enum type: `KyberVariant`,
## `McElieceVariant`, and so on. Those are different types, so one name can
## serve them all and the compiler still knows which code to call:
##
##   keypair(kyber768)            -> KyberVariant       -> Kyber code
##   keypair(mceliece6688128f)    -> McElieceVariant    -> McEliece code
##
## This costs nothing at runtime. The choice is settled while compiling.
## It cannot be driven by a value read from a file - for that, use
## `dynamic.nim`, which is the only tier that can.

import ./kems/types
import ./kems/kyber
import ./kems/mceliece
import ./kems/frodo
import ./kems/bike
import ./kems/ntru
import ./kems/saber

export types
export kyber, mceliece, frodo, bike, ntru, saber

## ╭⟢ keypair

proc keypair*(v: KyberVariant, seed: seq[byte] = @[]): KemKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = kyberTyrKeypair(v, seed)
  result = KemKeypair(family: kfKyber, public: t.publicKey, secret: t.secretKey)

proc keypair*(v: McElieceVariant, seed: seq[byte] = @[]): KemKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = mcelieceTyrKeypair(v, seed)
  result = KemKeypair(family: kfMcEliece, public: t.publicKey, secret: t.secretKey)

proc keypair*(v: FrodoVariant, seed: seq[byte] = @[]): KemKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = frodoTyrKeypair(v, seed)
  result = KemKeypair(family: kfFrodo, public: t.publicKey, secret: t.secretKey)

proc keypair*(v: BikeVariant, seed: seq[byte] = @[]): KemKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = bikeTyrKeypair(v, seed)
  result = KemKeypair(family: kfBike, public: t.publicKey, secret: t.secretKey)

proc keypair*(v: NtruVariant, seed: seq[byte] = @[]): KemKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = ntruTyrKeypair(v, seed)
  result = KemKeypair(family: kfNtru, public: t.publicKey, secret: t.secretKey)

proc keypair*(v: SaberVariant, seed: seq[byte] = @[]): KemKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = saberTyrKeypair(v, seed)
  result = KemKeypair(family: kfSaber, public: t.publicKey, secret: t.secretKey)

## ╭⟢ encapsulate

proc encaps*(v: KyberVariant, pk: openArray[byte], seed: seq[byte] = @[]): KemCiphertext =
  ## v/pk/seed: variant, the recipient's public key, optional fixed randomness.
  var t = kyberTyrEncaps(v, pk, seed)
  result = KemCiphertext(family: kfKyber, ciphertext: t.ciphertext, shared: t.sharedSecret)

proc encaps*(v: McElieceVariant, pk: openArray[byte], seed: seq[byte] = @[]): KemCiphertext =
  ## v/pk/seed: variant, the recipient's public key, optional fixed randomness.
  ## McEliece splits these into two entry points, so pick by whether a seed
  ## was supplied. An empty seed means "use system randomness".
  var t: McElieceTyrCipher
  if seed.len == 0:
    t = mcelieceTyrEncaps(v, pk)
  else:
    t = mcelieceTyrEncapsDerand(v, pk, seed)
  result = KemCiphertext(family: kfMcEliece, ciphertext: t.ciphertext, shared: t.sharedSecret)

proc encaps*(v: FrodoVariant, pk: openArray[byte], seed: seq[byte] = @[]): KemCiphertext =
  ## v/pk/seed: variant, the recipient's public key, optional fixed randomness.
  var t = frodoTyrEncaps(v, pk, seed)
  result = KemCiphertext(family: kfFrodo, ciphertext: t.ciphertext, shared: t.sharedSecret)

proc encaps*(v: BikeVariant, pk: openArray[byte], seed: seq[byte] = @[]): KemCiphertext =
  ## v/pk/seed: variant, the recipient's public key, optional fixed randomness.
  var t = bikeTyrEncaps(v, pk, seed)
  result = KemCiphertext(family: kfBike, ciphertext: t.ciphertext, shared: t.sharedSecret)

proc encaps*(v: NtruVariant, pk: openArray[byte], seed: seq[byte] = @[]): KemCiphertext =
  ## v/pk/seed: variant, the recipient's public key, optional fixed randomness.
  var t = ntruTyrEncaps(v, pk, seed)
  result = KemCiphertext(family: kfNtru, ciphertext: t.ciphertext, shared: t.sharedSecret)

proc encaps*(v: SaberVariant, pk: openArray[byte], seed: seq[byte] = @[]): KemCiphertext =
  ## v/pk/seed: variant, the recipient's public key, optional fixed randomness.
  var t = saberTyrEncaps(v, pk, seed)
  result = KemCiphertext(family: kfSaber, ciphertext: t.ciphertext, shared: t.sharedSecret)

## ╭⟢ decapsulate

proc decaps*(v: KyberVariant, sk, ct: openArray[byte]): seq[byte] =
  ## v/sk/ct: variant, your secret key, the ciphertext you received.
  result = kyberTyrDecaps(v, sk, ct)

proc decaps*(v: McElieceVariant, sk, ct: openArray[byte]): seq[byte] =
  ## v/sk/ct: variant, your secret key, the ciphertext you received.
  result = mcelieceTyrDecaps(v, sk, ct)

proc decaps*(v: FrodoVariant, sk, ct: openArray[byte]): seq[byte] =
  ## v/sk/ct: variant, your secret key, the ciphertext you received.
  result = frodoTyrDecaps(v, sk, ct)

proc decaps*(v: BikeVariant, sk, ct: openArray[byte]): seq[byte] =
  ## v/sk/ct: variant, your secret key, the ciphertext you received.
  result = bikeTyrDecaps(v, sk, ct)

proc decaps*(v: NtruVariant, sk, ct: openArray[byte]): seq[byte] =
  ## v/sk/ct: variant, your secret key, the ciphertext you received.
  result = ntruTyrDecaps(v, sk, ct)

proc decaps*(v: SaberVariant, sk, ct: openArray[byte]): seq[byte] =
  ## v/sk/ct: variant, your secret key, the ciphertext you received.
  result = saberTyrDecaps(v, sk, ct)
