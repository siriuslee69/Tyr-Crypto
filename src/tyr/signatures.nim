## ---------------------------------------------------------------------
## | Signatures <- default tier: one name per operation, by overloading |
## | keypair(v) / sign(v, msg, sk) / verify(v, msg, sig, pk)            |
## ---------------------------------------------------------------------
##
## The four ways to reach a signature scheme
## -----------------------------------------
##
##   import tyr/signatures            <- THIS FILE. every family, one name
##                                       each; the compiler picks by the
##                                       variant type:  keypair(dilithium65)
##
##   import tyr/signatures/falcon     <- one family, its own names:
##                                       falconTyrKeypair(falcon512)
##
##   import tyr/signatures/dynamic    <- choose from a VALUE while running:
##                                       keypairOf(AnySig(family: sfFalcon, ...))
##
##   import tyr/signatures/single     <- one family by build flag, nothing
##      -d:tyrSigFalcon                  else compiled. For small devices.
##
## Overloading works here because each family names its variants with its
## own enum type, so one name can serve them all and the compiler still
## knows which code to call. The choice is settled while compiling and
## costs nothing at runtime.

import ./signatures/types
import ./signatures/dilithium
import ./signatures/falcon
import ./signatures/sphincs
import ./signatures/ed25519
import ./signatures/ecdsa_p256
import ./signatures/material

export types
export dilithium, falcon, sphincs, ed25519
export ecdsa_p256
export material

## ╭⟢ keypair

proc keypair*(v: DilithiumVariant, seed: seq[byte] = @[]): SigKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = dilithiumTyrKeypair(v, seed)
  result = SigKeypair(family: sfDilithium, public: t.publicKey, secret: t.secretKey)

proc keypair*(v: FalconVariant): SigKeypair =
  ## v: which Falcon parameter set to generate for.
  var t = falconTyrKeypair(v)
  result = SigKeypair(family: sfFalcon, public: t.publicKey, secret: t.secretKey)

proc keypair*(v: SphincsVariant, seed: seq[byte] = @[]): SigKeypair =
  ## v/seed: variant, and optional fixed randomness for reproducible tests.
  var t = sphincsTyrKeypair(v, seed)
  result = SigKeypair(family: sfSphincs, public: t.publicKey, secret: t.secretKey)

## ╭⟢ sign

proc sign*(v: DilithiumVariant, msg, sk: openArray[byte]): seq[byte] =
  ## v/msg/sk: variant, the bytes to sign, your secret key.
  result = dilithiumTyrSign(v, msg, sk)

proc sign*(v: FalconVariant, msg, sk: openArray[byte]): seq[byte] =
  ## v/msg/sk: variant, the bytes to sign, your secret key.
  result = falconTyrSign(v, msg, sk)

proc sign*(v: SphincsVariant, msg, sk: openArray[byte]): seq[byte] =
  ## v/msg/sk: variant, the bytes to sign, your secret key.
  result = sphincsTyrSign(v, msg, sk)

## ╭⟢ verify

proc verify*(v: DilithiumVariant, msg, sig, pk: openArray[byte]): bool =
  ## v/msg/sig/pk: variant, the signed bytes, the signature, signer's public key.
  ## Returns false for a forged or altered message; never raises on bad input.
  result = dilithiumTyrVerify(v, msg, sig, pk)

proc verify*(v: FalconVariant, msg, sig, pk: openArray[byte]): bool =
  ## v/msg/sig/pk: variant, the signed bytes, the signature, signer's public key.
  result = falconTyrVerify(v, msg, sig, pk)

proc verify*(v: SphincsVariant, msg, sig, pk: openArray[byte]): bool =
  ## v/msg/sig/pk: variant, the signed bytes, the signature, signer's public key.
  result = sphincsTyrVerify(v, msg, sig, pk)
