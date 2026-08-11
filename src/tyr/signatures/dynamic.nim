## ---------------------------------------------------------------------
## | Signature Dynamic <- choose the family from a VALUE while running   |
## | AnySig value -> case -> the matching family's code                  |
## ---------------------------------------------------------------------
##
## The default tier settles the choice while compiling. This tier reads it
## from a value instead, which is what you need when the scheme is named in
## a config file or a message header:
##
##   AnySig(family: sfFalcon, falcon: falcon512)
##          ^^^^^^^^^^^^^^^^ the tag the `case` reads
##
## Names end in `Of` so every tier can be imported side by side.
## Every family is compiled in, because any of them could be chosen.

import ./types
import ./dilithium
import ./falcon
import ./sphincs
import ./ed25519

export types

type
  ## One signature choice: the family tag plus that family's variant.
  ## Ed25519 has no variants, so it carries nothing extra.
  AnySig* = object
    case family*: SigFamily
    of sfDilithium: dilithium*: DilithiumVariant
    of sfFalcon:    falcon*: FalconVariant
    of sfSphincs:   sphincs*: SphincsVariant
    of sfEd25519:   discard

proc keypairOf*(a: AnySig, seed: seq[byte] = @[]): SigKeypair =
  ## a/seed: the runtime choice, and optional fixed randomness for tests.
  ## Ed25519 needs a 32-byte seed; an empty seed means system randomness.
  case a.family
  of sfDilithium:
    var t = dilithiumTyrKeypair(a.dilithium, seed)
    result = SigKeypair(family: sfDilithium, public: t.publicKey, secret: t.secretKey)
  of sfFalcon:
    var t = falconTyrKeypair(a.falcon)
    result = SigKeypair(family: sfFalcon, public: t.publicKey, secret: t.secretKey)
  of sfSphincs:
    var t = sphincsTyrKeypair(a.sphincs, seed)
    result = SigKeypair(family: sfSphincs, public: t.publicKey, secret: t.secretKey)
  of sfEd25519:
    var t: Ed25519Keypair
    if seed.len == 0: t = ed25519TyrKeypair()
    else: t = ed25519TyrKeypairFromSeed(seed)
    result = SigKeypair(family: sfEd25519, public: t.publicKey, secret: t.secretKey)

proc signOf*(a: AnySig, msg, sk: openArray[byte]): seq[byte] =
  ## a/msg/sk: the runtime choice, the bytes to sign, your secret key.
  case a.family
  of sfDilithium: result = dilithiumTyrSign(a.dilithium, msg, sk)
  of sfFalcon:    result = falconTyrSign(a.falcon, msg, sk)
  of sfSphincs:   result = sphincsTyrSign(a.sphincs, msg, sk)
  of sfEd25519:   result = ed25519TyrSign(msg, sk)

proc verifyOf*(a: AnySig, msg, sig, pk: openArray[byte]): bool =
  ## a/msg/sig/pk: the runtime choice, signed bytes, signature, public key.
  ## Returns false for a forged or altered message.
  case a.family
  of sfDilithium: result = dilithiumTyrVerify(a.dilithium, msg, sig, pk)
  of sfFalcon:    result = falconTyrVerify(a.falcon, msg, sig, pk)
  of sfSphincs:   result = sphincsTyrVerify(a.sphincs, msg, sig, pk)
  of sfEd25519:   result = ed25519TyrVerify(msg, sig, pk)
