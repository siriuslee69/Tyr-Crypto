## ----------------------------------------------------
## BIKE Types <- fixed wire layouts and state objects
## ----------------------------------------------------

import ./params

type
  ## One fixed-width 32-byte BIKE seed.
  BikeSeed* = array[bikeSeedBytes, byte]
  ## One fixed-width 32-byte BIKE message block.
  BikeMessage* = array[bikeMessageBytes, byte]
  ## One fixed-width 32-byte BIKE shared secret block.
  BikeSharedSecret* = array[bikeSharedSecretBytes, byte]
  ## One raw degree-`r` polynomial serialized in little-endian bit order.
  BikeRawPoly* = array[bikeRBytes, byte]
  ## One fixed-weight secret-index list.
  BikeIndexList* = array[bikeD, uint32]
  ## The two secret-index lists stored inside a BIKE secret key.
  BikeDualIndexList* = array[bikeN0, BikeIndexList]
  ## The two raw BIKE error polynomials.
  BikeRawError* = array[bikeN0, BikeRawPoly]
  ## Parsed BIKE ciphertext representation.
  BikeCiphertextRaw* = object
    c0*: BikeRawPoly
    c1*: BikeMessage
  ## Parsed BIKE secret-key representation.
  BikeSecretKeyState* = object
    wlist*: BikeDualIndexList
    bin*: array[bikeN0, BikeRawPoly]
    pk*: BikeRawPoly
    sigma*: BikeMessage
  ## Internal padded polynomial over GF(2)[x].
  BikePadPoly* = seq[uint64]
  ## Internal double-width padded polynomial over GF(2)[x].
  BikeDoublePadPoly* = seq[uint64]
  ## Internal triplicated syndrome buffer.
  BikeSyndrome* = seq[uint64]
  ## Internal UPC bit-slice buffer.
  BikeUpc* = array[bikeSlices, seq[uint64]]
  ## Public/secret keypair emitted by the pure-Nim BIKE backend.
  BikeTyrKeypair* = object
    variant*: BikeVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]
  ## Detached ciphertext plus shared secret emitted by encapsulation.
  BikeTyrCipher* = object
    variant*: BikeVariant
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]
