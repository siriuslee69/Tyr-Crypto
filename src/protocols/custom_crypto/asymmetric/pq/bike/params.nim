## ---------------------------------------------------------
## BIKE Params <- level-1 fixed layout and threshold values
## ---------------------------------------------------------

type
  ## Supported pure-Nim BIKE variants.
  BikeVariant* = enum
    bikeL1

  ## Fixed parameter bundle for one BIKE variant.
  BikeParams* = object
    variant*: BikeVariant
    rBits*: int
    d*: int
    t*: int
    blockBits*: int
    maxRandIndicesT*: int
    thresholdCoeff0*: uint64
    thresholdCoeff1*: uint64
    thresholdMulConst*: uint64
    thresholdShrConst*: int
    thresholdMin*: int
    publicKeyBytes*: int
    secretKeyBytes*: int
    ciphertextBytes*: int
    sharedSecretBytes*: int
    keypairRandomBytes*: int
    encapsRandomBytes*: int

const
  bikeN0* = 2
  bikeSeedBytes* = 32
  bikeMessageBytes* = 32
  bikeSharedSecretBytes* = 32

  bikeRBits* = 12323
  bikeD* = 71
  bikeT* = 134
  bikeBlockBits* = 16384
  bikeMaxRandIndicesT* = 271

  bikeThresholdCoeff0* = 1353000000'u64
  bikeThresholdCoeff1* = 697220'u64
  bikeThresholdMulConst* = 12379400392853802749'u64
  bikeThresholdShrConst* = 26
  bikeThresholdMin* = 36

  bikeNBits* = bikeRBits * bikeN0
  bikeRBytes* = (bikeRBits + 7) div 8
  bikeRQWords* = (bikeRBits + 63) div 64
  bikeRPadded* = ((bikeRBits + bikeBlockBits - 1) div bikeBlockBits) * bikeBlockBits
  bikeRPaddedBytes* = bikeRPadded div 8
  bikeRPaddedQWords* = bikeRPadded div 64
  bikeLastRQWordLead* = bikeRBits and 63
  bikeLastRQWordTrail* = 64 - bikeLastRQWordLead
  bikeLastRByteLead* = bikeRBits and 7
  bikeLastRByteTrail* = 8 - bikeLastRByteLead
  bikeLastRQWordMask* = (1'u64 shl bikeLastRQWordLead) - 1'u64
  bikeLastRByteMask* = byte((1'u16 shl bikeLastRByteLead) - 1'u16)

  bikeDelta* = 3
  bikeSlices* = 8
  bikeMaxIt* = 5
  bikeQWordsHalfLog2* = 128

  bikePublicKeyBytes* = bikeRBytes
  bikeSecretKeyBytes* = (bikeN0 * bikeD * 4) + (bikeN0 * bikeRBytes) + bikeRBytes + bikeMessageBytes
  bikeCiphertextBytes* = bikeRBytes + bikeMessageBytes
  bikeKeypairRandomBytes* = bikeSeedBytes * 2
  bikeEncapsRandomBytes* = bikeSeedBytes * 2

  bikeExp0K*: array[14, int] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
  ]
  bikeExp0L*: array[14, int] = [
    6162, 3081, 3851, 5632, 22, 484, 119, 1838, 1742, 3106, 10650, 1608, 10157, 8816
  ]
  bikeExp1K*: array[14, int] = [
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 33, 4129
  ]
  bikeExp1L*: array[14, int] = [
    0, 0, 0, 0, 0, 6162, 0, 0, 0, 0, 0, 0, 242, 5717
  ]

proc params*(v: BikeVariant): BikeParams =
  ## Return the fixed parameter bundle for one BIKE variant.
  case v
  of bikeL1:
    result.variant = bikeL1
    result.rBits = bikeRBits
    result.d = bikeD
    result.t = bikeT
    result.blockBits = bikeBlockBits
    result.maxRandIndicesT = bikeMaxRandIndicesT
    result.thresholdCoeff0 = bikeThresholdCoeff0
    result.thresholdCoeff1 = bikeThresholdCoeff1
    result.thresholdMulConst = bikeThresholdMulConst
    result.thresholdShrConst = bikeThresholdShrConst
    result.thresholdMin = bikeThresholdMin
    result.publicKeyBytes = bikePublicKeyBytes
    result.secretKeyBytes = bikeSecretKeyBytes
    result.ciphertextBytes = bikeCiphertextBytes
    result.sharedSecretBytes = bikeSharedSecretBytes
    result.keypairRandomBytes = bikeKeypairRandomBytes
    result.encapsRandomBytes = bikeEncapsRandomBytes
