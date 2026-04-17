## ---------------------------------------------------------
## BIKE Sampling <- SHAKE-driven fixed-weight index samplers
## ---------------------------------------------------------

import ./params
import ./types
import ./util
import ../sha3/sha3
import ../random

type
  ## Internal SHAKE256-backed byte stream for BIKE sampling.
  BikePrfState* = object
    seed*: BikeSeed
    buffer*: seq[byte]
    offset*: int

proc initPrfState*(seed: BikeSeed): BikePrfState =
  ## Initialize the BIKE SHAKE256 PRF stream for one seed.
  result.seed = seed
  result.buffer = shake256(seed, 4096)
  result.offset = 0

proc ensurePrfBytes(S: var BikePrfState, n: int) =
  var
    want: int = 0
  want = S.offset + n
  if want <= S.buffer.len:
    return
  S.buffer = shake256(S.seed, want + 4096)

proc getPrfOutput*(S: var BikePrfState, n: int): seq[byte] =
  ## Read the next `n` bytes from the BIKE SHAKE256 PRF stream.
  ensurePrfBytes(S, n)
  result = newSeq[byte](n)
  copyMem(addr result[0], addr S.buffer[S.offset], n)
  S.offset = S.offset + n

proc secureSetBitsPort*(P: var BikePadPoly, firstPos: int, W: openArray[uint32]) =
  ## Set the requested bit positions into one padded BIKE polynomial.
  var
    posQw: seq[uint32] = @[]
    posBit: seq[uint64] = @[]
    i: int = 0
    j: int = 0
    w: int32 = 0
    val: uint64 = 0
    mask: uint64 = 0
  posQw = newSeq[uint32](W.len)
  posBit = newSeq[uint64](W.len)
  i = 0
  while i < W.len:
    w = int32(W[i]) - int32(firstPos)
    posQw[i] = cast[uint32](w shr 6)
    posBit[i] = 1'u64 shl (cast[uint32](w) and 63'u32)
    i = i + 1
  i = 0
  while i < bikeRPaddedQWords:
    val = 0'u64
    j = 0
    while j < W.len:
      mask = 0'u64 - uint64(secureCmp32(posQw[j], uint32(i)))
      val = val or (posBit[j] and mask)
      j = j + 1
    P[i] = val
    i = i + 1

proc sampleIndicesFisherYates*(numIndices, maxIdx: int, S: var BikePrfState): seq[uint32] =
  ## Sample `numIndices` unique positions via the BIKE Fisher-Yates stream.
  var
    i: int = 0
    j: int = 0
    rndBuf: seq[byte] = @[]
    rnd: uint64 = 0
    l: uint32 = 0
    isDup: uint32 = 0
    mask: uint32 = 0
  result = newSeq[uint32](numIndices)
  i = numIndices - 1
  while i >= 0:
    rndBuf = getPrfOutput(S, 4)
    rnd = uint64(loadU32Le(rndBuf, 0)) * uint64(maxIdx - i)
    l = uint32(i) + uint32(rnd shr 32)
    isDup = 0'u32
    j = i + 1
    while j < numIndices:
      isDup = isDup or secureCmp32(l, result[j])
      j = j + 1
    mask = 0'u32 - isDup
    result[i] = (mask and uint32(i)) xor ((not mask) and l)
    if i == 0:
      break
    i = i - 1

proc toIndexList(W: seq[uint32]): BikeIndexList =
  var
    i: int = 0
  if W.len != bikeD:
    raise newException(ValueError, "invalid BIKE index-list length")
  i = 0
  while i < bikeD:
    result[i] = W[i]
    i = i + 1

proc generateSecretKey*(seed0: BikeSeed): tuple[h0, h1: BikePadPoly, w0, w1: BikeIndexList] =
  ## Generate the BIKE-L1 secret polynomials from the first keypair seed.
  var
    prf: BikePrfState
    w0Seq: seq[uint32] = @[]
    w1Seq: seq[uint32] = @[]
  prf = initPrfState(seed0)
  result.h0 = newPadPoly()
  result.h1 = newPadPoly()
  w0Seq = sampleIndicesFisherYates(bikeD, bikeRBits, prf)
  w1Seq = sampleIndicesFisherYates(bikeD, bikeRBits, prf)
  result.w0 = toIndexList(w0Seq)
  result.w1 = toIndexList(w1Seq)
  secureSetBitsPort(result.h0, 0, result.w0)
  secureSetBitsPort(result.h1, 0, result.w1)
  zeroBytes(prf.buffer)

proc generateErrorVector*(seed: BikeSeed): BikeRawError =
  ## Generate the BIKE-L1 raw error vector from one message-sized seed.
  var
    prf: BikePrfState
    w: seq[uint32] = @[]
    e0: BikePadPoly = @[]
    e1: BikePadPoly = @[]
  prf = initPrfState(seed)
  w = sampleIndicesFisherYates(bikeT, bikeNBits, prf)
  e0 = newPadPoly()
  e1 = newPadPoly()
  secureSetBitsPort(e0, 0, w)
  secureSetBitsPort(e1, bikeRBits, w)
  result[0] = padPolyToRaw(e0)
  result[1] = padPolyToRaw(e1)
  maskRawLastByte(result[0])
  maskRawLastByte(result[1])
  zeroBytes(prf.buffer)

proc randomKeypairMaterial*(): seq[byte] =
  ## Draw the 64-byte BIKE keypair randomness stream.
  result = cryptoRandomBytes(bikeKeypairRandomBytes)

proc randomEncapsMaterial*(): seq[byte] =
  ## Draw the 64-byte BIKE encapsulation randomness stream.
  result = cryptoRandomBytes(bikeEncapsRandomBytes)
