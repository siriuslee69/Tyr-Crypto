## ----------------------------------------------------------
## BIKE Decode <- portable BGF decoder for BIKE-L1 decapsulation
## ----------------------------------------------------------

import ./params
import ./types
import ./util
import ./gf2x
import ../../helpers/otter_support

proc log2Msb(v: int): int =
  var
    t: int = v
  result = 0
  while t > 0:
    result = result + 1
    t = t shr 1

proc copySyndrome(A: BikeSyndrome): BikeSyndrome =
  result = newSyndrome()
  var
    i: int = 0
  i = 0
  while i < result.len:
    result[i] = A[i]
    i = i + 1

proc dupPort(S: var BikeSyndrome) =
  var
    i: int = 0
  S[bikeRQWords - 1] =
    (S[0] shl bikeLastRQWordLead) or (S[bikeRQWords - 1] and bikeLastRQWordMask)
  i = 0
  while i < (2 * bikeRQWords) - 1:
    S[bikeRQWords + i] =
      (S[i] shr bikeLastRQWordTrail) or (S[i + 1] shl bikeLastRQWordLead)
    i = i + 1

proc rotrBig(outS: var BikeSyndrome, inS: BikeSyndrome, qwNumIn: int) =
  var
    qwNum: int = qwNumIn
    idx: int = 0
    mask32: uint32 = 0
    mask: uint64 = 0
    i: int = 0
  outS = copySyndrome(inS)
  idx = bikeQWordsHalfLog2
  while idx >= 1:
    mask32 = secureL32Mask(uint32(qwNum), uint32(idx))
    mask = uint64(mask32) or (uint64(mask32) shl 32)
    qwNum = qwNum - int(uint64(idx) and mask)
    i = 0
    while i < bikeRQWords + idx:
      outS[i] = (outS[i] and (not mask)) or (outS[i + idx] and mask)
      i = i + 1
    idx = idx shr 1

proc rotrSmall(outS: var BikeSyndrome, inS: BikeSyndrome, bits: int) =
  var
    mask: uint64 = 0
    highShift: int = 0
    i: int = 0
    lowPart: uint64 = 0
    highPart: uint64 = 0
  mask = 0'u64 - uint64(ord(bits != 0))
  highShift = int(uint64(64 - bits) and mask)
  i = 0
  while i < bikeRQWords:
    lowPart = inS[i] shr bits
    highPart = (inS[i + 1] shl highShift) and mask
    outS[i] = lowPart or highPart
    i = i + 1

proc rotateRightPort*(inS: BikeSyndrome, bitsCount: int): BikeSyndrome =
  ## Rotate the first `r` syndrome bits right by `bitsCount`.
  var
    tmp: BikeSyndrome = @[]
  tmp = newSyndrome()
  result = newSyndrome()
  rotrBig(tmp, inS, bitsCount div 64)
  rotrSmall(result, tmp, bitsCount mod 64)

proc bitSlicedAdderPort*(U: var BikeUpc, rotated: var BikeSyndrome, numSlices: int) =
  ## Add one rotated syndrome into the UPC bit-slice accumulator.
  var
    j: int = 0
    i: int = 0
    carry: uint64 = 0
  j = 0
  while j < numSlices:
    i = 0
    while i < bikeRQWords:
      carry = U[j][i] and rotated[i]
      U[j][i] = U[j][i] xor rotated[i]
      rotated[i] = carry
      i = i + 1
    j = j + 1

proc bitSliceFullSubtractPort*(U: var BikeUpc, vIn: int) =
  var
    br: seq[uint64] = @[]
    j: int = 0
    i: int = 0
    v: int = vIn
    lsbMask: uint64 = 0
    a: uint64 = 0
    tmp: uint64 = 0
  br = newSeq[uint64](bikeRQWords)
  j = 0
  while j < bikeSlices:
    if (v and 1) == 1:
      lsbMask = not 0'u64
    else:
      lsbMask = 0'u64
    v = v shr 1
    i = 0
    while i < bikeRQWords:
      a = U[j][i]
      tmp = ((not a) and lsbMask and (not br[i])) or (((not a) or lsbMask) and br[i])
      U[j][i] = a xor lsbMask xor br[i]
      br[i] = tmp
      i = i + 1
    j = j + 1

proc syndromeToRaw(S: BikeSyndrome): BikeRawPoly =
  var
    i: int = 0
    j: int = 0
    o: int = 0
    t: uint64 = 0
  i = 0
  o = 0
  while i < bikeRQWords:
    t = S[i]
    j = 0
    while j < 8 and o < bikeRBytes:
      result[o] = byte((t shr (j * 8)) and 0xff'u64)
      j = j + 1
      o = o + 1
    i = i + 1
  maskRawLastByte(result)

proc computeSyndrome(c0, h0: BikePadPoly): BikeSyndrome =
  var
    padS: BikePadPoly = @[]
    i: int = 0
  padS = gf2xModMul(c0, h0)
  result = newSyndrome()
  i = 0
  while i < bikeRQWords:
    result[i] = padS[i]
    i = i + 1
  dupPort(result)

proc recomputeSyndrome(c0, h0, pk: BikePadPoly, E: BikeRawError): BikeSyndrome =
  var
    ePad: array[bikeN0, BikePadPoly]
    tmpC0: BikePadPoly = @[]
  ePad = rawErrorToPad(E)
  tmpC0 = gf2xModMul(ePad[1], pk)
  gf2xModAdd(tmpC0, tmpC0, c0)
  gf2xModAdd(tmpC0, tmpC0, ePad[0])
  result = computeSyndrome(tmpC0, h0)

proc mul64High(a, b: uint64): uint64 =
  var
    aLo: uint64 = a and 0xffffffff'u64
    bLo: uint64 = b and 0xffffffff'u64
    aHi: uint64 = a shr 32
    bHi: uint64 = b shr 32
  result = aHi * bHi + ((aHi * bLo + aLo * bHi) shr 32)

proc getThreshold(S: BikeSyndrome): int =
  var
    syndromeWeight: uint64 = 0
    thr: uint64 = 0
    mask: uint32 = 0
  syndromeWeight = rBitsVectorWeight(syndromeToRaw(S))
  thr = bikeThresholdCoeff0 + (bikeThresholdCoeff1 * syndromeWeight)
  thr = mul64High(thr, bikeThresholdMulConst)
  thr = thr shr bikeThresholdShrConst
  mask = secureL32Mask(uint32(thr), uint32(bikeThresholdMin))
  thr = (uint64(mask) and thr) or (uint64(not mask) and uint64(bikeThresholdMin))
  result = int(thr)

proc updateErrorSlice(E: var BikeRawError, slot: int, lastSlice: BikePadPoly,
    sourceMask: BikeRawPoly) =
  var
    rawSlice: BikeRawPoly
    j: int = 0
    sumMsb: byte = 0
  rawSlice = padPolyToRaw(lastSlice)
  j = 0
  while j < bikeRBytes:
    sumMsb = not rawSlice[j]
    E[slot][j] = E[slot][j] xor (sourceMask[j] and sumMsb)
    j = j + 1
  maskRawLastByte(E[slot])

proc fillPotentialMask(dst: var BikeRawPoly, lastSlice: BikePadPoly) =
  var
    rawSlice: BikeRawPoly
    j: int = 0
  rawSlice = padPolyToRaw(lastSlice)
  j = 0
  while j < bikeRBytes:
    dst[j] = not rawSlice[j]
    j = j + 1
  maskRawLastByte(dst)

proc findErr1(E, blackE, grayE: var BikeRawError, S: BikeSyndrome,
    wlist: BikeDualIndexList, threshold: int) =
  var
    slot: int = 0
    j: int = 0
    rotated: BikeSyndrome = @[]
    U: BikeUpc
    lastSlice: BikePadPoly = @[]
    ones: BikeSyndrome = @[]
  slot = 0
  while slot < bikeN0:
    U = newUpc()
    j = 0
    while j < bikeD:
      rotated = rotateRightPort(S, int(wlist[slot][j]))
      bitSlicedAdderPort(U, rotated, log2Msb(j + 1))
      j = j + 1
    bitSliceFullSubtractPort(U, threshold)
    lastSlice = U[bikeSlices - 1]
    fillPotentialMask(blackE[slot], lastSlice)
    updateErrorSlice(E, slot, lastSlice, blackE[slot])
    ones = newSyndrome()
    j = 0
    while j < bikeRQWords:
      ones[j] = not 0'u64
      j = j + 1
    j = 0
    while j < bikeDelta:
      bitSlicedAdderPort(U, ones, bikeSlices)
      j = j + 1
    lastSlice = U[bikeSlices - 1]
    fillPotentialMask(grayE[slot], lastSlice)
    j = 0
    while j < bikeRBytes:
      grayE[slot][j] = (not blackE[slot][j]) and grayE[slot][j]
      j = j + 1
    maskRawLastByte(grayE[slot])
    slot = slot + 1

proc findErr2(E: var BikeRawError, posE: BikeRawError, S: BikeSyndrome,
    wlist: BikeDualIndexList, threshold: int) =
  var
    slot: int = 0
    j: int = 0
    rotated: BikeSyndrome = @[]
    U: BikeUpc
    lastSlice: BikePadPoly = @[]
  slot = 0
  while slot < bikeN0:
    U = newUpc()
    j = 0
    while j < bikeD:
      rotated = rotateRightPort(S, int(wlist[slot][j]))
      bitSlicedAdderPort(U, rotated, log2Msb(j + 1))
      j = j + 1
    bitSliceFullSubtractPort(U, threshold)
    lastSlice = U[bikeSlices - 1]
    updateErrorSlice(E, slot, lastSlice, posE[slot])
    slot = slot + 1

proc decodeBike*(ct: BikeCiphertextRaw, sk: BikeSecretKeyState): BikeRawError =
  ## Decode the BIKE-L1 error vector during decapsulation.
  otterSpan("bike.decodeBike"):
    var
      c0: BikePadPoly = @[]
      h0: BikePadPoly = @[]
      pk: BikePadPoly = @[]
      s: BikeSyndrome = @[]
      blackE: BikeRawError
      grayE: BikeRawError
      iter: int = 0
      threshold: int = 0
    c0 = rawToPadPoly(ct.c0)
    h0 = rawToPadPoly(sk.bin[0])
    pk = rawToPadPoly(sk.pk)
    s = computeSyndrome(c0, h0)
    iter = 0
    while iter < bikeMaxIt:
      threshold = getThreshold(s)
      findErr1(result, blackE, grayE, s, sk.wlist, threshold)
      s = recomputeSyndrome(c0, h0, pk, result)
      if iter < 1:
        findErr2(result, blackE, s, sk.wlist, ((bikeD + 1) div 2) + 1)
        s = recomputeSyndrome(c0, h0, pk, result)
        findErr2(result, grayE, s, sk.wlist, ((bikeD + 1) div 2) + 1)
        s = recomputeSyndrome(c0, h0, pk, result)
      iter = iter + 1
