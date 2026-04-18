## --------------------------------------------------------------------
## BIKE GF2X <- portable polynomial arithmetic over GF(2)[x]/(x^r - 1)
## --------------------------------------------------------------------

import ./params
import ./types
import ./util
import ../../../../helpers/otter_support

const
  bikeKSqrThreshold = 64

proc gf2xModAdd*(C: var BikePadPoly, A, B: BikePadPoly) =
  ## Compute `C = A + B mod 2` over padded qwords.
  var
    i: int = 0
  i = 0
  while i < bikeRPaddedQWords:
    C[i] = A[i] xor B[i]
    i = i + 1

proc gf2xMulBasePort(C: var seq[uint64], cOff: int, a, b: uint64) =
  var
    h: uint64 = 0
    l: uint64 = 0
    g1: uint64 = 0
    g2: uint64 = 0
    u: array[8, uint64]
    i: int = 0
    j: int = 0
    b0m: uint64 = b and ((1'u64 shl 61) - 1'u64)
    idx: uint64 = 0
  u[0] = 0
  u[1] = b0m
  u[2] = u[1] shl 1
  u[3] = u[2] xor b0m
  u[4] = u[2] shl 1
  u[5] = u[4] xor b0m
  u[6] = u[3] shl 1
  u[7] = u[6] xor b0m

  i = 0
  while i < 8:
    idx = uint64(i)
    l = l xor (u[i] and secureCmpeq64Mask(a and 7'u64, idx))
    l = l xor ((u[i] shl 3) and secureCmpeq64Mask((a shr 3) and 7'u64, idx))
    h = h xor ((u[i] shr 61) and secureCmpeq64Mask((a shr 3) and 7'u64, idx))
    i = i + 1

  i = 6
  while i < 64:
    g1 = 0'u64
    g2 = 0'u64
    j = 0
    while j < 8:
      idx = uint64(j)
      g1 = g1 xor (u[j] and secureCmpeq64Mask((a shr i) and 7'u64, idx))
      g2 = g2 xor (u[j] and secureCmpeq64Mask((a shr (i + 3)) and 7'u64, idx))
      j = j + 1
    l = l xor (g1 shl i) xor (g2 shl (i + 3))
    h = h xor (g1 shr (64 - i)) xor (g2 shr (64 - (i + 3)))
    i = i + 6

  i = 61
  while i < 64:
    if ((b shr i) and 1'u64) == 1'u64:
      l = l xor (a shl i)
      h = h xor (a shr (64 - i))
    i = i + 1

  C[cOff] = l
  C[cOff + 1] = h

proc gf2xSqrPort(A: BikePadPoly): BikeDoublePadPoly =
  var
    i: int = 0
  result = newDoublePadPoly()
  i = 0
  while i < bikeRQWords:
    gf2xMulBasePort(result, 2 * i, A[i], A[i])
    i = i + 1

proc gf2xRedPort(A: BikeDoublePadPoly): BikePadPoly =
  var
    i: int = 0
    vt0: uint64 = 0
    vt1: uint64 = 0
    vt2: uint64 = 0
  result = newPadPoly()
  i = 0
  while i < bikeRQWords:
    vt0 = A[i]
    vt1 = A[i + bikeRQWords] shl bikeLastRQWordTrail
    vt2 = A[i + bikeRQWords - 1] shr bikeLastRQWordLead
    result[i] = vt0 xor (vt1 or vt2)
    i = i + 1
  result[bikeRQWords - 1] = result[bikeRQWords - 1] and bikeLastRQWordMask
  i = bikeRQWords
  while i < bikeRPaddedQWords:
    result[i] = 0'u64
    i = i + 1

proc karatsubaAdd1(alah, blbh: var seq[uint64], A, B: seq[uint64],
    aOff, bOff, qLen: int) =
  var
    i: int = 0
  i = 0
  while i < qLen:
    alah[i] = A[aOff + i] xor A[aOff + qLen + i]
    blbh[i] = B[bOff + i] xor B[bOff + qLen + i]
    i = i + 1

proc karatsubaAdd2(Z: var seq[uint64], X, Y: seq[uint64], xOff, yOff, qLen: int) =
  var
    i: int = 0
  i = 0
  while i < qLen:
    Z[i] = X[xOff + i] xor Y[yOff + i]
    i = i + 1

proc karatsubaAdd3(C: var seq[uint64], cOff: int, mid: seq[uint64], qLen: int) =
  var
    i: int = 0
    vr0: uint64 = 0
    vr1: uint64 = 0
    vr2: uint64 = 0
    vr3: uint64 = 0
    vt: uint64 = 0
  i = 0
  while i < qLen:
    vr0 = C[cOff + i]
    vr1 = C[cOff + qLen + i]
    vr2 = C[cOff + (2 * qLen) + i]
    vr3 = C[cOff + (3 * qLen) + i]
    vt = mid[i]
    C[cOff + qLen + i] = vt xor vr0 xor vr1
    C[cOff + (2 * qLen) + i] = vt xor vr2 xor vr3
    i = i + 1

proc karatsuba(C: var seq[uint64], cOff: int, A, B: seq[uint64], aOff, bOff,
    qLen, qPad: int, sec: var seq[uint64], secOff: int) =
  var
    half: int = 0
    alah: seq[uint64] = @[]
    blbh: seq[uint64] = @[]
    tmp: seq[uint64] = @[]
  if qLen <= 1:
    gf2xMulBasePort(C, cOff, A[aOff], B[bOff])
    return

  half = qPad shr 1
  karatsuba(C, cOff, A, B, aOff, bOff, min(qLen, half), half, sec, secOff + (3 * half))
  if qLen <= half:
    return

  karatsuba(C, cOff + (2 * half), A, B, aOff + half, bOff + half, qLen - half, half,
    sec, secOff + (3 * half))

  alah = newSeq[uint64](half)
  blbh = newSeq[uint64](half)
  tmp = newSeq[uint64](half)
  karatsubaAdd1(alah, blbh, A, B, aOff, bOff, half)
  karatsubaAdd2(tmp, C, C, cOff + half, cOff + (2 * half), half)
  karatsuba(C, cOff + half, alah, blbh, 0, 0, half, half, sec, secOff + (3 * half))
  karatsubaAdd3(C, cOff, tmp, half)

proc toPadSeq(A: BikePadPoly): seq[uint64] =
  result = newSeq[uint64](bikeRPaddedQWords)
  var
    i: int = 0
  i = 0
  while i < bikeRPaddedQWords:
    result[i] = A[i]
    i = i + 1

proc gf2xModMul*(A, B: BikePadPoly): BikePadPoly =
  ## Multiply two padded BIKE polynomials modulo `x^r - 1`.
  otterSpan("bike.gf2xModMul"):
    var
      c: seq[uint64] = @[]
      aSeq: seq[uint64] = @[]
      bSeq: seq[uint64] = @[]
      sec: seq[uint64] = @[]
      dbl: BikeDoublePadPoly = @[]
      i: int = 0
    c = newSeq[uint64](bikeRPaddedQWords * 2)
    aSeq = toPadSeq(A)
    bSeq = toPadSeq(B)
    sec = newSeq[uint64](bikeRPaddedQWords * 3)
    karatsuba(c, 0, aSeq, bSeq, 0, 0, bikeRQWords, bikeRPaddedQWords, sec, 0)
    dbl = newDoublePadPoly()
    i = 0
    while i < dbl.len:
      dbl[i] = c[i]
      i = i + 1
    result = gf2xRedPort(dbl)
    zeroWords(c)
    zeroWords(aSeq)
    zeroWords(bSeq)
    zeroWords(sec)
    zeroWords(dbl)

proc kSqrPort*(A: BikePadPoly, lParam: int): BikePadPoly =
  var
    rawA: BikeRawPoly
    rawC: BikeRawPoly
    idx: int = 0
    pos: int = 0
  rawA = padPolyToRaw(A)
  idx = 0
  while idx < bikeRBytes * 8:
    pos = (lParam * idx) mod bikeRBits
    if getBitRaw(rawA, pos) == 1'u8:
      setBitRaw(rawC, idx)
    idx = idx + 1
  maskRawLastByte(rawC)
  result = rawToPadPoly(rawC)

proc gf2xModSqrInPlace(A: var BikePadPoly) =
  var
    dbl: BikeDoublePadPoly = @[]
  dbl = gf2xSqrPort(A)
  A = gf2xRedPort(dbl)
  zeroWords(dbl)

proc repeatedSquaring(A: BikePadPoly, numSqrs: int): BikePadPoly =
  var
    i: int = 0
  result = toPadSeq(A)
  i = 0
  while i < numSqrs:
    gf2xModSqrInPlace(result)
    i = i + 1

proc gf2xModInv*(A: BikePadPoly): BikePadPoly =
  ## Invert a BIKE-L1 polynomial modulo `x^r - 1`.
  otterSpan("bike.gf2xModInv"):
    var
      f: BikePadPoly = @[]
      g: BikePadPoly = @[]
      t: BikePadPoly = @[]
      i: int = 0
    f = toPadSeq(A)
    t = toPadSeq(A)
    i = 1
    while i < bikeExp0K.len:
      if bikeExp0K[i - 1] <= bikeKSqrThreshold:
        g = repeatedSquaring(f, bikeExp0K[i - 1])
      else:
        g = kSqrPort(f, bikeExp0L[i - 1])
      f = gf2xModMul(g, f)
      if bikeExp1K[i] != 0:
        if bikeExp1K[i] <= bikeKSqrThreshold:
          g = repeatedSquaring(f, bikeExp1K[i])
        else:
          g = kSqrPort(f, bikeExp1L[i])
        t = gf2xModMul(g, t)
      i = i + 1
    gf2xModSqrInPlace(t)
    result = t
