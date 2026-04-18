## -----------------------------------------------------------------
## BIKE Util <- serialization, masking, and constant-time helpers
## -----------------------------------------------------------------

import std/bitops

import ./params
import ./types

proc copyByteSeq*(A: openArray[byte]): seq[byte] =
  var
    i: int = 0
  result = newSeq[byte](A.len)
  i = 0
  while i < A.len:
    result[i] = A[i]
    i = i + 1

proc zeroBytes*(A: var openArray[byte]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u8
    i = i + 1

proc zeroWords*(A: var openArray[uint64]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u64
    i = i + 1

proc zeroIndices*(A: var openArray[uint32]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u32
    i = i + 1

proc newPadPoly*(): BikePadPoly =
  result = newSeq[uint64](bikeRPaddedQWords)

proc newDoublePadPoly*(): BikeDoublePadPoly =
  result = newSeq[uint64](bikeRPaddedQWords * 2)

proc newSyndrome*(): BikeSyndrome =
  result = newSeq[uint64](bikeRQWords * 3)

proc newUpc*(): BikeUpc =
  var
    i: int = 0
  i = 0
  while i < bikeSlices:
    result[i] = newSeq[uint64](bikeRPaddedQWords)
    i = i + 1

proc loadU32Le*(A: openArray[byte], o: int): uint32 =
  result =
    uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or
    (uint32(A[o + 3]) shl 24)

proc storeU32Le*(A: var openArray[byte], o: int, v: uint32) =
  A[o] = byte(v and 0xff'u32)
  A[o + 1] = byte((v shr 8) and 0xff'u32)
  A[o + 2] = byte((v shr 16) and 0xff'u32)
  A[o + 3] = byte((v shr 24) and 0xff'u32)

proc secureCmp32*(a, b: uint32): uint32 =
  var
    x: uint32 = 0
  x = a xor b
  result = uint32(1) xor uint32((x or (0'u32 - x)) shr 31)

proc secureL32Mask*(a, b: uint32): uint32 =
  result = not uint32((uint64(a) - uint64(b)) shr 32)

proc secureCmpeq64Mask*(a, b: uint64): uint64 =
  var
    x: uint64 = 0
  x = a xor b
  result = 0'u64 - (uint64(1) xor ((x or (0'u64 - x)) shr 63))

proc secureCmpBytes*(A, B: openArray[byte]): uint32 =
  var
    i: int = 0
    acc: uint8 = 0
  if A.len != B.len:
    return 0'u32
  i = 0
  while i < A.len:
    acc = acc or (A[i] xor B[i])
    i = i + 1
  result = uint32(acc == 0)

proc maskRawLastByte*(R: var BikeRawPoly) =
  R[bikeRBytes - 1] = R[bikeRBytes - 1] and bikeLastRByteMask

proc rawToPadPoly*(R: BikeRawPoly): BikePadPoly =
  var
    i: int = 0
    j: int = 0
    o: int = 0
  result = newPadPoly()
  i = 0
  o = 0
  while i < bikeRQWords:
    j = 0
    while j < 8 and o < bikeRBytes:
      result[i] = result[i] or (uint64(R[o]) shl (j * 8))
      j = j + 1
      o = o + 1
    i = i + 1
  result[bikeRQWords - 1] = result[bikeRQWords - 1] and bikeLastRQWordMask

proc padPolyToRaw*(P: BikePadPoly): BikeRawPoly =
  var
    i: int = 0
    j: int = 0
    o: int = 0
    t: uint64 = 0
  i = 0
  o = 0
  while i < bikeRQWords:
    t = P[i]
    j = 0
    while j < 8 and o < bikeRBytes:
      result[o] = byte((t shr (j * 8)) and 0xff'u64)
      j = j + 1
      o = o + 1
    i = i + 1
  result[bikeRBytes - 1] = result[bikeRBytes - 1] and bikeLastRByteMask

proc getBitRaw*(R: BikeRawPoly, pos: int): uint8 =
  result = uint8((R[pos shr 3] shr (pos and 7)) and 1'u8)

proc setBitRaw*(R: var BikeRawPoly, pos: int) =
  R[pos shr 3] = R[pos shr 3] or byte(1'u8 shl (pos and 7))

proc rBitsVectorWeight*(R: BikeRawPoly): uint64 =
  var
    i: int = 0
    b: byte = 0
  i = 0
  while i < bikeRBytes - 1:
    result = result + uint64(countSetBits(R[i]))
    i = i + 1
  b = R[bikeRBytes - 1] and bikeLastRByteMask
  result = result + uint64(countSetBits(b))

proc serializePublicKey*(R: BikeRawPoly): seq[byte] =
  result = copyByteSeq(R)

proc parsePublicKey*(A: openArray[byte]): BikeRawPoly =
  var
    i: int = 0
  if A.len != bikePublicKeyBytes:
    raise newException(ValueError, "invalid BIKE public key length")
  i = 0
  while i < bikeRBytes:
    result[i] = A[i]
    i = i + 1
  result[bikeRBytes - 1] = result[bikeRBytes - 1] and bikeLastRByteMask

proc serializeCiphertext*(ct: BikeCiphertextRaw): seq[byte] =
  result = newSeq[byte](bikeCiphertextBytes)
  copyMem(addr result[0], unsafeAddr ct.c0[0], bikeRBytes)
  copyMem(addr result[bikeRBytes], unsafeAddr ct.c1[0], bikeMessageBytes)

proc parseCiphertext*(A: openArray[byte]): BikeCiphertextRaw =
  var
    i: int = 0
  if A.len != bikeCiphertextBytes:
    raise newException(ValueError, "invalid BIKE ciphertext length")
  i = 0
  while i < bikeRBytes:
    result.c0[i] = A[i]
    i = i + 1
  result.c0[bikeRBytes - 1] = result.c0[bikeRBytes - 1] and bikeLastRByteMask
  i = 0
  while i < bikeMessageBytes:
    result.c1[i] = A[bikeRBytes + i]
    i = i + 1

proc serializeSecretKey*(S: BikeSecretKeyState): seq[byte] =
  var
    o: int = 0
    i: int = 0
    j: int = 0
  result = newSeq[byte](bikeSecretKeyBytes)
  o = 0
  i = 0
  while i < bikeN0:
    j = 0
    while j < bikeD:
      storeU32Le(result, o, S.wlist[i][j])
      o = o + 4
      j = j + 1
    i = i + 1
  i = 0
  while i < bikeN0:
    copyMem(addr result[o], unsafeAddr S.bin[i][0], bikeRBytes)
    o = o + bikeRBytes
    i = i + 1
  copyMem(addr result[o], unsafeAddr S.pk[0], bikeRBytes)
  o = o + bikeRBytes
  copyMem(addr result[o], unsafeAddr S.sigma[0], bikeMessageBytes)

proc parseSecretKey*(A: openArray[byte]): BikeSecretKeyState =
  var
    o: int = 0
    i: int = 0
    j: int = 0
  if A.len != bikeSecretKeyBytes:
    raise newException(ValueError, "invalid BIKE secret key length")
  o = 0
  i = 0
  while i < bikeN0:
    j = 0
    while j < bikeD:
      result.wlist[i][j] = loadU32Le(A, o)
      o = o + 4
      j = j + 1
    i = i + 1
  i = 0
  while i < bikeN0:
    copyMem(addr result.bin[i][0], unsafeAddr A[o], bikeRBytes)
    result.bin[i][bikeRBytes - 1] = result.bin[i][bikeRBytes - 1] and bikeLastRByteMask
    o = o + bikeRBytes
    i = i + 1
  copyMem(addr result.pk[0], unsafeAddr A[o], bikeRBytes)
  result.pk[bikeRBytes - 1] = result.pk[bikeRBytes - 1] and bikeLastRByteMask
  o = o + bikeRBytes
  copyMem(addr result.sigma[0], unsafeAddr A[o], bikeMessageBytes)

proc toSeed*(A: openArray[byte], o: int = 0): BikeSeed =
  var
    i: int = 0
  if A.len - o < bikeSeedBytes:
    raise newException(ValueError, "invalid BIKE seed length")
  i = 0
  while i < bikeSeedBytes:
    result[i] = A[o + i]
    i = i + 1

proc rawErrorToPad*(E: BikeRawError): array[bikeN0, BikePadPoly] =
  var
    i: int = 0
  i = 0
  while i < bikeN0:
    result[i] = rawToPadPoly(E[i])
    i = i + 1

proc padSliceToRaw*(P: BikePadPoly): BikeRawPoly =
  result = padPolyToRaw(P)

proc appendRawPoly*(dst: var seq[byte], R: BikeRawPoly) =
  var
    start: int = 0
  start = dst.len
  dst.setLen(start + bikeRBytes)
  copyMem(addr dst[start], unsafeAddr R[0], bikeRBytes)
