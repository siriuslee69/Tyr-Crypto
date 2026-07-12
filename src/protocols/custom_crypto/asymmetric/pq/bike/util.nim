## -----------------------------------------------------------------
## BIKE Util <- serialization, masking, and constant-time helpers
## -----------------------------------------------------------------

import std/bitops
import std/typetraits
import std/volatile

import ./params
import ./types

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `secureZeroBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc secureZeroBytes*(A: var openArray[byte]) =
  ## Volatile zeroization for secret byte buffers (cannot be elided).
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u8)
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `secureZeroWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc secureZeroWords*(A: var openArray[uint64]) =
  ## Volatile zeroization for secret word buffers (cannot be elided).
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u64)
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `secureZeroPod`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc secureZeroPod*[T](S: var T) =
  ## Volatile zeroization for POD-style secret stack state.
  static:
    doAssert supportsCopyMem(T), "secureZeroPod requires a POD-style type"
  var
    p: ptr UncheckedArray[byte] = cast[ptr UncheckedArray[byte]](addr S)
    i: int = 0
  while i < sizeof(T):
    volatileStore(addr p[i], 0'u8)
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `copyByteSeq`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc copyByteSeq*(A: openArray[byte]): seq[byte] =
  var
    i: int = 0
  result = newSeq[byte](A.len)
  i = 0
  while i < A.len:
    result[i] = A[i]
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `zeroBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zeroBytes*(A: var openArray[byte]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u8
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `zeroWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zeroWords*(A: var openArray[uint64]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u64
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `zeroIndices`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zeroIndices*(A: var openArray[uint32]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u32
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `newPadPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc newPadPoly*(): BikePadPoly =
  result = newSeq[uint64](bikeRPaddedQWords)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `newDoublePadPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc newDoublePadPoly*(): BikeDoublePadPoly =
  result = newSeq[uint64](bikeRPaddedQWords * 2)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `newSyndrome`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc newSyndrome*(): BikeSyndrome =
  result = newSeq[uint64](bikeRQWords * 3)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `newUpc`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc newUpc*(): BikeUpc =
  var
    i: int = 0
  i = 0
  while i < bikeSlices:
    result[i] = newSeq[uint64](bikeRPaddedQWords)
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `loadU32Le`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc loadU32Le*(A: openArray[byte], o: int): uint32 =
  result =
    uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or
    (uint32(A[o + 3]) shl 24)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `storeU32Le`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc storeU32Le*(A: var openArray[byte], o: int, v: uint32) =
  A[o] = byte(v and 0xff'u32)
  A[o + 1] = byte((v shr 8) and 0xff'u32)
  A[o + 2] = byte((v shr 16) and 0xff'u32)
  A[o + 3] = byte((v shr 24) and 0xff'u32)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `secureCmp32`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc secureCmp32*(a, b: uint32): uint32 =
  var
    x: uint32 = 0
  x = a xor b
  result = uint32(1) xor uint32((x or (0'u32 - x)) shr 31)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `secureL32Mask`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc secureL32Mask*(a, b: uint32): uint32 =
  result = not uint32((uint64(a) - uint64(b)) shr 32)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `secureCmpeq64Mask`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc secureCmpeq64Mask*(a, b: uint64): uint64 =
  var
    x: uint64 = 0
  x = a xor b
  result = 0'u64 - (uint64(1) xor ((x or (0'u64 - x)) shr 63))

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `secureCmpBytes`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `maskRawLastByte`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc maskRawLastByte*(R: var BikeRawPoly) =
  R[bikeRBytes - 1] = R[bikeRBytes - 1] and bikeLastRByteMask

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `rawToPadPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `padPolyToRaw`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `getBitRaw`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc getBitRaw*(R: BikeRawPoly, pos: int): uint8 =
  result = uint8((R[pos shr 3] shr (pos and 7)) and 1'u8)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `setBitRaw`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setBitRaw*(R: var BikeRawPoly, pos: int) =
  R[pos shr 3] = R[pos shr 3] or byte(1'u8 shl (pos and 7))

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `rBitsVectorWeight`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `serializePublicKey`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc serializePublicKey*(R: BikeRawPoly): seq[byte] =
  result = copyByteSeq(R)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `parsePublicKey`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `serializeCiphertext`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc serializeCiphertext*(ct: BikeCiphertextRaw): seq[byte] =
  result = newSeq[byte](bikeCiphertextBytes)
  copyMem(addr result[0], unsafeAddr ct.c0[0], bikeRBytes)
  copyMem(addr result[bikeRBytes], unsafeAddr ct.c1[0], bikeMessageBytes)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `parseCiphertext`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `serializeSecretKey`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `parseSecretKey`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `toSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toSeed*(A: openArray[byte], o: int = 0): BikeSeed =
  var
    i: int = 0
  if A.len - o < bikeSeedBytes:
    raise newException(ValueError, "invalid BIKE seed length")
  i = 0
  while i < bikeSeedBytes:
    result[i] = A[o + i]
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `rawErrorToPad`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc rawErrorToPad*(E: BikeRawError): array[bikeN0, BikePadPoly] =
  var
    i: int = 0
  i = 0
  while i < bikeN0:
    result[i] = rawToPadPoly(E[i])
    i = i + 1

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `padSliceToRaw`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc padSliceToRaw*(P: BikePadPoly): BikeRawPoly =
  result = padPolyToRaw(P)

## Reference: [BIKE-5.2] sections 2-4, BIKE KEM and BGF decoder algorithms; canonical byte and polynomial encoding rules for `appendRawPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc appendRawPoly*(dst: var seq[byte], R: BikeRawPoly) =
  var
    start: int = 0
  start = dst.len
  dst.setLen(start + bikeRBytes)
  copyMem(addr dst[start], unsafeAddr R[0], bikeRBytes)
