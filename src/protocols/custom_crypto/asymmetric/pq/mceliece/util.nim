## Little-endian helpers and constant-time masks used across the Classic McEliece helpers.

import std/[typetraits, volatile]

type
  GF* = uint16

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `storeGF`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc storeGF*(dest: var openArray[byte], a: GF) =
  ## Store a GF element to two bytes (little-endian).
  assert dest.len >= 2
  dest[0] = byte(a and 0xFF)
  dest[1] = byte((a shr 8) and 0xFF)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `loadGF`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc loadGF*(src: openArray[byte]): GF =
  ## Load a GF element from two bytes (little-endian) and mask to the field size.
  assert src.len >= 2
  var a: uint16 = (uint16(src[1]) shl 8) or uint16(src[0])
  a and 0x1FFF'u16

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `load4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load4*(src: openArray[byte]): uint32 =
  ## Load 4 bytes little-endian.
  assert src.len >= 4
  var ret = uint32(src[3])
  for i in countdown(2, 0):
    ret = (ret shl 8) or uint32(src[i])
  ret

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `store8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc store8*(dest: var openArray[byte], v: uint64) =
  ## Store 8 bytes little-endian.
  assert dest.len >= 8
  dest[0] = byte((v shr 0) and 0xFF)
  dest[1] = byte((v shr 8) and 0xFF)
  dest[2] = byte((v shr 16) and 0xFF)
  dest[3] = byte((v shr 24) and 0xFF)
  dest[4] = byte((v shr 32) and 0xFF)
  dest[5] = byte((v shr 40) and 0xFF)
  dest[6] = byte((v shr 48) and 0xFF)
  dest[7] = byte((v shr 56) and 0xFF)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `load8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load8*(src: openArray[byte]): uint64 =
  ## Load 8 bytes little-endian.
  assert src.len >= 8
  var ret = uint64(src[7])
  for i in countdown(6, 0):
    ret = (ret shl 8) or uint64(src[i])
  ret

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `bitrev`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bitrev*(a: GF): GF =
  ## Bit-reverse the 13-bit field element and drop the top 3 padding bits.
  var x = a
  x = ((x and 0x00FF'u16) shl 8) or ((x and 0xFF00'u16) shr 8)
  x = ((x and 0x0F0F'u16) shl 4) or ((x and 0xF0F0'u16) shr 4)
  x = ((x and 0x3333'u16) shl 2) or ((x and 0xCCCC'u16) shr 2)
  x = ((x and 0x5555'u16) shl 1) or ((x and 0xAAAA'u16) shr 1)
  (x shr 3) and 0x1FFF'u16

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `ctMaskNonZero`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctMaskNonZero*(x: GF): uint16 {.inline.} =
  ## Return 0xFFFF when x != 0, else 0x0000 (branch-free).
  var m = uint16(x)
  m = m - 1'u16
  m = m shr 15
  m = m - 1'u16
  m

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `ctMaskZero`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctMaskZero*(x: GF): uint16 {.inline.} =
  ## Return 0xFFFF when x == 0, else 0x0000 (branch-free).
  not ctMaskNonZero(x)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; canonical byte and polynomial encoding rules for `clearSensitiveWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearSensitiveWords*[T](A: var openArray[T]) {.raises: [].} =
  ## Volatile wipe for POD buffers that hold transient secret data.
  when supportsCopyMem(T):
    if A.len == 0:
      return
    var
      p = cast[ptr UncheckedArray[byte]](unsafeAddr A[0])
      i: int = 0
      n: int = A.len * sizeof(T)
    while i < n:
      volatileStore(addr p[i], 0'u8)
      i = i + 1
  else:
    {.error: "clearSensitiveWords requires supportsCopyMem(T)".}
