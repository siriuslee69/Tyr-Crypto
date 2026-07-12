## Classic McEliece utility helpers (pure Nim).
## Provides constant‑time bit helpers and little‑endian load/store used by
## transpose/controlbits/benes. Kept tiny so it can be inlined by the caller.

type
  ## Field element type used by the Classic McEliece PQClean "clean" code paths.
  GF* = uint16

## Return 0xFFFF when x is non‑zero, else 0x0000. Constant‑time.
## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; portable representation and constant-schedule support for `ctNonZero16`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctNonZero16*(x: int16): int16 {.inline.} =
  var
    ux: uint16 = uint16(x)
    mask: uint16 = uint16((ux or (0'u16 - ux)) shr 15)
  return int16(mask) * int16(-1)  # mask is 0/1, scale to 0/-1

## Constant‑time minimum for signed 32‑bit values.
## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; portable representation and constant-schedule support for `ctMin32`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctMin32*(a, b: int32): int32 {.inline.} =
  var
    ab: int32 = a xor b
    c: int32 = b - a
    m: int32 = c xor ab
  m = m shr 31             # arithmetic shift, 0 or -1
  m = m and ab
  return a xor m

## Little‑endian load of 8 bytes into a uint64.
## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; portable representation and constant-schedule support for `load64`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load64*(p: ptr UncheckedArray[byte]): uint64 {.inline.} =
  var acc: uint64 = 0
  for i in 0 .. 7:
    acc = acc or (uint64(p[i]) shl (8 * i))
  acc

## Little‑endian store of a uint64 into 8 bytes.
## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; portable representation and constant-schedule support for `store64`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc store64*(p: ptr UncheckedArray[byte], v: uint64) {.inline.} =
  for i in 0 .. 7:
    p[i] = byte((v shr (8 * i)) and 0xFF)

## Bit‑reverse a 16‑bit word, then drop the top (16 - gfbits) bits.
## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; portable representation and constant-schedule support for `bitrev`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bitrev*(a: GF; gfbits: int): GF {.inline.} =
  var x = a
  x = ((x and 0x00FF) shl 8) or ((x and 0xFF00) shr 8)
  x = ((x and 0x0F0F) shl 4) or ((x and 0xF0F0) shr 4)
  x = ((x and 0x3333) shl 2) or ((x and 0xCCCC) shr 2)
  x = ((x and 0x5555) shl 1) or ((x and 0xAAAA) shr 1)
  return GF(x shr (16 - gfbits))
