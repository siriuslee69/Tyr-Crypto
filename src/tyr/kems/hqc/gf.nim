## ---------------------------------------------------------------------
## | HQC GF <- arithmetic in GF(2^8), the field one byte lives in       |
## ---------------------------------------------------------------------
##
## What a "field element" is here
## ------------------------------
## The Reed-Solomon half of HQC treats every byte as a polynomial whose
## coefficients are single bits:
##
##   byte 0b1000_1101  ->  x^7 + x^3 + x^2 + 1
##
## Adding two of them is exclusive-or, because 1 + 1 = 0 with no carry.
## Multiplying them is polynomial multiplication followed by a division
## remainder, taken against one fixed polynomial:
##
##   modulus = x^8 + x^4 + x^3 + x^2 + 1     (written 0x11D)
##
## That remainder step is what keeps every product inside one byte.
##
## Powers of alpha
## ---------------
## `alpha` is the element 2 (the polynomial `x`). Multiplying by it
## repeatedly walks through every non-zero byte exactly once before
## returning to 1, which is why 255 powers cover the whole field:
##
##   alpha^0 = 1, alpha^1 = 2, alpha^2 = 4, ... alpha^7 = 128,
##   alpha^8 = 29  <- 256 does not fit in a byte, so the modulus is applied
##
## `gfExp` lists those powers and `gfLog` reverses the list. Both are
## worked out while compiling, from the recurrence above, so there are no
## transcribed magic numbers to get wrong.
##
## Constant time
## -------------
## `gfMul` never indexes a table with a secret value. It multiplies bit
## by bit with masks instead, which is slower than a lookup and is the
## point: a cache-timing observer learns nothing about the operands.
##
## Reference: [HQC-20250822] GF(2^8) arithmetic used by the Reed-Solomon
## code; ported from the reference implementation's `gf.c`, which in turn
## follows algorithm `mul1` of https://hal.inria.fr/inria-00188261v4.

import runePragmas
import ./params

## Reference: [HQC-20250822] GF(2^8) definition; table construction for `buildGfExp`; pitfall: entries 255..257 repeat the start of the cycle and are needed by the multiply.
proc buildGfExp(): array[258, uint16] {.raises: [].} =
  ## Powers of alpha, worked out at compile time.
  ##
  ##   result[k] = alpha^k for k in 0..254
  ##   result[255] = 1, result[256] = 2, result[257] = 4
  ##
  ## The last three repeat the beginning of the cycle so callers that add
  ## two logarithms never have to reduce the sum first.
  var
    elt: uint16 = 1
    i: int = 0
  while i < hqcGfMulOrder:
    result[i] = elt
    elt = elt * 2'u16
    if elt >= (1'u16 shl hqcGfM):
      elt = elt xor uint16(hqcGfPoly)
    i = i + 1
  result[hqcGfMulOrder] = 1
  result[hqcGfMulOrder + 1] = 2
  result[hqcGfMulOrder + 2] = 4

## Reference: [HQC-20250822] GF(2^8) definition; table construction for `buildGfLog`; pitfall: the logarithm of zero does not exist and is fixed at zero by convention.
proc buildGfLog(E: array[258, uint16]): array[256, uint16] {.raises: [].} =
  ## E: the exponent table.
  ## The reverse of `buildGfExp`: which power of alpha a byte is.
  var
    i: int = 0
  while i < hqcGfMulOrder:
    result[int(E[i])] = uint16(i)
    i = i + 1
  result[0] = 0

const
  gfExp* = buildGfExp()
    ## gfExp[k] is alpha^k. 258 entries; see `buildGfExp`.
  gfLog* = buildGfLog(gfExp)
    ## gfLog[b] is the k with alpha^k = b. gfLog[0] is 0 by convention.

  gfReductionTaps: array[3, int] = [4, 3, 2]
    ## 0x11D is 0b1_0001_1101, so bits 8, 4, 3, 2 and 0 are set. Bit 8 is
    ## removed by the shift and bit 0 by the first exclusive-or, leaving
    ## these three positions to fold the overflow back into.

## Reference: [HQC-20250822] GF(2^8) reduction; remainder step for `gfReduce`; pitfall: two rounds are needed because a product of two degree-7 values reaches degree 14.
proc gfReduce*(x: uint16): uint16 {.role: {math}, raises: [].} =
  ## x: a polynomial of degree 14 or less.
  ## Take the remainder modulo 0x11D, leaving a polynomial of degree 7
  ## or less - that is, a value that fits in one byte.
  var
    t: uint16 = x
    m: uint32 = 0
    z1: int = 0
    z2: int = 0
    dist: int = 0
    round: int = 0
    j: int = 0
  while round < 2:
    m = uint32(t) shr hqcGfM
    t = t and ((1'u16 shl hqcGfM) - 1'u16)
    t = t xor uint16(m and 0xffff'u32)
    z1 = 0
    j = gfReductionTaps.len
    while j > 0:
      z2 = gfReductionTaps[j - 1]
      dist = z2 - z1
      m = m shl dist
      t = t xor uint16(m and 0xffff'u32)
      z1 = z2
      j = j - 1
    round = round + 1
  result = t

## Reference: [HQC-20250822] GF(2^8) multiplication; carry-less product for `gfCarrylessMul`; pitfall: the two-bit window table must be selected with masks, never with an index, or the timing leaks the operand.
proc gfCarrylessMul(a, b: uint16): uint16 {.role: {math}, raises: [].} =
  ## a/b: two bytes read as polynomials.
  ## Multiply without ever carrying, giving a polynomial of degree 14 or
  ## less packed into 16 bits.
  ##
  ## The work is done two bits of `a` at a time. `u` holds the four
  ## possible partial products (0, b, 2b, 3b) and the right one is picked
  ## by exclusive-or with a mask, so every call touches all four.
  var
    u = default(array[4, uint16])
    g: uint16 = 0
    lo: uint16 = 0
    hi: uint16 = 0
    window: uint16 = 0
    diff: uint32 = 0
    mask: uint16 = 0
    i: int = 0
    j: int = 0
  u[0] = 0
  u[1] = b and ((1'u16 shl 7) - 1'u16)
  u[2] = u[1] shl 1
  u[3] = u[2] xor u[1]
  window = a and 3'u16
  g = 0
  j = 0
  while j < 4:
    diff = uint32(window) - uint32(j)
    g = g xor (u[j] and uint16((0'u32 - (1'u32 - ((diff or (0'u32 - diff)) shr 31))) and 0xffff'u32))
    j = j + 1
  lo = g
  hi = 0
  i = 2
  while i < 8:
    g = 0
    window = (a shr i) and 3'u16
    j = 0
    while j < 4:
      diff = uint32(window) - uint32(j)
      g = g xor (u[j] and uint16((0'u32 - (1'u32 - ((diff or (0'u32 - diff)) shr 31))) and 0xffff'u32))
      j = j + 1
    lo = lo xor (g shl i)
    hi = hi xor (g shr (8 - i))
    i = i + 2
  ## The top bit of `b` was masked out of `u` above, so add its
  ## contribution back in here.
  mask = 0'u16 - ((b shr 7) and 1'u16)
  lo = lo xor ((a shl 7) and mask)
  hi = hi xor ((a shr 1) and mask)
  result = (lo and 0xff'u16) xor ((hi and 0xff'u16) shl 8)

## Reference: [HQC-20250822] GF(2^8) multiplication; field product for `gfMul`; pitfall: must stay free of secret-dependent table lookups and branches.
proc gfMul*(a, b: uint16): uint16 {.role: {math}, raises: [].} =
  ## a/b: two field elements.
  ## Their product in GF(2^8), in constant time.
  result = gfReduce(gfCarrylessMul(a and 0xff'u16, b and 0xff'u16))

## Reference: [HQC-20250822] GF(2^8) squaring; bit spreading for `gfSquare`; pitfall: squaring spreads bit i to position 2i because cross terms cancel in characteristic two.
proc gfSquare*(a: uint16): uint16 {.role: {math}, raises: [].} =
  ## a: a field element.
  ## Its square. In this field squaring only moves bits apart:
  ##
  ##   bit 0 -> bit 0, bit 1 -> bit 2, bit 2 -> bit 4, ...
  ##
  ## because every cross term appears twice and cancels.
  var
    b: uint32 = uint32(a)
    s: uint32 = uint32(a) and 1'u32
    i: int = 1
  while i < hqcGfM:
    b = b shl 1
    s = s xor (b and (1'u32 shl (2 * i)))
    i = i + 1
  result = gfReduce(uint16(s and 0xffff'u32))

## Reference: [HQC-20250822] GF(2^8) inversion; addition chain for `gfInverse`; pitfall: the inverse of zero is defined as zero here, matching the reference implementation.
proc gfInverse*(a: uint16): uint16 {.role: {math}, raises: [].} =
  ## a: a field element.
  ## Its multiplicative inverse, which is a^254 because a^255 = 1.
  ##
  ## Reaching a^254 takes only eleven operations by climbing the chain
  ## 1, 2, 3, 4, 7, 11, 15, 30, 60, 120, 127, 254 rather than multiplying
  ## 253 times.
  var
    inv: uint16 = 0
    t1: uint16 = 0
    t2: uint16 = 0
  inv = gfSquare(a)       ## a^2
  t1 = gfMul(inv, a)      ## a^3
  inv = gfSquare(inv)     ## a^4
  t2 = gfMul(inv, t1)     ## a^7
  t1 = gfMul(inv, t2)     ## a^11
  inv = gfMul(t1, inv)    ## a^15
  inv = gfSquare(inv)     ## a^30
  inv = gfSquare(inv)     ## a^60
  inv = gfSquare(inv)     ## a^120
  inv = gfMul(inv, t2)    ## a^127
  inv = gfSquare(inv)     ## a^254
  result = inv

