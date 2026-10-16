## ---------------------------------------------------------------------
## | HQC GF2X <- multiplying two very long bit strings                  |
## ---------------------------------------------------------------------
##
## What "multiply" means here
## --------------------------
## Both operands are polynomials with one bit per coefficient, and the
## product is taken modulo x^n - 1. That last part makes the product
## cyclic: anything that runs off the top end wraps back to the bottom.
##
##   plain product:  2n bits, degrees 0 .. 2n-2
##   after folding:  n bits,  bit k gets bit k and bit k+n added in
##
## There are no carries anywhere, because 1 + 1 = 0 in this arithmetic.
##
## Two multiplication strategies
## -----------------------------
## Short operands use the obvious method - take each bit of `a` that is
## set and add a shifted copy of `b`. That costs about n^2 word steps.
##
## Long operands use Karatsuba, which splits each operand in half and
## trades one of the four half-size multiplications for a few additions:
##
##   a = a1*X + a0        b = b1*X + b0
##   z0 = a0*b0     z2 = a1*b1     zmid = (a0+a1)*(b0+b1)
##   a*b = z2*X^2 + (zmid - z0 - z2)*X + z0
##
## Three half-size products instead of four, applied over and over, turns
## n^2 into roughly n^1.58. Below 16 words the bookkeeping costs more
## than it saves, so the obvious method takes over again.
##
## One flat scratch buffer
## -----------------------
## Every intermediate lives in a single array of words, addressed by
## offset. That mirrors the reference implementation exactly and means
## the recursion never allocates:
##
##   +--------+--------+----------+------+------+---------------------+
##   |   z0   |   z2   |   zmid   |  ta  |  tb  |  scratch for the    |
##   |   2n   |   2n   |    2n    |  n   |  n   |  next level down    |
##   +--------+--------+----------+------+------+---------------------+
##   0       2n       4n         6n     7n     8n
##
## Reference: [HQC-20250822] polynomial multiplication modulo x^n - 1;
## ported from the reference implementation's `gf2x.c`.

import runePragmas
import ./params
import ./types

const
  karatsubaThreshold = 16
    ## Operand size in 64-bit words below which splitting stops paying off.
  scratchWordsPerWord = 16
    ## The recursion needs under 16 words of scratch per operand word;
    ## see the layout picture above, summed over every level.
  scratchSlackWords = 64
    ## A little headroom so no rounding at a recursion boundary can bite.

## Reference: [HQC-20250822] polynomial multiplication; scratch sizing for `newHqcMulScratch`; pitfall: the buffer holds the operands and the product as well as the recursion scratch.
proc newHqcMulScratch*(p: HqcParams): seq[uint64] {.role: {helper}, raises: [].} =
  ## p: the parameter set.
  ## One reusable work area for `vecMul`, laid out as
  ##
  ##   [0 .. 2n)      the unfolded product
  ##   [2n .. 3n)     a copy of the first operand
  ##   [3n .. 4n)     a copy of the second operand
  ##   [4n .. )       the recursion scratch drawn above
  result = newSeq[uint64](4 * p.vecNWords +
    scratchWordsPerWord * p.vecNWords + scratchSlackWords)

## Reference: [HQC-20250822] polynomial multiplication; one masked shifted row for `xorShiftedRow`; pitfall: bit 0 has no carry word, every other bit spills into the next word.
proc xorShiftedRow(W: var seq[uint64], rOff, bOff, n, bit: int, mask: uint64)
    {.inline, raises: [].} =
  ## W: work area. rOff: where this row lands. bOff/n: operand b and its length.
  ## bit/mask: shift amount and all-ones (bit of a set) or all-zeros.
  ##   r[j]   ^= (b[j] shl bit)        and mask
  ##   r[j+1] ^= (b[j] shr (64 - bit)) and mask     (only when bit > 0)
  var
    j: int = 0
  if bit == 0:
    while j < n:
      W[rOff + j] = W[rOff + j] xor (W[bOff + j] and mask)
      j = j + 1
    return
  while j < n:
    W[rOff + j] = W[rOff + j] xor ((W[bOff + j] shl bit) and mask)
    W[rOff + j + 1] = W[rOff + j + 1] xor ((W[bOff + j] shr (64 - bit)) and mask)
    j = j + 1

## Reference: [HQC-20250822] polynomial multiplication; schoolbook product for `schoolbookMul`; pitfall: the destination range must not overlap either operand range.
proc schoolbookMul(W: var seq[uint64], rOff, aOff, bOff, n: int)
    {.role: {math}, raises: [].} =
  ## W/rOff/aOff/bOff/n: the work area, where the 2n-word product goes,
  ## where the two n-word operands are, and how long they are.
  ##
  ## For every set bit of `a`, add `b` shifted left by that many places.
  ## The shift is applied with a mask instead of a branch so the work
  ## does not depend on which bits happen to be set.
  var
    ai: uint64 = 0
    mask: uint64 = 0
    i: int = 0
    bit: int = 0
  i = 0
  while i < 2 * n:
    W[rOff + i] = 0'u64
    i = i + 1
  i = 0
  while i < n:
    ai = W[aOff + i]
    bit = 0
    while bit < 64:
      mask = 0'u64 - ((ai shr bit) and 1'u64)
      xorShiftedRow(W, rOff + i, bOff, n, bit, mask)
      bit = bit + 1
    i = i + 1

## Reference: [HQC-20250822] polynomial multiplication; recursive split for `karatsubaMul`; pitfall: the child scratch starts past `ta` and `tb`, so a shorter offset silently corrupts the middle product.
include "gf2x_karatsuba.nim"
include "gf2x_reduce.nim"
