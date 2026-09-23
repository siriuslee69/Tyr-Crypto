proc reduceModXnMinus1(dst: var HqcVec, W: seq[uint64], rOff: int,
    p: HqcParams) {.role: {math}, raises: [].} =
  ## dst/W/rOff/p: the n-bit result, the work area, where the 2n-word
  ## product sits, and the parameter set.
  ##
  ## Bit k+n of the product is the same as bit k, so the top half is
  ## shifted down and added to the bottom half. Because n is not a whole
  ## number of words, the shift straddles a word boundary and each output
  ## word takes a piece from two input words.
  var
    lowBits: int = 0
    r: uint64 = 0
    carry: uint64 = 0
    i: int = 0
  lowBits = p.n and 63
  i = 0
  while i < p.vecNWords:
    r = W[rOff + i + p.vecNWords - 1] shr lowBits
    carry = W[rOff + i + p.vecNWords] shl (64 - lowBits)
    dst[i] = W[rOff + i] xor r xor carry
    i = i + 1
  dst[p.vecNWords - 1] = dst[p.vecNWords - 1] and
    ((1'u64 shl lowBits) - 1'u64)

## Reference: [HQC-20250822] polynomial multiplication modulo x^n - 1; public product for `vecMul`; pitfall: the scratch must belong to this call alone, because the recursion writes all over it.
proc vecMul*(dst: var HqcVec, A, B: HqcVec, p: HqcParams, W: var seq[uint64])
    {.role: {math}, raises: [].} =
  ## dst/A/B/p/W: the n-bit product, the two n-bit operands, the parameter
  ## set, and a scratch buffer from `newHqcMulScratch`.
  ## Multiply two bit strings modulo x^n - 1.
  var
    n: int = 0
    aOff: int = 0
    bOff: int = 0
    tOff: int = 0
    i: int = 0
  n = p.vecNWords
  aOff = 2 * n
  bOff = 3 * n
  tOff = 4 * n
  i = 0
  while i < n:
    W[aOff + i] = A[i]
    W[bOff + i] = B[i]
    i = i + 1
  karatsubaMul(W, 0, aOff, bOff, n, tOff)
  reduceModXnMinus1(dst, W, 0, p)
