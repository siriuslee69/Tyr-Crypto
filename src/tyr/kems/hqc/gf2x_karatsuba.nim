proc karatsubaMul(W: var seq[uint64], rOff, aOff, bOff, n, tOff: int)
    {.role: {math}, raises: [].} =
  ## W/rOff/aOff/bOff/n/tOff: the work area, the 2n-word product slot, the
  ## two n-word operands, their length, and where this level's scratch
  ## starts.
  var
    m: int = 0
    n0: int = 0
    n1: int = 0
    z0Off: int = 0
    z2Off: int = 0
    zmidOff: int = 0
    taOff: int = 0
    tbOff: int = 0
    childOff: int = 0
    lowA: uint64 = 0
    lowB: uint64 = 0
    mid: uint64 = 0
    z0i: uint64 = 0
    i: int = 0
  if n <= karatsubaThreshold:
    schoolbookMul(W, rOff, aOff, bOff, n)
    return
  m = n shr 1
  n0 = m
  n1 = n - m
  z0Off = tOff
  z2Off = z0Off + 2 * n
  zmidOff = z2Off + 2 * n
  taOff = zmidOff + 2 * n
  tbOff = taOff + n
  childOff = tOff + 8 * n
  karatsubaMul(W, z0Off, aOff, bOff, n0, childOff)
  karatsubaMul(W, z2Off, aOff + m, bOff + m, n1, childOff)
  i = 0
  while i < n1:
    lowA = 0'u64
    lowB = 0'u64
    if i < n0:
      lowA = W[aOff + i]
      lowB = W[bOff + i]
    W[taOff + i] = lowA xor W[aOff + m + i]
    W[tbOff + i] = lowB xor W[bOff + m + i]
    i = i + 1
  karatsubaMul(W, zmidOff, taOff, tbOff, n1, childOff)
  ## Put the three pieces back together.
  i = 0
  while i < 2 * n:
    W[rOff + i] = 0'u64
    i = i + 1
  i = 0
  while i < 2 * n0:
    W[rOff + i] = W[rOff + i] xor W[z0Off + i]
    i = i + 1
  i = 0
  while i < 2 * n1:
    W[rOff + 2 * m + i] = W[rOff + 2 * m + i] xor W[z2Off + i]
    i = i + 1
  i = 0
  while i < 2 * n1:
    z0i = 0'u64
    if i < 2 * n0:
      z0i = W[z0Off + i]
    mid = W[zmidOff + i] xor z0i xor W[z2Off + i]
    W[rOff + m + i] = W[rOff + m + i] xor mid
    i = i + 1

## Reference: [HQC-20250822] reduction modulo x^n - 1; folding step for `reduceModXnMinus1`; pitfall: n is never a multiple of 64 for any HQC parameter set, so the shift amounts stay in range.
