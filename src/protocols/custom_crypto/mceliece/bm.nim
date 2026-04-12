## Berlekamp-Massey for Classic McEliece (parameterised by variant).

import ./params
import ./gf
import ./util

proc berlekampMassey*(p: McElieceParams; s: openArray[GF]; outPoly: var seq[GF]) =
  ## Compute the minimal polynomial of the syndrome sequence `s`.
  ## `s` must contain `2 * sysT` field elements.
  var
    C = newSeq[GF](p.sysT + 1)
    B = newSeq[GF](p.sysT + 1)
    T = newSeq[GF](p.sysT + 1)
    b: GF = 1
    L: uint32 = 0
    upper: int = 0
    d: GF = 0
    mne: uint16 = 0
    mle: uint16 = 0
    f: GF = 0
    newL: uint32 = 0
  assert s.len >= 2 * p.sysT
  outPoly.setLen(p.sysT + 1)
  C[0] = 1
  B[1] = 1

  for N in 0 ..< 2 * p.sysT:
    d = 0
    upper = N
    if upper > p.sysT:
      upper = p.sysT
    for i in 0 .. upper:
      d = d xor gfMul(C[i], s[N - i])

    mne = uint16(d)
    mne = mne - 1
    mne = mne shr 15
    mne = mne - 1

    mle = uint16(N) - uint16(2'u32 * L)
    mle = mle shr 15
    mle = mle - 1
    mle = mle and mne

    for i in 0 .. p.sysT:
      T[i] = C[i]

    f = gfFrac(b, d)
    for i in 0 .. p.sysT:
      C[i] = C[i] xor (gfMul(f, B[i]) and GF(mne))

    newL = uint32(N + 1) - L
    L = (L and (not uint32(mle))) or (newL and uint32(mle))

    for i in 0 .. p.sysT:
      B[i] = (B[i] and GF(not uint32(mle))) or (T[i] and GF(mle))

    b = (b and GF(not uint32(mle))) or (d and GF(mle))

    for i in countdown(p.sysT, 1):
      B[i] = B[i - 1]
    B[0] = 0

  for i in 0 .. p.sysT:
    outPoly[i] = C[p.sysT - i]
