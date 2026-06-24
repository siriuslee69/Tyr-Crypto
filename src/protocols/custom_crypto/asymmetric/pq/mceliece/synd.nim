## Syndrome computation for Classic McEliece.

import ./params
import ./util
import ./gf
import ./root

proc synd*(p: McElieceParams; f: openArray[GF]; L: openArray[GF]; r: openArray[byte]; outS: var seq[GF];
    bitLimit: int = -1) =
  ## Compute the 2*sysT syndrome for received word r (bit-packed) with Goppa poly f and support L.
  assert f.len >= p.sysT + 1
  assert L.len >= p.sysN
  ## Paper note: the optional public `bitLimit` lets callers skip ciphertext
  ## zero-padding bits while preserving the Classic McEliece syndrome formula.
  var
    limit: int = (if bitLimit < 0: p.sysN else: bitLimit)
    c: GF = 0
    mask: GF = 0
    e: GF = 0
    e2Inv: GF = 0
    accum: GF = 0
    i: int = 0
    j: int = 0
  assert limit <= p.sysN
  assert r.len * 8 >= limit
  outS.setLen(2 * p.sysT)
  j = 0
  while j < 2 * p.sysT:
    outS[j] = 0
    j = j + 1

  i = 0
  while i < limit:
    c = GF((r[i div 8] shr (i mod 8)) and 1)
    mask = GF(0) - c
    e = evalPoly(p, f, L[i])
    e2Inv = gfInv(gfMul(e, e))

    accum = e2Inv
    j = 0
    while j < 2 * p.sysT:
      outS[j] = gfAdd(outS[j], accum and mask)
      accum = gfMul(accum, L[i])
      j = j + 1
    i = i + 1
