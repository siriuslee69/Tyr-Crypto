## Syndrome computation for Classic McEliece.

import ./params
import ./util
import ./gf
import ./root

proc synd*(p: McElieceParams; f: openArray[GF]; L: openArray[GF]; r: openArray[byte]; outS: var seq[GF]) =
  ## Compute the 2*sysT syndrome for received word r (bit-packed) with Goppa poly f and support L.
  assert f.len >= p.sysT + 1
  assert L.len >= p.sysN
  outS.setLen(2 * p.sysT)
  for j in 0 ..< 2 * p.sysT:
    outS[j] = 0

  for i in 0 ..< p.sysN:
    let c = GF((r[i div 8] shr (i mod 8)) and 1)
    let e = evalPoly(p, f, L[i])
    let e2Inv = gfInv(gfMul(e, e))

    var accum = e2Inv
    for j in 0 ..< 2 * p.sysT:
      outS[j] = gfAdd(outS[j], gfMul(accum, c))
      accum = gfMul(accum, L[i])
