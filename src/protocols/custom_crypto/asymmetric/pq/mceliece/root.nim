## Polynomial evaluation helpers for Classic McEliece.

import ./params
import ./util
import ./gf

proc evalPoly*(p: McElieceParams; f: openArray[GF]; a: GF): GF =
  ## Evaluate polynomial f at point a (f[0] is constant term).
  assert f.len >= p.sysT + 1
  var r = f[p.sysT]
  var i = p.sysT - 1
  while i >= 0:
    r = gfMul(r, a)
    r = gfAdd(r, f[i])
    if i == 0: break
    dec i
  r

proc rootEval*(p: McElieceParams; f: openArray[GF]; L: openArray[GF]; outVals: var seq[GF]) =
  ## Evaluate polynomial f at every support element in L.
  assert f.len >= p.sysT + 1
  assert L.len >= p.sysN
  outVals.setLen(p.sysN)
  for i in 0 ..< p.sysN:
    outVals[i] = evalPoly(p, f, L[i])
