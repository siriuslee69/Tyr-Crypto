## Secret-key helper: generate the Goppa polynomial via Gaussian elimination.

import std/sequtils
import ./params
import ./gf
import ./util

proc genpolyGen*(p: McElieceParams; outPoly: var seq[GF]; f: openArray[GF]): bool =
  ## Derive the minimal polynomial of f (length sysT) into outPoly (length sysT).
  ## Returns true on success, false if the matrix is singular.
  assert f.len >= p.sysT
  outPoly.setLen(p.sysT)

  # mat has (sysT + 1) rows, each of length sysT
  var mat = newSeq[seq[GF]](p.sysT + 1)
  for i in 0 .. p.sysT:
    mat[i] = newSeqWith(p.sysT, GF(0))

  mat[0][0] = 1
  for i in 1 ..< p.sysT:
    mat[0][i] = 0
  for i in 0 ..< p.sysT:
    mat[1][i] = f[i]
  for j in 2 .. p.sysT:
    GFmul(p, mat[j], mat[j - 1], f)

  for j in 0 ..< p.sysT:
    for k in j + 1 ..< p.sysT:
      let mask = gfIsZero(mat[j][j])           # 0x1FFF when zero else 0
      for c in j .. p.sysT:
        mat[c][j] = mat[c][j] xor (mat[c][k] and mask)

    let pivotZero = ctMaskZero(mat[j][j])      # 0xFFFF when zero
    if pivotZero == 0xFFFF'u16:
      return false

    let inv = gfInv(mat[j][j])
    for c in j .. p.sysT:
      mat[c][j] = gfMul(mat[c][j], inv)

    for k in 0 ..< p.sysT:
      if k != j:
        let t = mat[j][k]
        for c in j .. p.sysT:
          mat[c][k] = mat[c][k] xor gfMul(mat[c][j], t)

  for i in 0 ..< p.sysT:
    outPoly[i] = mat[p.sysT][i]

  true
