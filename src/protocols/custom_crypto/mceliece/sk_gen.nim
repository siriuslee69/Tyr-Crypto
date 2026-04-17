## Secret-key helper: generate the Goppa polynomial via Gaussian elimination.

import ./params
import ./gf
import ./util

proc genpolyGen*(p: McElieceParams; outPoly: var seq[GF]; f: openArray[GF]): bool =
  ## Derive the minimal polynomial of f (length sysT) into outPoly (length sysT).
  ## Returns true on success, false if the matrix is singular.
  let cols = p.sysT
  assert f.len >= cols
  outPoly.setLen(cols)

  var mat = newSeq[GF]((cols + 1) * cols)
  defer:
    clearSensitiveWords(mat)

  template cell(row, col: int): untyped =
    mat[(row * cols) + col]

  cell(0, 0) = 1
  for i in 0 ..< cols:
    cell(1, i) = f[i]
  for j in 2 .. cols:
    GFmul(p,
      mat.toOpenArray(j * cols, j * cols + cols - 1),
      mat.toOpenArray((j - 1) * cols, (j - 1) * cols + cols - 1),
      f)

  for j in 0 ..< cols:
    for k in j + 1 ..< cols:
      let mask = gfIsZero(cell(j, j))
      for c in j .. cols:
        cell(c, j) = cell(c, j) xor (cell(c, k) and mask)

    if ctMaskZero(cell(j, j)) == 0xFFFF'u16:
      return false

    let inv = gfInv(cell(j, j))
    for c in j .. cols:
      cell(c, j) = gfMul(cell(c, j), inv)

    for k in 0 ..< cols:
      if k != j:
        let t = cell(j, k)
        for c in j .. cols:
          cell(c, k) = cell(c, k) xor gfMul(cell(c, j), t)

  for i in 0 ..< cols:
    outPoly[i] = cell(cols, i)

  true
