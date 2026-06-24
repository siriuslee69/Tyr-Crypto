## Secret-key helper: generate the Goppa polynomial via Gaussian elimination.

import ./params
import ./gf
import ./util

proc genpolyGen*(p: McElieceParams; outPoly: var seq[GF]; f: openArray[GF]): bool =
  ## Derive the minimal polynomial of f (length sysT) into outPoly (length sysT).
  ## Returns true on success, false if the matrix is singular.
  var
    cols: int = p.sysT
    i: int = 0
    j: int = 0
    k: int = 0
    c: int = 0
    mask: GF = 0
    inv: GF = 0
    t: GF = 0
  assert f.len >= cols
  outPoly.setLen(cols)

  var mat = newSeq[GF]((cols + 1) * cols)
  defer:
    clearSensitiveWords(mat)

  template cell(row, col: int): untyped =
    mat[(row * cols) + col]

  cell(0, 0) = 1
  i = 0
  while i < cols:
    cell(1, i) = f[i]
    i = i + 1
  j = 2
  while j <= cols:
    GFmul(p,
      mat.toOpenArray(j * cols, j * cols + cols - 1),
      mat.toOpenArray((j - 1) * cols, (j - 1) * cols + cols - 1),
      f)
    j = j + 1

  j = 0
  while j < cols:
    k = j + 1
    while k < cols:
      mask = gfIsZero(cell(j, j))
      c = j
      while c <= cols:
        cell(c, j) = cell(c, j) xor (cell(c, k) and mask)
        c = c + 1
      k = k + 1

    if ctMaskZero(cell(j, j)) == 0xFFFF'u16:
      return false

    inv = gfInv(cell(j, j))
    c = j
    while c <= cols:
      cell(c, j) = gfMul(cell(c, j), inv)
      c = c + 1

    k = 0
    while k < cols:
      if k != j:
        t = cell(j, k)
        c = j
        while c <= cols:
          cell(c, k) = cell(c, k) xor gfMul(cell(c, j), t)
          c = c + 1
      k = k + 1
    j = j + 1

  i = 0
  while i < cols:
    outPoly[i] = cell(cols, i)
    i = i + 1

  true
