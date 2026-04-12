## Public-key generation for the pure-Nim Classic McEliece backend.

import std/bitops

import ./params
import ./util
import ./gf
import ./root
import ./controlbits
import ./sort

proc ctMaskEqualU64(a, b: uint64): uint64 {.inline.} =
  var
    x = a xor b
  x = x - 1'u64
  x = x shr 63
  result = 0'u64 - x

proc load64Row(row: seq[byte], o: int): uint64 {.inline.} =
  result = load8(row.toOpenArray(o, o + 7))

proc store64Row(row: var seq[byte], o: int, v: uint64) {.inline.} =
  var
    tmp: array[8, byte]
  store8(tmp, v)
  for i in 0 ..< 8:
    row[o + i] = tmp[i]

proc movColumns(mat: var seq[seq[byte]], pi: var seq[uint16],
    pivots: var uint64, p: McElieceParams): bool =
  var
    buf: array[32, uint64]
    ctzList: array[32, int]
    t: uint64 = 0
    d: uint16 = 0
    mask: uint64 = 0
    row = p.pkNRows - 32
    blockIdx = row div 8
    j: int = 0
    k: int = 0
  for i in 0 ..< 32:
    buf[i] = load64Row(mat[row + i], blockIdx)

  pivots = 0'u64
  for i in 0 ..< 32:
    t = buf[i]
    j = i + 1
    while j < 32:
      t = t or buf[j]
      j = j + 1
    if t == 0'u64:
      return false
    ctzList[i] = countTrailingZeroBits(t)
    pivots = pivots or (1'u64 shl ctzList[i])

    j = i + 1
    while j < 32:
      mask = (buf[i] shr ctzList[i]) and 1'u64
      mask = mask - 1'u64
      buf[i] = buf[i] xor (buf[j] and mask)
      j = j + 1
    j = i + 1
    while j < 32:
      mask = (buf[j] shr ctzList[i]) and 1'u64
      mask = 0'u64 - mask
      buf[j] = buf[j] xor (buf[i] and mask)
      j = j + 1
  for j in 0 ..< 32:
    k = j + 1
    while k < 64:
      d = pi[row + j] xor pi[row + k]
      d = d and uint16(ctMaskEqualU64(uint64(k), uint64(ctzList[j])) and 0xffff'u64)
      pi[row + j] = pi[row + j] xor d
      pi[row + k] = pi[row + k] xor d
      k = k + 1
  for i in 0 ..< p.pkNRows:
    t = load64Row(mat[i], blockIdx)
    for j in 0 ..< 32:
      let delta = ((t shr j) xor (t shr ctzList[j])) and 1'u64
      t = t xor (delta shl ctzList[j])
      t = t xor (delta shl j)
    store64Row(mat[i], blockIdx, t)
  result = true

proc pkGen*(p: McElieceParams, g: openArray[GF], perm: openArray[uint32],
    pk: var seq[byte], controlBitsOut: var seq[byte], pivots: var uint64): bool =
  ## Generate a systematic public key plus Benes control bits from a Goppa polynomial and permutation.
  var
    buf = newSeq[uint64](1 shl p.gfBits)
    pi = newSeq[uint16](1 shl p.gfBits)
    L = newSeq[GF](p.sysN)
    inv = newSeq[GF](p.sysN)
    mat = newSeq[seq[byte]](p.pkNRows)
    row: int = 0
    c: int = 0
    j: int = 0
    k: int = 0
    b: byte = 0
    mask: byte = 0
  if g.len < p.sysT + 1:
    raise newException(ValueError, "goppa polynomial length mismatch")
  if perm.len < (1 shl p.gfBits):
    raise newException(ValueError, "permutation length mismatch")

  for i in 0 ..< buf.len:
    buf[i] = (uint64(perm[i]) shl 31) or uint64(i)
  uint64Sort(buf)
  for i in 1 ..< buf.len:
    if (buf[i - 1] shr 31) == (buf[i] shr 31):
      return false
  for i in 0 ..< pi.len:
    pi[i] = uint16(buf[i] and uint64(p.gfMask))
  for i in 0 ..< p.sysN:
    L[i] = bitrev(pi[i])

  rootEval(p, g, L, inv)
  for i in 0 ..< p.sysN:
    inv[i] = gfInv(inv[i])

  for i in 0 ..< p.pkNRows:
    mat[i] = newSeq[byte](p.sysN div 8)
  for i in 0 ..< p.sysT:
    j = 0
    while j < p.sysN:
      k = 0
      while k < p.gfBits:
        b = byte((inv[j + 7] shr k) and 1'u16)
        b = (b shl 1) or byte((inv[j + 6] shr k) and 1'u16)
        b = (b shl 1) or byte((inv[j + 5] shr k) and 1'u16)
        b = (b shl 1) or byte((inv[j + 4] shr k) and 1'u16)
        b = (b shl 1) or byte((inv[j + 3] shr k) and 1'u16)
        b = (b shl 1) or byte((inv[j + 2] shr k) and 1'u16)
        b = (b shl 1) or byte((inv[j + 1] shr k) and 1'u16)
        b = (b shl 1) or byte((inv[j + 0] shr k) and 1'u16)
        mat[i * p.gfBits + k][j div 8] = b
        k = k + 1
      j = j + 8
    for j in 0 ..< p.sysN:
      inv[j] = gfMul(inv[j], L[j])

  for i in 0 ..< (p.pkNRows + 7) div 8:
    for j in 0 ..< 8:
      row = i * 8 + j
      if row >= p.pkNRows:
        break
      if row == p.pkNRows - 32:
        if not movColumns(mat, pi, pivots, p):
          return false
      k = row + 1
      while k < p.pkNRows:
        mask = byte((((mat[row][i] xor mat[k][i]) shr j) and 1'u8))
        mask = 0'u8 - mask
        c = 0
        while c < p.sysN div 8:
          mat[row][c] = mat[row][c] xor (mat[k][c] and mask)
          c = c + 1
        k = k + 1
      if (((mat[row][i] shr j) and 1'u8) == 0'u8):
        return false
      k = 0
      while k < p.pkNRows:
        if k != row:
          mask = byte((mat[k][i] shr j) and 1'u8)
          mask = 0'u8 - mask
          c = 0
          while c < p.sysN div 8:
            mat[k][c] = mat[k][c] xor (mat[row][c] and mask)
            c = c + 1
        k = k + 1

  pk.setLen(p.pkNRows * p.pkRowBytes)
  for i in 0 ..< p.pkNRows:
    for j in 0 ..< p.pkRowBytes:
      pk[i * p.pkRowBytes + j] = mat[i][p.pkNRows div 8 + j]
  controlBitsOut = controlBitsFromPermutation(pi, p.gfBits)
  result = true
