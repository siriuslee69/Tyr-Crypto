## Niederreiter encryption helpers for the pure-Nim Classic McEliece backend.

import ./params
import ./util
import ../random

proc sameMask(x, y: uint16): byte {.inline.} =
  var
    mask = uint32(x xor y)
  mask = mask - 1'u32
  mask = mask shr 31
  mask = 0'u32 - mask
  result = byte(mask and 0xff'u32)

proc foldParity64(x: uint64): byte {.inline.} =
  var t = x
  t = t xor (t shr 32)
  t = t xor (t shr 16)
  t = t xor (t shr 8)
  t = t xor (t shr 4)
  t = t xor (t shr 2)
  t = t xor (t shr 1)
  result = byte(t and 1'u64)

proc genErrorVector*(p: McElieceParams): seq[byte] =
  ## Generate a bit-packed weight-`sysT` error vector for the selected McEliece tier.
  var
    buf: seq[byte] = @[]
    ind = newSeq[uint16](p.sysT)
    val = newSeq[byte](p.sysT)
    count: int = 0
    eq: bool = false
    i: int = 0
    j: int = 0
  defer:
    clearSensitiveWords(buf)
    clearSensitiveWords(ind)
    clearSensitiveWords(val)
  while true:
    clearSensitiveWords(buf)
    buf = cryptoRandomBytes(p.sysT * 4)
    count = 0
    i = 0
    while i < p.sysT * 2 and count < p.sysT:
      let num = loadGF(buf.toOpenArray(i * 2, i * 2 + 1))
      if num < uint16(p.sysN):
        ind[count] = num
        count = count + 1
      i = i + 1
    if count < p.sysT:
      continue
    eq = false
    i = 1
    while i < p.sysT and not eq:
      j = 0
      while j < i:
        if ind[i] == ind[j]:
          eq = true
          break
        j = j + 1
      i = i + 1
    if not eq:
      break
  for j in 0 ..< p.sysT:
    val[j] = 1'u8 shl (ind[j] and 7)
  result = newSeq[byte](p.sysN div 8)
  for i in 0 ..< result.len:
    result[i] = 0
    for j in 0 ..< p.sysT:
      result[i] = result[i] or (val[j] and sameMask(uint16(i), ind[j] shr 3))

proc syndromeFromPublicKey*(p: McElieceParams, pk, e: openArray[byte]): seq[byte] =
  ## Compute the bit-packed syndrome for public key `pk` and error vector `e`.
  var
    pkPtr: int = 0
    i: int = 0
    j: int = 0
    b: byte = 0
    start = (p.sysN div 8) - p.pkRowBytes
    tail = p.pkNRows mod 8
    accum64: uint64 = 0
    rowByte: byte = 0
    prevPk: byte = 0
  if pk.len != p.pkNRows * p.pkRowBytes:
    raise newException(ValueError, "invalid McEliece public key length")
  if e.len != p.sysN div 8:
    raise newException(ValueError, "invalid McEliece error vector length")
  result = newSeq[byte](p.syndBytes)
  while i < p.pkNRows:
    b = (e[i div 8] shr (i mod 8)) and 1'u8
    if tail == 0:
      accum64 = 0
      j = 0
      while j + 8 <= p.pkRowBytes:
        accum64 = accum64 xor (
          load8(pk.toOpenArray(pkPtr + j, pkPtr + j + 7)) and
          load8(e.toOpenArray(start + j, start + j + 7))
        )
        j = j + 8
      b = b xor foldParity64(accum64)
      while j < p.pkRowBytes:
        b = b xor (pk[pkPtr + j] and e[start + j])
        j = j + 1
    else:
      prevPk = 0
      j = 0
      while j < p.pkRowBytes:
        rowByte = byte(((int(pk[pkPtr + j]) shl tail) or
          (int(prevPk) shr (8 - tail))) and 0xFF)
        b = b xor (rowByte and e[start + j])
        prevPk = pk[pkPtr + j]
        j = j + 1
    b = b xor (b shr 4)
    b = b xor (b shr 2)
    b = b xor (b shr 1)
    b = b and 1'u8
    result[i div 8] = result[i div 8] or (b shl (i mod 8))
    pkPtr = pkPtr + p.pkRowBytes
    i = i + 1

proc encryptError*(p: McElieceParams, pk: openArray[byte]): tuple[syndrome, errorVec: seq[byte]] =
  ## Generate a fresh error vector and its corresponding Niederreiter syndrome.
  result.errorVec = genErrorVector(p)
  result.syndrome = syndromeFromPublicKey(p, pk, result.errorVec)
