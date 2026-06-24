## Niederreiter encryption helpers for the pure-Nim Classic McEliece backend.

import ./params
import ./util
import ../../../random

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

proc mcelieceEncapsRandomBlockBytes*(p: McElieceParams): int {.inline.} =
  ## Return the random-byte block size consumed by PQClean `gen_e`.
  p.sysT * 2 * sizeof(uint16)

proc indHasDuplicate(ind: openArray[uint16], n: int): bool {.inline.} =
  ## Check for duplicate indices (nested search extracted to keep caller flat).
  var
    i: int = 1
    j: int = 0
  while i < n:
    j = 0
    while j < i:
      if ind[i] == ind[j]:
        return true
      j = j + 1
    i = i + 1
  result = false

proc buildErrorVector(p: McElieceParams, ind: openArray[uint16], val: openArray[byte]): seq[byte] {.inline.} =
  ## Pack error vector bytes from indices and bit values (nested packing extracted).
  var
    i: int = 0
    j: int = 0
  result = newSeq[byte](p.sysN div 8)
  while i < result.len:
    result[i] = 0
    j = 0
    while j < p.sysT:
      result[i] = result[i] or (val[j] and sameMask(uint16(i), ind[j] shr 3))
      j = j + 1
    i = i + 1

proc errorVectorFromRandomBlock(p: McElieceParams,
    buf: openArray[byte]): tuple[ok: bool, errorVec: seq[byte]] =
  ## Try to derive a bit-packed weight-`sysT` error vector from one PQClean
  ## `gen_e` random block.
  var
    ind = newSeq[uint16](p.sysT)
    val = newSeq[byte](p.sysT)
    count: int = 0
    i: int = 0
    num: uint16 = 0
  defer:
    clearSensitiveWords(ind)
    clearSensitiveWords(val)
  if buf.len != mcelieceEncapsRandomBlockBytes(p):
    raise newException(ValueError, "invalid McEliece encaps random block length")
  count = 0
  i = 0
  while i < p.sysT * 2 and count < p.sysT:
    num = loadGF(buf.toOpenArray(i * 2, i * 2 + 1))
    if num < uint16(p.sysN):
      ind[count] = num
      count = count + 1
    i = i + 1
  if count < p.sysT:
    return
  if indHasDuplicate(ind, p.sysT):
    return
  for j in 0 ..< p.sysT:
    val[j] = 1'u8 shl (ind[j] and 7)
  result.ok = true
  result.errorVec = buildErrorVector(p, ind, val)

proc genErrorVectorDerand*(p: McElieceParams, randomness: openArray[byte]): seq[byte] =
  ## Generate an error vector from one or more PQClean `gen_e` random blocks.
  var
    blockBytes: int = mcelieceEncapsRandomBlockBytes(p)
    offset: int = 0
    candidate: tuple[ok: bool, errorVec: seq[byte]]
  if randomness.len == 0 or (randomness.len mod blockBytes) != 0:
    raise newException(ValueError, "McEliece encaps randomness must be one or more " &
      $blockBytes & "-byte blocks")
  while offset < randomness.len:
    candidate = errorVectorFromRandomBlock(p,
      randomness.toOpenArray(offset, offset + blockBytes - 1))
    if candidate.ok:
      return candidate.errorVec
    clearSensitiveWords(candidate.errorVec)
    offset = offset + blockBytes
  raise newException(ValueError, "McEliece encaps randomness did not produce a valid error vector")

proc genErrorVector*(p: McElieceParams): seq[byte] =
  ## Generate a bit-packed weight-`sysT` error vector for the selected McEliece tier.
  var
    buf: seq[byte] = @[]
    candidate: tuple[ok: bool, errorVec: seq[byte]]
  defer:
    clearSensitiveWords(buf)
  while true:
    clearSensitiveWords(buf)
    buf = cryptoRandomBytes(mcelieceEncapsRandomBlockBytes(p))
    candidate = errorVectorFromRandomBlock(p, buf)
    if candidate.ok:
      return candidate.errorVec

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

proc encryptErrorDerand*(p: McElieceParams, pk, randomness: openArray[byte]): tuple[syndrome, errorVec: seq[byte]] =
  ## Generate a deterministic error vector and its corresponding syndrome.
  result.errorVec = genErrorVectorDerand(p, randomness)
  result.syndrome = syndromeFromPublicKey(p, pk, result.errorVec)
