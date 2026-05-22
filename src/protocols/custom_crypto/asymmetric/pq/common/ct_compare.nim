## ----------------------------------------------------------------
## CT Compare <- shared constant-time byte and mask comparisons
## ----------------------------------------------------------------

proc verifyBytes*(A, B: openArray[byte]): int =
  ## Return 0 when `A == B`, else 1, using a branch-free byte walk.
  var
    r: uint8 = 0
    i: int = 0
  if A.len != B.len:
    return 1
  i = 0
  while i < A.len:
    r = r or (A[i] xor B[i])
    i = i + 1
  result = int((0'u64 - uint64(r)) shr 63)

proc bytesEqualCt*(A, B: openArray[byte]): bool =
  ## Constant-time equality test for equal-length byte strings.
  verifyBytes(A, B) == 0

proc uint16MaskAllOnesCt*(m: uint16): bool =
  ## Return true when `m == 0xFFFF`, else false, without early exit.
  var
    maskBytes: array[2, byte]
  maskBytes[0] = byte(m and 0xff'u16)
  maskBytes[1] = byte((m shr 8) and 0xff'u16)
  result = verifyBytes(maskBytes, [byte 0xff, 0xff]) == 0
