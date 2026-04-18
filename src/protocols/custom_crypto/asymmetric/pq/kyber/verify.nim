## ----------------------------------------------------------
## Kyber Verify <- constant-time compare and conditional move
## ----------------------------------------------------------

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

proc cmovBytes*(R: var openArray[byte], X: openArray[byte], b: uint8) =
  ## Copy `X` into `R` when `b == 1`, leave `R` untouched when `b == 0`.
  var
    mask: uint8 = 0
    i: int = 0
  if R.len != X.len:
    raise newException(ValueError, "cmov input lengths must match")
  mask = uint8(0 - int(b and 1'u8))
  i = 0
  while i < R.len:
    R[i] = R[i] xor (mask and (R[i] xor X[i]))
    i = i + 1

proc cmovInt16*(r: var int16, v: int16, b: uint16) =
  ## Copy `v` into `r` when `b == 1`, leave `r` unchanged when `b == 0`.
  var
    mask: uint16 = 0
    ru: uint16 = 0
    vu: uint16 = 0
  mask = uint16(0 - int(b and 1'u16))
  ru = cast[uint16](r)
  vu = cast[uint16](v)
  r = cast[int16](ru xor (mask and (ru xor vu)))
