## ----------------------------------------------------------
## Kyber Verify <- constant-time compare and conditional move
## ----------------------------------------------------------

import ../common/ct_compare

export ct_compare

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; constant-time comparison and conditional-selection requirements for `cmovBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; constant-time comparison and conditional-selection requirements for `cmovInt16`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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
