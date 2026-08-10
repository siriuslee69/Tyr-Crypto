## -------------------------------------------------------
## Kyber CBD <- centered binomial samplers for Kyber noise
## -------------------------------------------------------

import ./params
import ./types
import ./util

{.push boundChecks: off.}

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; noise, error, and secret sampling rules for `cbd2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbd2(R: var Poly, buf: openArray[byte]) =
  var
    i: int = 0
    j: int = 0
    t: uint32 = 0
    d: uint32 = 0
    a: int16 = 0
    b: int16 = 0
  i = 0
  while i < kyberN div 8:
    t = load32Le(buf, 4 * i)
    d = t and 0x55555555'u32
    d = d + ((t shr 1) and 0x55555555'u32)
    j = 0
    while j < 8:
      a = int16((d shr (4 * j)) and 0x3'u32)
      b = int16((d shr (4 * j + 2)) and 0x3'u32)
      R.coeffs[8 * i + j] = a - b
      j = j + 1
    i = i + 1

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; noise, error, and secret sampling rules for `cbd3`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbd3(R: var Poly, buf: openArray[byte]) =
  var
    i: int = 0
    j: int = 0
    t: uint32 = 0
    d: uint32 = 0
    a: int16 = 0
    b: int16 = 0
  i = 0
  while i < kyberN div 4:
    t = load24Le(buf, 3 * i)
    d = t and 0x00249249'u32
    d = d + ((t shr 1) and 0x00249249'u32)
    d = d + ((t shr 2) and 0x00249249'u32)
    j = 0
    while j < 4:
      a = int16((d shr (6 * j)) and 0x7'u32)
      b = int16((d shr (6 * j + 3)) and 0x7'u32)
      R.coeffs[4 * i + j] = a - b
      j = j + 1
    i = i + 1

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; noise, error, and secret sampling rules for `polyCbdEta1Into`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyCbdEta1Into*(p: KyberParams, r: var Poly, buf: openArray[byte]) =
  ## Sample a polynomial from the eta1 centered binomial distribution into a caller-owned polynomial.
  case p.eta1
  of 2:
    cbd2(r, buf)
  of 3:
    cbd3(r, buf)
  else:
    raise newException(ValueError, "unsupported Kyber eta1")

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; noise, error, and secret sampling rules for `polyCbdEta1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyCbdEta1*(p: KyberParams, buf: openArray[byte]): Poly =
  ## Sample a polynomial from the eta1 centered binomial distribution.
  polyCbdEta1Into(p, result, buf)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; noise, error, and secret sampling rules for `polyCbdEta2Into`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyCbdEta2Into*(p: KyberParams, r: var Poly, buf: openArray[byte]) =
  ## Sample a polynomial from the eta2 centered binomial distribution into a caller-owned polynomial.
  case p.eta2
  of 2:
    cbd2(r, buf)
  else:
    raise newException(ValueError, "unsupported Kyber eta2")

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; noise, error, and secret sampling rules for `polyCbdEta2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyCbdEta2*(p: KyberParams, buf: openArray[byte]): Poly =
  ## Sample a polynomial from the eta2 centered binomial distribution.
  polyCbdEta2Into(p, result, buf)

{.pop.}
