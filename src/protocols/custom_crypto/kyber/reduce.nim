## ---------------------------------------------------------
## Kyber Reduce <- Montgomery and Barrett reduction helpers
## ---------------------------------------------------------

import ./params

{.push boundChecks: off.}

const
  kyberMont* = -1044'i16 ## 2^16 mod q
  kyberQInv* = -3327'i16 ## q^-1 mod 2^16

proc montgomeryReduce*(a: int32): int16 {.inline.} =
  ## Compute the Montgomery reduction of `a`.
  var
    t: int16 = 0
    m: int32 = 0
  m = int32(cast[int16](a)) * int32(kyberQInv)
  t = cast[int16](m)
  result = int16((a - int32(t) * kyberQ) shr 16)

proc barrettReduce*(a: int16): int16 {.inline.} =
  ## Compute the centered Barrett reduction of `a`.
  const
    v = int16(((1 shl 26) + kyberQ div 2) div kyberQ)
  var
    t: int16 = 0
  t = int16((int32(v) * int32(a) + (1 shl 25)) shr 26)
  t = t * int16(kyberQ)
  result = a - t

{.pop.}
