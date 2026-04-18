## -------------------------------------------------------------
## Kyber Types <- shared polynomial and matrix objects for Kyber
## -------------------------------------------------------------

import ./params

type
  ## One Kyber polynomial in Z_q[X]/(X^256 + 1).
  Poly* = object
    coeffs*: array[kyberN, int16]

  ## One Kyber vector with room for the largest supported K.
  PolyVec* = object
    vec*: array[kyberMaxK, Poly]

  ## One Kyber matrix stored as rows of `PolyVec`.
  PolyMatrix* = array[kyberMaxK, PolyVec]
