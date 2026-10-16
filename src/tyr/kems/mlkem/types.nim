## -------------------------------------------------------------
## ML-KEM Types <- shared polynomial and matrix objects for ML-KEM
## -------------------------------------------------------------

import ./params

type
  ## One ML-KEM polynomial in Z_q[X]/(X^256 + 1).
  Poly* = object
    coeffs*: array[mlkemN, int16]

  ## One ML-KEM vector with room for the largest supported K.
  PolyVec* = object
    vec*: array[mlkemMaxK, Poly]

  ## One ML-KEM matrix stored as rows of `PolyVec`.
  PolyMatrix* = array[mlkemMaxK, PolyVec]
