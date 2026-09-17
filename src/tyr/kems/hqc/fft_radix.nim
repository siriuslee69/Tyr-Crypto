## ---------------------------------------------------------------------
## | HQC FFT Radix <- splitting a polynomial so it can be halved         |
## ---------------------------------------------------------------------
##
## The additive FFT works by cutting one polynomial into two shorter
## ones, over and over. This file does the cutting; `fft.nim` does the
## descending. They are separate because the cut is a fixed algebraic
## identity with nothing recursive about it, while the descent is all
## recursion and bookkeeping.
##
## The identity
## ------------
## Every polynomial can be written as
##
##   f(x)  =  f0(x^2 + x)  +  x * f1(x^2 + x)
##
## and `f0` and `f1` each have half as many coefficients as `f`. Doing
## that repeatedly is what turns 256 separate evaluations into something
## proportional to 256 * log(256).
##
## The evaluation points
## ---------------------
## The points are built by ADDING field elements rather than multiplying
## them, which is where "additive" comes from. Take seven basis elements
## and combine every subset of them with exclusive-or:
##
##   betas       = 128, 64, 32, 16, 8, 4, 2      <- a basis, 1 left out
##   subset sums = every exclusive-or of a subset of them
##               = every field element, each exactly once
##
## Leaving the element 1 out of the basis is deliberate: it is what lets
## the two halves of each split be told apart afterwards.
##
## Reference: [HQC-20250822] additive FFT for root finding; ported from
## the reference implementation's `fft.c`, following Gao and Mateer,
## "Additive Fast Fourier Transforms over Finite Fields" (IEEE TIT 56,
## 2010) with the refinements of Bernstein, Chou and Schwabe,
## https://binary.cr.yp.to/mcbits-20130616.pdf.

import runePragmas
import ./params

const
  fftFull* = 1 shl hqcGfM            ## 256, one slot per field element
  fftHalf* = 1 shl (hqcGfM - 1)      ## 128
  fftQuarter* = 1 shl (hqcGfM - 2)   ## 64
  fftSmall* = 1 shl (hqcMaxFftExp - 2)      ## 8, the widest radix half
  fftMedium* = 1 shl (hqcMaxFftExp - 1)     ## 16, the widest top-level half

type
  ## Scratch for one radix split. Sized for the largest parameter set so
  ## no recursion level ever allocates.
  FftHalfBuf* = array[fftSmall, uint16]

proc radix*(f0, f1: var openArray[uint16], f: openArray[uint16], mF: int)
  {.role: {math}, raises: [].}

## Reference: [HQC-20250822] additive FFT basis; basis construction for `computeFftBetas`; pitfall: the element 1 is deliberately left out of the basis.
proc computeFftBetas*(betas: var openArray[uint16]) {.role: {math}, raises: [].} =
  ## betas: receives hqcGfM - 1 basis elements.
  ## The basis 2^7, 2^6, ... 2^1.
  var
    i: int = 0
  while i < hqcGfM - 1:
    betas[i] = 1'u16 shl (hqcGfM - 1 - i)
    i = i + 1

## Reference: [HQC-20250822] additive FFT evaluation points; subset-sum enumeration for `computeSubsetSums`; pitfall: entry i must be the sum selected by the binary digits of i.
proc computeSubsetSums*(S: var openArray[uint16], A: openArray[uint16],
    setSize: int) {.role: {math}, raises: [].} =
  ## S/A/setSize: destination of 2^setSize sums, the set, and its size.
  ## Every exclusive-or of a subset of `A`, indexed by which members the
  ## binary digits of the index pick out:
  ##
  ##   S[0b000] = 0            S[0b001] = A[0]
  ##   S[0b010] = A[1]         S[0b011] = A[1] xor A[0]
  var
    i: int = 0
    j: int = 0
  S[0] = 0
  i = 0
  while i < setSize:
    j = 0
    while j < (1 shl i):
      S[(1 shl i) + j] = A[i] xor S[j]
      j = j + 1
    i = i + 1

## Reference: [HQC-20250822] additive FFT radix conversion; generic split for `radixBig`; pitfall: the copies are sized in ELEMENTS here where the reference counts bytes.
proc radixBig(f0, f1: var openArray[uint16], f: openArray[uint16],
    mF: int) {.role: {math}, raises: [].} =
  ## f0/f1/f/mF: the two halves, the input of 2^mF coefficients, and mF.
  ## The split for sizes the hand-written cases below do not cover. It
  ## folds the input into two shorter polynomials and splits each of
  ## those with the hand-written code.
  var
    Q = default(array[2 * fftSmall + 1, uint16])
    R = default(array[2 * fftSmall + 1, uint16])
    Q0 = default(FftHalfBuf)
    Q1 = default(FftHalfBuf)
    R0 = default(FftHalfBuf)
    R1 = default(FftHalfBuf)
    n: int = 0
    i: int = 0
  n = 1 shl (mF - 2)
  i = 0
  while i < n:
    Q[i] = f[3 * n + i]
    Q[n + i] = f[3 * n + i]
    i = i + 1
  i = 0
  while i < 2 * n:
    R[i] = f[i]
    i = i + 1
  i = 0
  while i < n:
    Q[i] = Q[i] xor f[2 * n + i]
    R[n + i] = R[n + i] xor Q[i]
    i = i + 1
  radix(Q0, Q1, Q, mF - 1)
  radix(R0, R1, R, mF - 1)
  i = 0
  while i < n:
    f0[i] = R0[i]
    f0[n + i] = Q0[i]
    f1[i] = R1[i]
    f1[n + i] = Q1[i]
    i = i + 1

## Reference: [HQC-20250822] additive FFT radix conversion; split for `radix`; pitfall: these unrolled cases are exact identities, so a single changed index silently corrupts the decode.
proc radix*(f0, f1: var openArray[uint16], f: openArray[uint16], mF: int)
    {.role: {math}, raises: [].} =
  ## f0/f1/f/mF: the two halves, the input of 2^mF coefficients, and mF.
  ## Rewrite f(x) as f0(x^2 + x) + x * f1(x^2 + x). The small sizes are
  ## written out because the general routine would only rediscover them.
  case mF
  of 4:
    f0[4] = f[8] xor f[12]
    f0[6] = f[12] xor f[14]
    f0[7] = f[14] xor f[15]
    f1[5] = f[11] xor f[13]
    f1[6] = f[13] xor f[14]
    f1[7] = f[15]
    f0[5] = f[10] xor f[12] xor f1[5]
    f1[4] = f[9] xor f[13] xor f0[5]
    f0[0] = f[0]
    f1[3] = f[7] xor f[11] xor f[15]
    f0[3] = f[6] xor f[10] xor f[14] xor f1[3]
    f0[2] = f[4] xor f0[4] xor f0[3] xor f1[3]
    f1[1] = f[3] xor f[5] xor f[9] xor f[13] xor f1[3]
    f1[2] = f[3] xor f1[1] xor f0[3]
    f0[1] = f[2] xor f0[2] xor f1[1]
    f1[0] = f[1] xor f0[1]
  of 3:
    f0[0] = f[0]
    f0[2] = f[4] xor f[6]
    f0[3] = f[6] xor f[7]
    f1[1] = f[3] xor f[5] xor f[7]
    f1[2] = f[5] xor f[6]
    f1[3] = f[7]
    f0[1] = f[2] xor f0[2] xor f1[1]
    f1[0] = f[1] xor f0[1]
  of 2:
    f0[0] = f[0]
    f0[1] = f[2] xor f[3]
    f1[0] = f[1] xor f0[1]
    f1[1] = f[3]
  of 1:
    f0[0] = f[0]
    f1[0] = f[1]
  else:
    radixBig(f0, f1, f, mF)
