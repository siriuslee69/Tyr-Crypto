## ---------------------------------------------------------------------
## | HQC FFT <- evaluating one polynomial at every byte value at once   |
## ---------------------------------------------------------------------
##
## The job
## -------
## Reed-Solomon decoding ends with a polynomial called sigma whose roots
## mark the damaged positions. Finding them means asking, for all 256
## field elements e, "is sigma(e) zero?". Done one at a time that is 256
## separate evaluations. The additive FFT answers all 256 at once, by
## splitting the polynomial in half over and over:
##
##   sigma(x) = f0(x^2 + x)  +  x * f1(x^2 + x)
##                 \                    \
##                  evaluated on half as many points, twice
##
## Each split halves the work, so the total drops from 256*deg to
## something proportional to 256*log(256).
##
## The splitting itself lives next door in `fft_radix.nim`. This file is
## the descent: how far down to go, what basis each level works in, and
## how the two halves are put back together on the way up.
##
## Reference: [HQC-20250822] additive FFT for root finding; ported from
## the reference implementation's `fft.c`.

import runePragmas
import ./params
import ./gf
import ./fft_radix

export fftFull, fftHalf, fftQuarter

## Reference: [HQC-20250822] additive FFT recursion; evaluation step for `fftRec`; pitfall: `f` is twisted in place, so a caller must not reuse it afterwards.
proc fftRec(w: var openArray[uint16], f: var openArray[uint16], fCoeffs: int,
    m: int, mF: int, betas: openArray[uint16]) {.role: {math}, raises: [].} =
  ## w/f/fCoeffs/m/mF/betas: results, the polynomial (modified), how many
  ## coefficients it really has, how many basis elements are left, the
  ## log of its length, and the basis.
  ## Evaluate `f` at every subset sum of `betas`.
  var
    f0 = default(FftHalfBuf)
    f1 = default(FftHalfBuf)
    gammas = default(array[hqcGfM - 2, uint16])
    deltas = default(array[hqcGfM - 2, uint16])
    gammasSums = default(array[fftQuarter, uint16])
    u = default(array[fftQuarter, uint16])
    v = default(array[fftQuarter, uint16])
    tmp = default(array[hqcGfM, uint16])
    betaPow: uint16 = 0
    i: int = 0
    j: int = 0
    k: int = 0
    x: int = 0
  ## Step 1: a straight line. f(b) = f[0] + b*f[1], and every evaluation
  ## point is one of the subset sums, built here by doubling.
  if mF == 1:
    i = 0
    while i < m:
      tmp[i] = gfMul(betas[i], f[1])
      i = i + 1
    w[0] = f[0]
    x = 1
    j = 0
    while j < m:
      k = 0
      while k < x:
        w[x + k] = w[k] xor tmp[j]
        k = k + 1
      x = x shl 1
      j = j + 1
    return
  ## Step 2: scale the variable so the last basis element becomes 1.
  if betas[m - 1] != 1'u16:
    betaPow = 1
    x = 1 shl mF
    i = 1
    while i < x:
      betaPow = gfMul(betaPow, betas[m - 1])
      f[i] = gfMul(betaPow, f[i])
      i = i + 1
  ## Step 3: split into the two shorter polynomials.
  radix(f0, f1, f, mF)
  ## Step 4: the basis for the next level down.
  i = 0
  while i + 1 < m:
    gammas[i] = gfMul(betas[i], gfInverse(betas[m - 1]))
    deltas[i] = gfSquare(gammas[i]) xor gammas[i]
    i = i + 1
  computeSubsetSums(gammasSums, gammas, m - 1)
  ## Step 5: evaluate the first half.
  fftRec(u, f0, (fCoeffs + 1) div 2, m - 1, mF - 1, deltas)
  k = 1 shl ((m - 1) and 0x0f)
  if fCoeffs <= 3:
    ## f1 is a single constant, so its evaluations need no recursion.
    w[0] = u[0]
    w[k] = u[0] xor f1[0]
    i = 1
    while i < k:
      w[i] = u[i] xor gfMul(gammasSums[i], f1[0])
      w[k + i] = w[i] xor f1[0]
      i = i + 1
  else:
    fftRec(v, f1, fCoeffs div 2, m - 1, mF - 1, deltas)
    ## Step 6: recombine. The two halves differ by one basis element.
    i = 0
    while i < k:
      w[k + i] = v[i]
      i = i + 1
    w[0] = u[0]
    w[k] = w[k] xor u[0]
    i = 1
    while i < k:
      w[i] = u[i] xor gfMul(gammasSums[i], v[i])
      w[k + i] = w[k + i] xor w[i]
      i = i + 1

## Reference: [HQC-20250822] additive FFT entry point; full evaluation for `fftEvaluate`; pitfall: on the first level the basis IS betas, so no scaling step is needed.
proc fftEvaluate*(w: var openArray[uint16], f: openArray[uint16],
    fCoeffs: int, p: HqcParams) {.role: {math}, raises: [].} =
  ## w/f/fCoeffs/p: 256 results, the polynomial of 2^fftExp coefficients,
  ## how many of them are really used, and the parameter set.
  ## Evaluate `f` at every one of the 256 field elements.
  var
    betas = default(array[hqcGfM - 1, uint16])
    betasSums = default(array[fftHalf, uint16])
    deltas = default(array[hqcGfM - 1, uint16])
    f0 = default(array[fftMedium, uint16])
    f1 = default(array[fftMedium, uint16])
    u = default(array[fftHalf, uint16])
    v = default(array[fftHalf, uint16])
    i: int = 0
    k: int = 0
  computeFftBetas(betas)
  computeSubsetSums(betasSums, betas, hqcGfM - 1)
  radix(f0, f1, f, p.fftExp)
  i = 0
  while i < hqcGfM - 1:
    deltas[i] = gfSquare(betas[i]) xor betas[i]
    i = i + 1
  fftRec(u, f0, (fCoeffs + 1) div 2, hqcGfM - 1, p.fftExp - 1, deltas)
  fftRec(v, f1, fCoeffs div 2, hqcGfM - 1, p.fftExp - 1, deltas)
  k = fftHalf
  i = 0
  while i < k:
    w[k + i] = v[i]
    i = i + 1
  ## w[0] is f evaluated at 0, and w[k] at 1 - the basis element that was
  ## deliberately left out.
  w[0] = u[0]
  w[k] = w[k] xor u[0]
  i = 1
  while i < k:
    w[i] = u[i] xor gfMul(betasSums[i], v[i])
    w[k + i] = w[k + i] xor w[i]
    i = i + 1

## Reference: [HQC-20250822] additive FFT root extraction; error-position marking for `fftRetrieveErrorPoly`; pitfall: an evaluation of zero marks a root, and the position is the NEGATED logarithm of that field element.
proc fftRetrieveErrorPoly*(E: var openArray[byte], w: openArray[uint16])
    {.role: {parser}, raises: [].} =
  ## E/w: 256 flags to mark, and the 256 evaluations.
  ## Turn "sigma is zero here" into "position i of the codeword is damaged".
  ##
  ## sigma was built so that its roots are the INVERSES of the damaged
  ## positions, which is why the index is 255 minus the logarithm.
  var
    gammas = default(array[hqcGfM - 1, uint16])
    gammasSums = default(array[fftHalf, uint16])
    k: int = 0
    i: int = 0
    index: int = 0
  computeFftBetas(gammas)
  computeSubsetSums(gammasSums, gammas, hqcGfM - 1)
  k = fftHalf
  E[0] = E[0] xor byte(1'u16 xor ((0'u16 - w[0]) shr 15))
  E[0] = E[0] xor byte(1'u16 xor ((0'u16 - w[k]) shr 15))
  i = 1
  while i < k:
    index = hqcGfMulOrder - int(gfLog[int(gammasSums[i])])
    E[index] = E[index] xor byte(1'u16 xor ((0'u16 - w[i]) shr 15))
    index = hqcGfMulOrder - int(gfLog[int(gammasSums[i] xor 1'u16)])
    E[index] = E[index] xor byte(1'u16 xor ((0'u16 - w[k + i]) shr 15))
    i = i + 1
