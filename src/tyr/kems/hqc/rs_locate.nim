## ---------------------------------------------------------------------
## | HQC RS Locate <- working out WHICH bytes of a codeword are wrong   |
## ---------------------------------------------------------------------
##
## Reed-Solomon decoding answers two questions, and they are answered by
## different machinery:
##
##   which bytes are wrong?     <- this file
##   by how much?               <- `rs_repair.nim`
##
## Three steps live here:
##
##   1. syndromes   2*delta numbers, all zero when nothing is damaged
##   2. sigma       a polynomial whose roots mark the damaged positions
##   3. roots       found with the additive FFT, all 256 at once
##
## Reference: [HQC-20250822] Reed-Solomon decoding; ported from the
## reference implementation's `reed_solomon.c`, following Lin and
## Costello, "Error Control Coding", chapter 6.

import runePragmas
import ./params
import ./gf
import ./fft
import ./masks
import ./util

## Reference: [HQC-20250822] Reed-Solomon syndrome computation; evaluation at the code roots for `computeSyndromes`; pitfall: alpha^((i+1)*j) replaces the reference implementation's precomputed table, and the two were checked equal for all three parameter sets.
proc computeSyndromes*(S: var openArray[uint16], cdw: openArray[byte],
    p: HqcParams) {.role: {parser}, raises: [].} =
  ## S/cdw/p: 2*delta syndromes, the received codeword, the parameter set.
  ##
  ## Syndrome i is the codeword read as a polynomial and evaluated at
  ## alpha^(i+1):
  ##
  ##   S[i] = cdw[0] + cdw[1]*alpha^(i+1) + cdw[2]*alpha^(2(i+1)) + ...
  ##
  ## A clean codeword is divisible by the generator, so every syndrome
  ## comes out zero. Anything else means damage.
  ##
  ## The reference implementation reads alpha^((i+1)*j) out of a stored
  ## table. Here it is read straight from the power table instead: the
  ## index depends only on the loop counters, never on the data, so this
  ## stays as constant-time as the table lookup it replaces.
  var
    i: int = 0
    j: int = 0
  i = 0
  while i < 2 * p.delta:
    S[i] = 0
    j = 1
    while j < p.n1:
      S[i] = S[i] xor gfMul(uint16(cdw[j]), gfExp[((i + 1) * j) mod hqcGfMulOrder])
      j = j + 1
    S[i] = S[i] xor uint16(cdw[0])
    i = i + 1

## Reference: [HQC-20250822] Reed-Solomon error locator; Berlekamp's algorithm for `computeElp`; pitfall: every update is masked rather than branched, so the running time says nothing about how much damage there was.
proc computeElp*(sigma: var openArray[uint16], S: openArray[uint16],
    p: HqcParams): uint16 {.role: {math}, raises: [].} =
  ## sigma/S/p: the error locator polynomial, the syndromes, the parameters.
  ## Return the degree of sigma, which is how many bytes are damaged.
  ##
  ## Berlekamp's algorithm builds sigma one syndrome at a time. At each
  ## step it measures the "discrepancy" - how far the current guess is
  ## from explaining the next syndrome - and corrects by that much. The
  ## previous best guess is kept in `xSigmaP` in case the correction
  ## makes the degree grow.
  var
    degSigma: uint16 = 0
    degSigmaP: uint16 = 0
    degSigmaCopy: uint16 = 0
    sigmaCopy = default(array[hqcMaxDelta + 1, uint16])
    xSigmaP = default(array[hqcMaxDelta + 1, uint16])
    pp: uint16 = 0xffff'u16      ## 2*rho, starting at "minus one"
    dP: uint16 = 1               ## the discrepancy at that earlier step
    d: uint16 = 0                ## the discrepancy now
    dd: uint16 = 0
    mask1: uint16 = 0
    mask2: uint16 = 0
    mask12: uint16 = 0
    degX: uint16 = 0
    degXSigmaP: uint16 = 0
    mu: int = 0
    i: int = 0
  xSigmaP[1] = 1
  d = S[0]
  sigma[0] = 1
  mu = 0
  while mu < 2 * p.delta:
    ## Keep a copy in case this step turns out to be the new best guess.
    i = 0
    while i < p.delta:
      sigmaCopy[i] = sigma[i]
      i = i + 1
    degSigmaCopy = degSigma
    dd = gfMul(d, gfInverse(dP))
    i = 1
    while i <= mu + 1 and i <= p.delta:
      sigma[i] = sigma[i] xor gfMul(dd, xSigmaP[i])
      i = i + 1
    degX = uint16(mu) - pp
    degXSigmaP = degX + degSigmaP
    ## mask12 is all ones exactly when this step made the degree grow.
    mask1 = maskNonZero16(d)
    mask2 = maskLess16(uint32(degSigma), uint32(degXSigmaP))
    mask12 = mask1 and mask2
    degSigma = degSigma xor (mask12 and (degXSigmaP xor degSigma))
    if mu == 2 * p.delta - 1:
      break
    pp = pp xor (mask12 and (uint16(mu) xor pp))
    dP = dP xor (mask12 and (d xor dP))
    i = p.delta
    while i > 0:
      xSigmaP[i] = (mask12 and sigmaCopy[i - 1]) xor
        ((not mask12) and xSigmaP[i - 1])
      i = i - 1
    degSigmaP = degSigmaP xor (mask12 and (degSigmaCopy xor degSigmaP))
    ## The next discrepancy: syndrome mu+1 minus what sigma predicts.
    d = S[mu + 1]
    i = 1
    while i <= mu + 1 and i <= p.delta:
      d = d xor gfMul(sigma[i], S[mu + 1 - i])
      i = i + 1
    mu = mu + 1
  hqcWipeU16(sigmaCopy)
  hqcWipeU16(xSigmaP)
  result = degSigma

## Reference: [HQC-20250822] Reed-Solomon root finding; FFT-based root search for `computeRoots`; pitfall: the FFT modifies its input, so sigma must be handed over on a scratch copy.
proc computeRoots*(E: var openArray[byte], sigma: openArray[uint16],
    p: HqcParams) {.role: {math}, raises: [].} =
  ## E/sigma/p: 256 damage flags, the error locator, the parameter set.
  ## Mark every codeword position whose locator value is a root of sigma.
  var
    w = default(array[fftFull, uint16])
  fftEvaluate(w, sigma, p.delta + 1, p)
  fftRetrieveErrorPoly(E, w)
  hqcWipeU16(w)
