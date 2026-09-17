## ---------------------------------------------------------------------
## | HQC RS Repair <- working out BY HOW MUCH each wrong byte is wrong  |
## ---------------------------------------------------------------------
##
## `rs_locate.nim` has already said which positions are damaged. Two
## steps remain, and they live here:
##
##   4. z            a second polynomial that says by how much
##   5. values       the actual error value at each damaged position
##
## Both walk every position of the codeword every time, never stopping
## early, so their timing says nothing about how much damage there was.
##
## Reference: [HQC-20250822] Reed-Solomon decoding; ported from the
## reference implementation's `reed_solomon.c`, following Lin and
## Costello, "Error Control Coding", chapter 6.

import runePragmas
import ./params
import ./gf
import ./masks
import ./util

## Reference: [HQC-20250822] Reed-Solomon error evaluator; evaluator construction for `computeZPoly`; pitfall: coefficients past the real degree of sigma must be masked to zero, not skipped.
proc computeZPoly*(z: var openArray[uint16], sigma: openArray[uint16],
    degree: uint16, S: openArray[uint16], p: HqcParams)
    {.role: {math}, raises: [].} =
  ## z/sigma/degree/S/p: the evaluator, the locator, its degree, the
  ## syndromes, the parameter set.
  ## Build z(x) = sigma(x) * S(x) truncated to degree `delta`. Where sigma
  ## says WHICH byte is wrong, z is what says by how much.
  var
    mask: uint16 = 0
    i: int = 0
    j: int = 0
  z[0] = 1
  i = 1
  while i < p.delta + 1:
    mask = maskLess16(uint32(i), uint32(degree) + 1'u32)
    z[i] = mask and sigma[i]
    i = i + 1
  z[1] = z[1] xor S[0]
  i = 2
  while i <= p.delta:
    mask = maskLess16(uint32(i), uint32(degree) + 1'u32)
    z[i] = z[i] xor (mask and S[i - 1])
    j = 1
    while j < i:
      z[i] = z[i] xor (mask and gfMul(sigma[j], S[i - j - 1]))
      j = j + 1
    i = i + 1

## Reference: [HQC-20250822] Reed-Solomon error values; Forney's formula for `computeErrorValues`; pitfall: the scan that collects the damaged positions must visit every position so its timing reveals nothing.
proc computeErrorValues*(V: var openArray[uint16], z: openArray[uint16],
    E: openArray[byte], p: HqcParams) {.role: {math}, raises: [].} =
  ## V/z/E/p: one value per codeword position, the evaluator, the damage
  ## flags, the parameter set.
  ##
  ## Two passes over every position, never stopping early:
  ##   pass 1 collects the locator value of each damaged position
  ##   pass 2 writes each computed value back at its position
  ## In between, Forney's formula turns the evaluator into the actual
  ## wrong-by-how-much value at each damaged position.
  var
    betaJ = default(array[hqcMaxDelta, uint16])
    eJ = default(array[hqcMaxDelta, uint16])
    deltaCounter: uint32 = 0
    deltaRealValue: uint32 = 0
    found: uint16 = 0
    mask1: uint16 = 0
    mask2: uint16 = 0
    t1: uint16 = 0
    t2: uint16 = 0
    inverse: uint16 = 0
    inversePowerJ: uint16 = 0
    i: int = 0
    j: int = 0
    k: int = 0
  ## Pass 1: which positions are damaged, in order.
  deltaCounter = 0
  i = 0
  while i < p.n1:
    found = 0
    mask1 = maskNonZero16(uint16(E[i]))
    j = 0
    while j < p.delta:
      mask2 = maskEqual16(uint32(j), deltaCounter)
      betaJ[j] = betaJ[j] + (mask1 and mask2 and gfExp[i])
      found = found + (mask1 and mask2 and 1'u16)
      j = j + 1
    deltaCounter = deltaCounter + uint32(found)
    i = i + 1
  deltaRealValue = deltaCounter
  ## Forney's formula at each collected position.
  i = 0
  while i < p.delta:
    t1 = 1
    t2 = 1
    inverse = gfInverse(betaJ[i])
    inversePowerJ = 1
    j = 1
    while j <= p.delta:
      inversePowerJ = gfMul(inversePowerJ, inverse)
      t1 = t1 xor gfMul(inversePowerJ, z[j])
      j = j + 1
    k = 1
    while k < p.delta:
      t2 = gfMul(t2, 1'u16 xor gfMul(inverse, betaJ[(i + k) mod p.delta]))
      k = k + 1
    mask1 = maskLess16(uint32(i), deltaRealValue)
    eJ[i] = mask1 and gfMul(t1, gfInverse(t2))
    i = i + 1
  ## Pass 2: put each value back where it belongs.
  deltaCounter = 0
  i = 0
  while i < p.n1:
    found = 0
    mask1 = maskNonZero16(uint16(E[i]))
    j = 0
    while j < p.delta:
      mask2 = maskEqual16(uint32(j), deltaCounter)
      V[i] = V[i] + (mask1 and mask2 and eJ[j])
      found = found + (mask1 and mask2 and 1'u16)
      j = j + 1
    deltaCounter = deltaCounter + uint32(found)
    i = i + 1
  hqcWipeU16(betaJ)
  hqcWipeU16(eJ)
