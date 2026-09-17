## ---------------------------------------------------------------------
## | HQC Reed-Solomon <- the outer code that repairs whole bad bytes    |
## ---------------------------------------------------------------------
##
## Where this sits
## ---------------
## HQC repairs damage in two passes. The inner Reed-Muller pass turns a
## noisy block of bits back into one byte, guessing wrong now and then.
## This outer Reed-Solomon pass repairs those wrong bytes:
##
##   ciphertext bits -> [Reed-Muller] -> n1 bytes, a few of them wrong
##                   -> [Reed-Solomon] -> the original message bytes
##
## What the code does
## ------------------
## Encoding appends `2*delta` check bytes to the message, so that any
## `delta` wrong bytes can be located and repaired:
##
##   codeword = [ check bytes ][ message bytes ]
##                 2*delta          k
##              <--------- n1 bytes -------->
##
## The message sits at the END of the codeword, which is what "systematic"
## means: the original bytes are still readable in the codeword.
##
## Decoding in six steps
## --------------------
##   1. syndromes     2*delta numbers, all zero when nothing is damaged
##   2. sigma         a polynomial whose roots mark the damaged positions
##   3. roots         found with the additive FFT, all 256 at once
##   4. z             a second polynomial that says by HOW MUCH
##   5. values        the actual error value at each damaged position
##   6. repair        exclusive-or the values back out
##
## Steps 1 to 3 live in `rs_locate.nim` and steps 4 and 5 in
## `rs_repair.nim`; this file is the encoder and the six-step sequence.
##
## Reference: [HQC-20250822] Reed-Solomon encoding and decoding; ported
## from the reference implementation's `reed_solomon.c`, which follows
## Lin and Costello, "Error Control Coding", chapters 4 and 6.

import runePragmas
import ./params
import ./gf
import ./fft
import ./rs_locate
import ./rs_repair
import ./util

## Reference: [HQC-20250822] Reed-Solomon systematic encoding; shift-register encoding for `reedSolomonEncode`; pitfall: the message bytes land at the END of the codeword, not the start.
proc reedSolomonEncode*(cdw: var openArray[byte], msg: openArray[byte],
    p: HqcParams, G: openArray[uint16]) {.role: {encryptor}, raises: [].} =
  ## cdw/msg/p/G: the n1-byte codeword, the message bytes, the parameter
  ## set, and the generator polynomial.
  ##
  ## This is long division carried out one message byte at a time by a
  ## shift register, exactly as a hardware encoder would do it:
  ##
  ##   gate = next message byte + the byte falling off the register
  ##   every register cell moves up one and picks up gate * g[cell]
  var
    tmp = default(array[hqcMaxGenPolyLen, uint16])
    gate: byte = 0
    checkBytes: int = 0
    i: int = 0
    j: int = 0
    k: int = 0
  checkBytes = p.n1 - p.messageBytes
  i = 0
  while i < p.n1:
    cdw[i] = 0'u8
    i = i + 1
  i = 0
  while i < p.messageBytes:
    gate = msg[p.messageBytes - 1 - i] xor cdw[checkBytes - 1]
    j = 0
    while j < p.genPolyLen:
      tmp[j] = gfMul(uint16(gate), G[j])
      j = j + 1
    k = checkBytes - 1
    while k > 0:
      cdw[k] = cdw[k - 1] xor byte(tmp[k] and 0xff'u16)
      k = k - 1
    cdw[0] = byte(tmp[0] and 0xff'u16)
    i = i + 1
  i = 0
  while i < p.messageBytes:
    cdw[checkBytes + i] = msg[i]
    i = i + 1
  hqcWipeU16(tmp)

## Reference: [HQC-20250822] Reed-Solomon decoding; six-step decode for `reedSolomonDecode`; pitfall: a codeword with more than delta damaged bytes decodes to nonsense rather than failing, and the KEM wrapper is what turns that into a safe rejection.
proc reedSolomonDecode*(msg: var openArray[byte], cdw: openArray[byte],
    p: HqcParams) {.role: {decryptor}, raises: [].} =
  ## msg/cdw/p: the recovered message bytes, the received codeword, the
  ## parameter set.
  ## Repair up to `delta` wrong bytes and hand back the message.
  var
    work = default(array[hqcMaxN1, byte])
    S = default(array[2 * hqcMaxDelta, uint16])
    sigma = default(array[1 shl hqcMaxFftExp, uint16])
    E = default(array[fftFull, byte])
    z = default(array[hqcMaxN1, uint16])
    V = default(array[hqcMaxN1, uint16])
    deg: uint16 = 0
    i: int = 0
  i = 0
  while i < p.n1:
    work[i] = cdw[i]
    i = i + 1
  computeSyndromes(S, work, p)
  deg = computeElp(sigma, S, p)
  computeRoots(E, sigma, p)
  computeZPoly(z, sigma, deg, S, p)
  computeErrorValues(V, z, E, p)
  i = 0
  while i < p.n1:
    work[i] = work[i] xor byte(V[i] and 0xff'u16)
    i = i + 1
  i = 0
  while i < p.messageBytes:
    msg[i] = work[p.genPolyLen - 1 + i]
    i = i + 1
  hqcWipeBytes(work)
  hqcWipeU16(S)
  hqcWipeU16(sigma)
  hqcWipeBytes(E)
  hqcWipeU16(z)
  hqcWipeU16(V)
