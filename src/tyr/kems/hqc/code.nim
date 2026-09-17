## ---------------------------------------------------------------------
## | HQC Code <- the two error-correcting codes, stacked                |
## ---------------------------------------------------------------------
##
## Neither code alone is enough. Reed-Muller survives a very noisy
## channel but only carries one byte per block, and it guesses wrong
## often enough to matter. Reed-Solomon almost never guesses wrong but
## cannot cope with bit-level noise. Stacking them fixes both:
##
##   message (k bytes)
##     |
##     |  Reed-Solomon: add 2*delta check bytes
##     v
##   codeword (n1 bytes)
##     |
##     |  Reed-Muller: each byte becomes n2 noisy-tolerant bits
##     v
##   codeword (n1*n2 bits)  <- this is what gets buried in noise
##
## Decoding runs the same ladder backwards. The Reed-Muller step hands
## back n1 bytes, a few of which are wrong; the Reed-Solomon step finds
## and repairs those few.
##
## Reference: [HQC-20250822] concatenated code; ported from the reference
## implementation's `code.c`.

import runePragmas
import ./params
import ./types
import ./reed_muller
import ./reed_solomon
import ./util

## Reference: [HQC-20250822] concatenated encoding; two-stage encoding for `codeEncode`; pitfall: the Reed-Solomon stage must run first, because the Reed-Muller stage expands its output.
proc codeEncode*(em: var HqcVec, m: openArray[byte], p: HqcParams,
    G: openArray[uint16]) {.role: {encryptor}, raises: [].} =
  ## em/m/p/G: the n1n2-bit codeword, the k message bytes, the parameter
  ## set, and the Reed-Solomon generator polynomial.
  ## Turn a short message into the long codeword that gets buried in noise.
  var
    tmp = default(array[hqcMaxN1, byte])
  reedSolomonEncode(tmp, m, p, G)
  reedMullerEncode(em, tmp, p)
  hqcWipeBytes(tmp)

## Reference: [HQC-20250822] concatenated decoding; two-stage decoding for `codeDecode`; pitfall: the Reed-Muller stage is allowed to be wrong about a few bytes, which is exactly what the Reed-Solomon stage is there for.
proc codeDecode*(m: var openArray[byte], em: HqcVec, p: HqcParams)
    {.role: {decryptor}, raises: [].} =
  ## m/em/p: the k recovered message bytes, the noisy codeword, the
  ## parameter set.
  ## Strip the noise off and hand back the message.
  var
    tmp = default(array[hqcMaxN1, byte])
  reedMullerDecode(tmp, em, p)
  reedSolomonDecode(m, tmp, p)
  hqcWipeBytes(tmp)

