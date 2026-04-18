## ------------------------------------------------------
## Frodo Noise <- centered noise sampling for FrodoKEM
## ------------------------------------------------------

import ./params
import ../../../../helpers/otter_support

proc frodoSampleN*(p: FrodoParams, S: var openArray[uint16]) =
  ## Map raw 16-bit pseudo-random words to the Frodo noise distribution.
  otterSpan("frodo.frodoSampleN"):
    var
      i: int = 0
      j: int = 0
      sample: uint16 = 0
      prnd: uint16 = 0
      sign: uint16 = 0
    i = 0
    while i < S.len:
      sample = 0'u16
      prnd = S[i] shr 1
      sign = S[i] and 0x1'u16
      j = 0
      while j < p.cdfTable.len - 1:
        sample = sample + (p.cdfTable[j] - prnd) shr 15
        j = j + 1
      S[i] = cast[uint16]((cast[int16](-cast[int16](sign)) xor cast[int16](sample)) +
        cast[int16](sign))
      i = i + 1
