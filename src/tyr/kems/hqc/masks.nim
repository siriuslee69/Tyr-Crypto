## ---------------------------------------------------------------------
## | HQC Masks <- answering yes/no without branching on a secret        |
## ---------------------------------------------------------------------
##
## The problem
## -----------
## Writing `if secret == 0:` lets anyone measuring how long the code runs
## learn something about the secret. So HQC never asks a question and
## jumps; it turns the answer into a bit pattern and blends both outcomes:
##
##   mask = all ones   -> (a and mask) or (b and not mask)  picks a
##   mask = all zeros  -> (a and mask) or (b and not mask)  picks b
##
## Every routine here builds one of those masks. They all read every
## input and take the same path whatever the answer is.
##
## How a mask is built
## -------------------
## For "is x non-zero", the trick is that x and its negation cannot both
## have a clear top bit unless x is zero:
##
##   x = 0        ->  x or -x = 0                 top bit 0
##   x = 1        ->  1 or 0xFFFFFFFF             top bit 1
##   x = 0x8000   ->  0x8000 or 0xFFFF8000        top bit 1
##
## Shifting that top bit down to position 0 and negating spreads it back
## across the whole word.
##
## Reference: [HQC-20250822] constant-time requirements; mask idioms taken
## from the reference implementation's `vector.c` and `reed_solomon.c`.

import runePragmas

## Reference: [HQC-20250822] constant-time requirements; non-zero test for `maskNonZero32`; pitfall: must not branch and must read the whole word.
proc maskNonZero32*(x: uint32): uint32 {.inline, role: {helper}, raises: [].} =
  ## x: the value to test.
  ## All ones when `x` is not zero, all zeros when it is.
  result = 0'u32 - ((x or (0'u32 - x)) shr 31)

## Reference: [HQC-20250822] constant-time requirements; equality test for `maskEqual32`; pitfall: must not branch and must read the whole word.
proc maskEqual32*(a, b: uint32): uint32 {.inline, role: {helper}, raises: [].} =
  ## a/b: the two values to compare.
  ## All ones when they are equal, all zeros when they differ.
  result = not maskNonZero32(a xor b)

## Reference: [HQC-20250822] constant-time requirements; ordering test for `maskLess32`; pitfall: only valid while both inputs stay below 2^31.
proc maskLess32*(a, b: uint32): uint32 {.inline, role: {helper}, raises: [].} =
  ## a/b: the two values to compare, both below 2^31.
  ## All ones when `a` is smaller than `b`, all zeros otherwise. The
  ## subtraction borrows into the top bit exactly when `a` is smaller.
  result = 0'u32 - ((a - b) shr 31)

## Reference: [HQC-20250822] constant-time requirements; narrowed non-zero test for `maskNonZero16`; pitfall: the Reed-Solomon code needs these masks at 16 bits wide.
proc maskNonZero16*(x: uint16): uint16 {.inline, role: {helper}, raises: [].} =
  ## x: the value to test.
  ## All ones when `x` is not zero, all zeros when it is.
  result = uint16(maskNonZero32(uint32(x)) and 0xffff'u32)

## Reference: [HQC-20250822] constant-time requirements; narrowed equality test for `maskEqual16`; pitfall: the Reed-Solomon code needs these masks at 16 bits wide.
proc maskEqual16*(a, b: uint32): uint16 {.inline, role: {helper}, raises: [].} =
  ## a/b: the two values to compare.
  ## All ones when they are equal, all zeros when they differ.
  result = uint16(maskEqual32(a, b) and 0xffff'u32)

## Reference: [HQC-20250822] constant-time requirements; narrowed ordering test for `maskLess16`; pitfall: only valid while both inputs stay below 2^31.
proc maskLess16*(a, b: uint32): uint16 {.inline, role: {helper}, raises: [].} =
  ## a/b: the two values to compare, both below 2^31.
  ## All ones when `a` is smaller than `b`, all zeros otherwise.
  result = uint16(maskLess32(a, b) and 0xffff'u32)
