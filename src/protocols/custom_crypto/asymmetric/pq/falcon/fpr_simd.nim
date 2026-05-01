## -------------------------------------------------------------------
## Falcon Fpr SIMD <- shared 2-lane FalconFpr helpers for SSE2 / NEON
## -------------------------------------------------------------------

import ./fpr
import ./params

when falconCompileHasSimd:
  ## Paper note: Falcon's spec and precision paper keep the FFT/LDL structure;
  ## Tyr only adds a portable two-lane `FalconFpr` backend here, not the full
  ## specialized AVX2 sampler design from other Falcon implementations.
  import simd_nexus/simd/base_operations
  import simd_nexus/simd/generic_f64

  type
    FalconSimd2* = SimdF64x2

  proc loadFalconSimd2*(A: openArray[FalconFpr], off: int): FalconSimd2 {.inline.} =
    ## A: FalconFpr slice backed by IEEE-754 bit patterns.
    ## off: starting element offset.
    result = loadF64x2Ptr[SimdF64x2](cast[pointer](unsafeAddr A[off]))

  proc storeFalconSimd2*(A: FalconSimd2, dst: var openArray[FalconFpr], off: int) {.inline.} =
    ## A: SIMD value to store back into a FalconFpr slice.
    ## dst: destination scalar slice.
    ## off: starting element offset.
    storeF64x2Ptr[SimdF64x2](cast[pointer](unsafeAddr dst[off]), A)

  proc set1FalconSimd2*(x: FalconFpr): FalconSimd2 {.inline.} =
    ## x: FalconFpr scalar to broadcast across both lanes.
    result = set1F64[SimdF64x2](fprToFloat(x))

  proc zeroFalconSimd2*(): FalconSimd2 {.inline.} =
    ## Return a zero-filled Falcon SIMD lane pair.
    result = set1F64[SimdF64x2](0.0)

  proc sumFalconSimd2*(A: FalconSimd2): FalconFpr {.inline.} =
    ## Fold both lanes into one FalconFpr scalar.
    var
      lanes = storeF64x2[SimdF64x2](A)
    result = floatToFpr(lanes[0] + lanes[1])

  proc addFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A + B

  proc subFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A - B

  proc mulFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A * B

  proc divFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A / B

  proc negFalconSimd2*(A: FalconSimd2): FalconSimd2 {.inline.} =
    ## Flip the sign of both Falcon float lanes.
    result = subFalconSimd2(zeroFalconSimd2(), A)
