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

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `loadFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc loadFalconSimd2*(A: openArray[FalconFpr], off: int): FalconSimd2 {.inline.} =
    ## A: FalconFpr slice backed by IEEE-754 bit patterns.
    ## off: starting element offset.
    result = loadF64x2Ptr[SimdF64x2](cast[pointer](unsafeAddr A[off]))

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `storeFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc storeFalconSimd2*(A: FalconSimd2, dst: var openArray[FalconFpr], off: int) {.inline.} =
    ## A: SIMD value to store back into a FalconFpr slice.
    ## dst: destination scalar slice.
    ## off: starting element offset.
    storeF64x2Ptr[SimdF64x2](cast[pointer](unsafeAddr dst[off]), A)

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `set1FalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc set1FalconSimd2*(x: FalconFpr): FalconSimd2 {.inline.} =
    ## x: FalconFpr scalar to broadcast across both lanes.
    result = set1F64[SimdF64x2](fprToFloat(x))

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `zeroFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc zeroFalconSimd2*(): FalconSimd2 {.inline.} =
    ## Return a zero-filled Falcon SIMD lane pair.
    result = set1F64[SimdF64x2](0.0)

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `sumFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc sumFalconSimd2*(A: FalconSimd2): FalconFpr {.inline.} =
    ## Fold both lanes into one FalconFpr scalar.
    var
      lanes = storeF64x2[SimdF64x2](A)
    result = floatToFpr(lanes[0] + lanes[1])

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `addFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc addFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A + B

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `subFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc subFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A - B

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `mulFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc mulFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A * B

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `divFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc divFalconSimd2*(A, B: FalconSimd2): FalconSimd2 {.inline.} =
    ## A: left SIMD operand.
    ## B: right SIMD operand.
    result = A / B

  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; implementation support for the family algorithms for `negFalconSimd2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc negFalconSimd2*(A: FalconSimd2): FalconSimd2 {.inline.} =
    ## Flip the sign of both Falcon float lanes.
    result = subFalconSimd2(zeroFalconSimd2(), A)
