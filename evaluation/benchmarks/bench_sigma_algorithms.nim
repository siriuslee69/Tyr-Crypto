proc runAlgo(kind: AlgoKind) =
  case kind
  of akBlake3Xof:
    discard blake3Hash(benchInput, benchBytes)
  of akGimliXof:
    gimliXofDiscard(benchKey32, benchNonce24, benchInput, benchBytes)
  of akXChaCha20:
    discard xchacha20Xor(benchKey32, benchNonce24, benchInput)
  of akXChaCha20Sse2:
    discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, b = xcbSse2)
  of akXChaCha20Avx2:
    discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, b = xcbAvx2)
  of akAesCtrScalar:
    discard aesCtrXor(benchKey32, benchAesNonce16, benchInput, acbScalar)
  of akAesCtrSse2:
    discard aesCtrXor(benchKey32, benchAesNonce16, benchInput, acbSse2)
  of akAesCtrAvx2:
    discard aesCtrXor(benchKey32, benchAesNonce16, benchInput, acbAvx2)
  of akGimli:
    var s = baseState
    gimliPermute(s)
  of akGimliSse:
    when declared(gimliPermuteSse):
      var s = baseState
      gimliPermuteSse(s)
    else:
      discard
  of akGimliSse4x:
    when declared(gimliPermuteSse4x):
      var
        ss: array[4, Gimli_Block] = default(array[4, Gimli_Block])
        i: int = 0
      i = 0
      while i < ss.len:
        ss[i] = baseState
        i = i + 1
      gimliPermuteSse4x(ss)
    else:
      discard
  of akGimliAvx8x:
    when declared(gimliPermuteAvx8x):
      var
        ss: array[8, Gimli_Block] = default(array[8, Gimli_Block])
        i: int = 0
      i = 0
      while i < ss.len:
        ss[i] = baseState
        i = i + 1
      gimliPermuteAvx8x(ss)
    else:
      discard
  of akBlake3Sse4:
    when declared(blake3CompressSse4):
      var
        cvs: array[4, Blake3Cv] = default(array[4, Blake3Cv])
        blocks: array[4, Blake3Block] = default(array[4, Blake3Block])
        i: int = 0
      i = 0
      while i < cvs.len:
        cvs[i] = baseCv
        blocks[i] = baseBlock
        i = i + 1
      discard blake3CompressSse4(cvs, blocks, 0'u64, 64'u32, 0'u32)
    else:
      discard
  of akBlake3Avx8:
    when declared(blake3CompressAvx8):
      var
        cvs: array[8, Blake3Cv] = default(array[8, Blake3Cv])
        blocks: array[8, Blake3Block] = default(array[8, Blake3Block])
        i: int = 0
      i = 0
      while i < cvs.len:
        cvs[i] = baseCv
        blocks[i] = baseBlock
        i = i + 1
      discard blake3CompressAvx8(cvs, blocks, 0'u64, 64'u32, 0'u32)
    else:
      discard

