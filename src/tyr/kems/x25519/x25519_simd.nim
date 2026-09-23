## X25519 SIMD field and batch routines included by x25519_impl.nim.
##
## The enclosing module supplies the backend imports and scalar helpers.

when defined(amd64) or defined(i386) or defined(neon) or defined(arm64) or defined(aarch64):
  type
    X25519FieldVec[T: SimdU64] = array[5, T]

  when defined(neon) or defined(arm64) or defined(aarch64):
    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `loadLaneVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
    proc loadLaneVec(vals: array[2, uint64]): uint64x2 {.inline.} =
      result = loadU64x2[uint64x2](vals)

    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `storeLaneVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
    proc storeLaneVec(v: uint64x2): array[2, uint64] {.inline.} =
      result = storeU64x2(v)
  else:
    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `loadLaneVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
    proc loadLaneVec(vals: array[2, uint64]): u64x2 {.inline.} =
      result = loadU64x2[u64x2](vals)

    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `storeLaneVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
    proc storeLaneVec(v: u64x2): array[2, uint64] {.inline.} =
      result = storeU64x2(v)

  when defined(avx2):
    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `loadLaneVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
    proc loadLaneVec(vals: array[4, uint64]): u64x4 {.inline.} =
      result = loadU64x4[u64x4](vals)

    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `storeLaneVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
    proc storeLaneVec(v: u64x4): array[4, uint64] {.inline.} =
      result = storeU64x4(v)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `subVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc subVec[T: SimdU64](a, b: T): T {.inline.} =
    result = a + (not b) + set1U64[T](1'u64)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `mulBy19Vec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc mulBy19Vec[T: SimdU64](a: T): T {.inline.} =
    result = a + (a shl 1) + (a shl 4)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `fe0Vec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc fe0Vec[T: SimdU64](h: var X25519FieldVec[T]) {.inline.} =
    var zero = set1U64[T](0'u64)
    h[0] = zero
    h[1] = zero
    h[2] = zero
    h[3] = zero
    h[4] = zero

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `fe1Vec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc fe1Vec[T: SimdU64](h: var X25519FieldVec[T]) {.inline.} =
    var
      zero = set1U64[T](0'u64)
      one = set1U64[T](1'u64)
    h[0] = one
    h[1] = zero
    h[2] = zero
    h[3] = zero
    h[4] = zero

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `packMaskVec`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
  proc packMaskVec[T: SimdU64](bits: openArray[uint32]): T {.inline.} =
    const lanes = lanesU64[T]()
    var
      maskVals: array[lanes, uint64] = default(array[lanes, uint64])
      lane: int = 0
    if bits.len != lanes:
      raise newException(ValueError, "invalid X25519 SIMD mask lane count")
    while lane < lanes:
      maskVals[lane] = 0'u64 - uint64(bits[lane] and 1'u32)
      inc lane
    result = loadLaneVec(maskVals)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `packFieldVec`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
  proc packFieldVec[T: SimdU64](fields: array[lanesU64[T](), X25519Field]): X25519FieldVec[T] {.inline.} =
    const lanes = lanesU64[T]()
    var
      limbVals: array[lanes, uint64] = default(array[lanes, uint64])
      limb: int = 0
      lane: int = 0
    limb = 0
    while limb < 5:
      lane = 0
      while lane < lanes:
        limbVals[lane] = fields[lane][limb]
        inc lane
      result[limb] = loadLaneVec(limbVals)
      inc limb

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `unpackFieldVec`; pitfall: reject malformed or non-canonical input before indexed access.
  proc unpackFieldVec[T: SimdU64](v: X25519FieldVec[T]): array[lanesU64[T](), X25519Field] {.inline.} =
    const lanes = lanesU64[T]()
    var
      limbVals: array[lanes, uint64] = default(array[lanes, uint64])
      limb: int = 0
      lane: int = 0
    limb = 0
    while limb < 5:
      limbVals = storeLaneVec(v[limb])
      lane = 0
      while lane < lanes:
        result[lane][limb] = limbVals[lane]
        inc lane
      inc limb

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `feAddVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc feAddVec[T: SimdU64](h: var X25519FieldVec[T], f, g: X25519FieldVec[T]) {.inline.} =
    h[0] = f[0] + g[0]
    h[1] = f[1] + g[1]
    h[2] = f[2] + g[2]
    h[3] = f[3] + g[3]
    h[4] = f[4] + g[4]

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `feSubVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc feSubVec[T: SimdU64](h: var X25519FieldVec[T], f, g: X25519FieldVec[T]) {.inline.} =
    var
      mask = set1U64[T](feMask)
      bias0 = set1U64[T](0x00ff_ffff_ffff_fda'u64)
      bias = set1U64[T](0x00ff_ffff_ffff_ffe'u64)
      h0 = g[0]
      h1 = g[1]
      h2 = g[2]
      h3 = g[3]
      h4 = g[4]
    h1 = h1 + (h0 shr 51)
    h0 = h0 and mask
    h2 = h2 + (h1 shr 51)
    h1 = h1 and mask
    h3 = h3 + (h2 shr 51)
    h2 = h2 and mask
    h4 = h4 + (h3 shr 51)
    h3 = h3 and mask
    h0 = h0 + mulBy19Vec(h4 shr 51)
    h4 = h4 and mask
    h[0] = subVec(f[0] + bias0, h0)
    h[1] = subVec(f[1] + bias, h1)
    h[2] = subVec(f[2] + bias, h2)
    h[3] = subVec(f[3] + bias, h3)
    h[4] = subVec(f[4] + bias, h4)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `feCswapVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc feCswapVec[T: SimdU64](f, g: var X25519FieldVec[T],
      bits: openArray[uint32]) {.inline.} =
    var
      mask = packMaskVec[T](bits)
      x0 = (f[0] xor g[0]) and mask
      x1 = (f[1] xor g[1]) and mask
      x2 = (f[2] xor g[2]) and mask
      x3 = (f[3] xor g[3]) and mask
      x4 = (f[4] xor g[4]) and mask
    f[0] = f[0] xor x0
    f[1] = f[1] xor x1
    f[2] = f[2] xor x2
    f[3] = f[3] xor x3
    f[4] = f[4] xor x4
    g[0] = g[0] xor x0
    g[1] = g[1] xor x1
    g[2] = g[2] xor x2
    g[3] = g[3] xor x3
    g[4] = g[4] xor x4

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `feMulVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc feMulVec[T: SimdU64](h: var X25519FieldVec[T], f, g: X25519FieldVec[T]) {.inline.} =
    const lanes = lanesU64[T]()
    var
      sf = unpackFieldVec(f)
      sg = unpackFieldVec(g)
      sh: array[lanes, X25519Field] = default(array[lanes, X25519Field])
      lane: int = 0
    while lane < lanes:
      feMul(sh[lane], sf[lane], sg[lane])
      inc lane
    h = packFieldVec[T](sh)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `feSqVec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc feSqVec[T: SimdU64](h: var X25519FieldVec[T], f: X25519FieldVec[T]) {.inline.} =
    const lanes = lanesU64[T]()
    var
      sf = unpackFieldVec(f)
      sh: array[lanes, X25519Field] = default(array[lanes, X25519Field])
      lane: int = 0
    while lane < lanes:
      feSq(sh[lane], sf[lane])
      inc lane
    h = packFieldVec[T](sh)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `feMul32Vec`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc feMul32Vec[T: SimdU64](h: var X25519FieldVec[T], f: X25519FieldVec[T],
      n: uint32) {.inline.} =
    const lanes = lanesU64[T]()
    var
      sf = unpackFieldVec(f)
      sh: array[lanes, X25519Field] = default(array[lanes, X25519Field])
      lane: int = 0
    while lane < lanes:
      feMul32(sh[lane], sf[lane], n)
      inc lane
    h = packFieldVec[T](sh)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `feInvertBatchFields`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc feInvertBatchFields[L: static[int]](outInv, zs: var array[L, X25519Field]) {.inline.} =
    var
      prefix: array[L, X25519Field] = default(array[L, X25519Field])
      running: X25519Field = default(X25519Field)
      invAll: X25519Field = default(X25519Field)
      lane: int = 0
    defer:
      secureClearPod(prefix)
      secureClearPod(running)
      secureClearPod(invAll)
    feCopy(prefix[0], zs[0])
    lane = 1
    while lane < L:
      feMul(prefix[lane], prefix[lane - 1], zs[lane])
      inc lane
    feInvert(invAll, prefix[L - 1])
    lane = L - 1
    while lane > 0:
      feMul(outInv[lane], invAll, prefix[lane - 1])
      feMul(running, invAll, zs[lane])
      feCopy(invAll, running)
      dec lane
    feCopy(outInv[0], invAll)

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519ScalarmultBatchRaw`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc x25519ScalarmultBatchRaw*[T: SimdU64](outShared: var array[lanesU64[T](), X25519Bytes32],
      secretKeys, publicKeys: array[lanesU64[T](), X25519Bytes32]): array[lanesU64[T](), bool] =
    otterSpan(x25519BenchTag & ".scalarmultBatch"):
      const lanes = lanesU64[T]()
      var
        t: array[lanes, X25519Bytes32] = default(array[lanes, X25519Bytes32])
        x1Fields: array[lanes, X25519Field] = default(array[lanes, X25519Field])
        x1, x2, x3, z2, z3: X25519FieldVec[T] = default(X25519FieldVec[T])
        a, b, aa, bb, e, da, cb: X25519FieldVec[T] = default(X25519FieldVec[T])
        swapBits: array[lanes, uint32] = default(array[lanes, uint32])
        bits: array[lanes, uint32] = default(array[lanes, uint32])
        x2Fields, z2Fields, invZ: array[lanes, X25519Field] = default(array[lanes, X25519Field])
        affine: X25519Field = default(X25519Field)
        lane: int = 0
        pos: int = 254
        allValid: bool = true
      defer:
        secureClearPod(t)
        secureClearPod(x1Fields)
        secureZeroMem(addr x1, sizeof(x1))
        secureZeroMem(addr x2, sizeof(x2))
        secureZeroMem(addr x3, sizeof(x3))
        secureZeroMem(addr z2, sizeof(z2))
        secureZeroMem(addr z3, sizeof(z3))
        secureZeroMem(addr a, sizeof(a))
        secureZeroMem(addr b, sizeof(b))
        secureZeroMem(addr aa, sizeof(aa))
        secureZeroMem(addr bb, sizeof(bb))
        secureZeroMem(addr e, sizeof(e))
        secureZeroMem(addr da, sizeof(da))
        secureZeroMem(addr cb, sizeof(cb))
        secureClearPod(swapBits)
        secureClearPod(bits)
        secureClearPod(x2Fields)
        secureClearPod(z2Fields)
        secureClearPod(invZ)
        secureClearPod(affine)
      lane = 0
      while lane < lanes:
        result[lane] = not hasSmallOrder(publicKeys[lane])
        if result[lane]:
          clampScalar(t[lane], secretKeys[lane])
          feFromBytes(x1Fields[lane], publicKeys[lane])
        else:
          allValid = false
          secureClearPod(t[lane])
          fe0(x1Fields[lane])
          secureClearPod(outShared[lane])
        inc lane
      if not allValid:
        lane = 0
        while lane < lanes:
          if result[lane]:
            result[lane] = x25519ScalarmultRaw(outShared[lane], secretKeys[lane], publicKeys[lane])
          else:
            secureClearPod(outShared[lane])
          inc lane
      else:
        x1 = packFieldVec[T](x1Fields)
        fe1Vec(x2)
        fe0Vec(z2)
        x3 = x1
        fe1Vec(z3)
        while pos >= 0:
          lane = 0
          while lane < lanes:
            bits[lane] = uint32((t[lane][pos div 8] shr (pos and 7)) and 1'u8)
            swapBits[lane] = swapBits[lane] xor bits[lane]
            inc lane
          feCswapVec(x2, x3, swapBits)
          feCswapVec(z2, z3, swapBits)
          swapBits = bits
          feAddVec(a, x2, z2)
          feSubVec(b, x2, z2)
          feSqVec(aa, a)
          feSqVec(bb, b)
          feMulVec(x2, aa, bb)
          feSubVec(e, aa, bb)
          feSubVec(da, x3, z3)
          feMulVec(da, da, a)
          feAddVec(cb, x3, z3)
          feMulVec(cb, cb, b)
          feAddVec(x3, da, cb)
          feSqVec(x3, x3)
          feSubVec(z3, da, cb)
          feSqVec(z3, z3)
          feMulVec(z3, z3, x1)
          feMul32Vec(z2, e, 121_666'u32)
          feAddVec(z2, z2, bb)
          feMulVec(z2, z2, e)
          dec pos
        feCswapVec(x2, x3, swapBits)
        feCswapVec(z2, z3, swapBits)
        x2Fields = unpackFieldVec(x2)
        z2Fields = unpackFieldVec(z2)
        feInvertBatchFields(invZ, z2Fields)
        lane = 0
        while lane < lanes:
          feMul(affine, x2Fields[lane], invZ[lane])
          feToBytes(outShared[lane], affine)
          result[lane] = not isAllZero(outShared[lane])
          inc lane

  ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519ScalarmultBatch2Impl`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc x25519ScalarmultBatch2Impl[T: SimdU64](outShared: var array[2, X25519Bytes32],
      secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
    var
      lane: int = 0
      allValid: bool = true
    while lane < 2:
      allValid = allValid and not hasSmallOrder(publicKeys[lane])
      inc lane
    if not allValid:
      lane = 0
      while lane < 2:
        if hasSmallOrder(publicKeys[lane]):
          result[lane] = false
          secureClearPod(outShared[lane])
        else:
          result[lane] = x25519ScalarmultRaw(outShared[lane], secretKeys[lane], publicKeys[lane])
        inc lane
      return
    result = x25519ScalarmultBatchRaw[T](outShared, secretKeys, publicKeys)

  when defined(amd64) or defined(i386):
    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519ScalarmultBatchSse2x`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
    proc x25519ScalarmultBatchSse2x*(outShared: var array[2, X25519Bytes32],
        secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
      result = x25519ScalarmultBatch2Impl[u64x2](outShared, secretKeys, publicKeys)

    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519TyrSharedSse2x`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
    proc x25519TyrSharedSse2x*(secretKeys, publicKeys: array[2, seq[byte]]): array[2, seq[byte]] =
      var
        sk: array[2, X25519Bytes32] = default(array[2, X25519Bytes32])
        pk: array[2, X25519Bytes32] = default(array[2, X25519Bytes32])
        shared: array[2, X25519Bytes32] = default(array[2, X25519Bytes32])
        ok: array[2, bool] = default(array[2, bool])
        lane: int = 0
      defer:
        secureClearPod(sk)
        secureClearPod(pk)
        secureClearPod(shared)
      while lane < 2:
        sk[lane] = toFixed32(secretKeys[lane])
        pk[lane] = toFixed32(publicKeys[lane])
        inc lane
      ok = x25519ScalarmultBatchSse2x(shared, sk, pk)
      lane = 0
      while lane < 2:
        if not ok[lane]:
          raise newException(ValueError, "X25519 SIMD batch shared secret derivation failed")
        result[lane] = toSeqBytes(shared[lane])
        inc lane

  when defined(neon) or defined(arm64) or defined(aarch64):
    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519ScalarmultBatchNeon2x`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
    proc x25519ScalarmultBatchNeon2x*(outShared: var array[2, X25519Bytes32],
        secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
      result = x25519ScalarmultBatch2Impl[uint64x2](outShared, secretKeys, publicKeys)

    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519TyrSharedNeon2x`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
    proc x25519TyrSharedNeon2x*(secretKeys, publicKeys: array[2, seq[byte]]): array[2, seq[byte]] =
      var
        sk: array[2, X25519Bytes32] = default(array[2, X25519Bytes32])
        pk: array[2, X25519Bytes32] = default(array[2, X25519Bytes32])
        shared: array[2, X25519Bytes32] = default(array[2, X25519Bytes32])
        ok: array[2, bool] = default(array[2, bool])
        lane: int = 0
      defer:
        secureClearPod(sk)
        secureClearPod(pk)
        secureClearPod(shared)
      while lane < 2:
        sk[lane] = toFixed32(secretKeys[lane])
        pk[lane] = toFixed32(publicKeys[lane])
        inc lane
      ok = x25519ScalarmultBatchNeon2x(shared, sk, pk)
      lane = 0
      while lane < 2:
        if not ok[lane]:
          raise newException(ValueError, "X25519 NEON batch shared secret derivation failed")
        result[lane] = toSeqBytes(shared[lane])
        inc lane

  when defined(avx2):
    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519ScalarmultBatchAvx4x`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
    proc x25519ScalarmultBatchAvx4x*(outShared: var array[4, X25519Bytes32],
        secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] =
      var
        lane: int = 0
        allValid: bool = true
      while lane < 4:
        allValid = allValid and not hasSmallOrder(publicKeys[lane])
        inc lane
      if not allValid:
        lane = 0
        while lane < 4:
          if hasSmallOrder(publicKeys[lane]):
            result[lane] = false
            secureClearPod(outShared[lane])
          else:
            result[lane] = x25519ScalarmultRaw(outShared[lane], secretKeys[lane], publicKeys[lane])
          inc lane
        return
      result = x25519ScalarmultBatchRaw[u64x4](outShared, secretKeys, publicKeys)

    ## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519TyrSharedAvx4x`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
    proc x25519TyrSharedAvx4x*(secretKeys, publicKeys: array[4, seq[byte]]): array[4, seq[byte]] =
      var
        sk: array[4, X25519Bytes32] = default(array[4, X25519Bytes32])
        pk: array[4, X25519Bytes32] = default(array[4, X25519Bytes32])
        shared: array[4, X25519Bytes32] = default(array[4, X25519Bytes32])
        ok: array[4, bool] = default(array[4, bool])
        lane: int = 0
      defer:
        secureClearPod(sk)
        secureClearPod(pk)
        secureClearPod(shared)
      while lane < 4:
        sk[lane] = toFixed32(secretKeys[lane])
        pk[lane] = toFixed32(publicKeys[lane])
        inc lane
      ok = x25519ScalarmultBatchAvx4x(shared, sk, pk)
      lane = 0
      while lane < 4:
        if not ok[lane]:
          raise newException(ValueError, "X25519 SIMD batch shared secret derivation failed")
        result[lane] = toSeqBytes(shared[lane])
        inc lane
