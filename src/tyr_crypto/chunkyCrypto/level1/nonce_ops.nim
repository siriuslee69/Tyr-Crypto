## ============================================================
## | ChunkyCrypto Nonce Ops <- per-chunk nonce derivation     |
## ============================================================

proc storeU64LE(v: uint64, bs: var openArray[uint8], o: int) =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)
  bs[o + 2] = uint8((v shr 16) and 0xff)
  bs[o + 3] = uint8((v shr 24) and 0xff)
  bs[o + 4] = uint8((v shr 32) and 0xff)
  bs[o + 5] = uint8((v shr 40) and 0xff)
  bs[o + 6] = uint8((v shr 48) and 0xff)
  bs[o + 7] = uint8((v shr 56) and 0xff)

proc deriveChunkNonce*(bs: array[24, uint8], i: uint64): array[24, uint8] =
  ## bs: base nonce bytes.
  ## i: chunk index.
  var
    ns: array[24, uint8]
    j: int = 0
  j = 0
  while j < ns.len:
    ns[j] = bs[j]
    j = j + 1
  storeU64LE(i, ns, 16)
  result = ns
