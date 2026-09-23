proc poly1305Mac*(key, msg: openArray[byte]): Poly1305Tag =
  ## Compute a detached Poly1305 authenticator for `msg` with a 32-byte one-time key.
  var
    r0: uint64 = 0
    r1: uint64 = 0
    r2: uint64 = 0
    r3: uint64 = 0
    r4: uint64 = 0
    s1: uint64 = 0
    s2: uint64 = 0
    s3: uint64 = 0
    s4: uint64 = 0
    h0: uint64 = 0
    h1: uint64 = 0
    h2: uint64 = 0
    h3: uint64 = 0
    h4: uint64 = 0
    d0: uint64 = 0
    d1: uint64 = 0
    d2: uint64 = 0
    d3: uint64 = 0
    d4: uint64 = 0
    c: uint64 = 0
    offset: int = 0
    take: int = 0
    hibit: uint64 = 0
    blk: array[poly1305BlockBytes, byte] = default(array[poly1305BlockBytes, byte])
    pad0: uint32 = 0
    pad1: uint32 = 0
    pad2: uint32 = 0
    pad3: uint32 = 0
    i: int = 0
  defer:
    secureClearPod(r0)
    secureClearPod(r1)
    secureClearPod(r2)
    secureClearPod(r3)
    secureClearPod(r4)
    secureClearPod(s1)
    secureClearPod(s2)
    secureClearPod(s3)
    secureClearPod(s4)
    secureClearPod(h0)
    secureClearPod(h1)
    secureClearPod(h2)
    secureClearPod(h3)
    secureClearPod(h4)
    secureClearPod(d0)
    secureClearPod(d1)
    secureClearPod(d2)
    secureClearPod(d3)
    secureClearPod(d4)
    secureClearBytes(blk)
    secureClearPod(pad0)
    secureClearPod(pad1)
    secureClearPod(pad2)
    secureClearPod(pad3)
  if key.len != poly1305KeyBytes:
    raise newException(ValueError, "poly1305 requires a 32-byte key")

  r0 = uint64(load32Le(key, 0) and 0x3ffffff'u32)
  r1 = uint64((load32Le(key, 3) shr 2) and 0x3ffff03'u32)
  r2 = uint64((load32Le(key, 6) shr 4) and 0x3ffc0ff'u32)
  r3 = uint64((load32Le(key, 9) shr 6) and 0x3f03fff'u32)
  r4 = uint64((load32Le(key, 12) shr 8) and 0x00fffff'u32)
  s1 = r1 * 5'u64
  s2 = r2 * 5'u64
  s3 = r3 * 5'u64
  s4 = r4 * 5'u64
  pad0 = load32Le(key, 16)
  pad1 = load32Le(key, 20)
  pad2 = load32Le(key, 24)
  pad3 = load32Le(key, 28)

  offset = 0
  while offset < msg.len:
    take = msg.len - offset
    if take >= poly1305BlockBytes:
      hibit = poly1305Hibit
      h0 = h0 + uint64(load32Le(msg, offset + 0) and 0x3ffffff'u32)
      h1 = h1 + uint64((load32Le(msg, offset + 3) shr 2) and 0x3ffffff'u32)
      h2 = h2 + uint64((load32Le(msg, offset + 6) shr 4) and 0x3ffffff'u32)
      h3 = h3 + uint64((load32Le(msg, offset + 9) shr 6) and 0x3ffffff'u32)
      h4 = h4 + uint64(load32Le(msg, offset + 12) shr 8) + hibit
      offset = offset + poly1305BlockBytes
    else:
      i = 0
      while i < take:
        blk[i] = msg[offset + i]
        i = i + 1
      blk[take] = 1'u8
      while i + 1 < poly1305BlockBytes:
        i = i + 1
        blk[i] = 0'u8
      hibit = 0'u64
      h0 = h0 + uint64(load32Le(blk, 0) and 0x3ffffff'u32)
      h1 = h1 + uint64((load32Le(blk, 3) shr 2) and 0x3ffffff'u32)
      h2 = h2 + uint64((load32Le(blk, 6) shr 4) and 0x3ffffff'u32)
      h3 = h3 + uint64((load32Le(blk, 9) shr 6) and 0x3ffffff'u32)
      h4 = h4 + uint64(load32Le(blk, 12) shr 8) + hibit
      offset = msg.len
    d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
    d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
    d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
    d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
    d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

    c = d0 shr 26
    h0 = d0 and poly1305Mask26
    d1 = d1 + c
    c = d1 shr 26
    h1 = d1 and poly1305Mask26
    d2 = d2 + c
    c = d2 shr 26
    h2 = d2 and poly1305Mask26
    d3 = d3 + c
    c = d3 shr 26
    h3 = d3 and poly1305Mask26
    d4 = d4 + c
    c = d4 shr 26
    h4 = d4 and poly1305Mask26
    h0 = h0 + c * 5'u64
    c = h0 shr 26
    h0 = h0 and poly1305Mask26
    h1 = h1 + c
  result = finalizeTag(h0, h1, h2, h3, h4, pad0, pad1, pad2, pad3)

proc poly1305Tag*(key, msg: openArray[byte]): seq[byte] =
  ## Convenience wrapper returning the detached Poly1305 authenticator as a sequence.
  var
    mac = poly1305Mac(key, msg)
    i: int = 0
  result = newSeq[byte](poly1305TagBytes)
  while i < poly1305TagBytes:
    result[i] = mac[i]
    i = i + 1

proc poly1305Verify*(key, msg, tag: openArray[byte]): bool =
  ## Verify a detached Poly1305 authenticator in constant time.
  if key.len != poly1305KeyBytes:
    raise newException(ValueError, "poly1305 requires a 32-byte key")
  var expected = poly1305Mac(key, msg)
  defer:
    secureClearBytes(expected)
  result = constantTimeEqual(expected, tag)
