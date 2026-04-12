## ---------------------------------------------------------
## Poly1305 <- scalar one-time authenticator over LE message
## ---------------------------------------------------------

const
  poly1305KeyBytes* = 32
  poly1305TagBytes* = 16
  poly1305BlockBytes = 16
  poly1305Mask26 = 0x3ffffff'u64
  poly1305Hibit = 1'u64 shl 24

type
  ## Fixed detached Poly1305 tag.
  Poly1305Tag* = array[poly1305TagBytes, byte]

proc load32Le(A: openArray[byte], o: int): uint32 {.inline.} =
  result =
    uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or
    (uint32(A[o + 3]) shl 24)

proc store32Le(A: var openArray[byte], o: int, v: uint32) {.inline.} =
  A[o] = byte(v and 0xff'u32)
  A[o + 1] = byte((v shr 8) and 0xff'u32)
  A[o + 2] = byte((v shr 16) and 0xff'u32)
  A[o + 3] = byte((v shr 24) and 0xff'u32)

proc constantTimeEqual(A, B: openArray[byte]): bool =
  if A.len != B.len:
    return false
  var
    diff: uint8 = 0
    i: int = 0
  while i < A.len:
    diff = diff or (A[i] xor B[i])
    i = i + 1
  result = diff == 0'u8

proc finalizeTag(h0In, h1In, h2In, h3In, h4In: uint64,
    pad0, pad1, pad2, pad3: uint32): Poly1305Tag =
  var
    h0 = h0In
    h1 = h1In
    h2 = h2In
    h3 = h3In
    h4 = h4In
    c: uint64 = 0
    g0: uint64 = 0
    g1: uint64 = 0
    g2: uint64 = 0
    g3: uint64 = 0
    g4: uint64 = 0
    mask: uint64 = 0
    f: uint64 = 0
    w0: uint32 = 0
    w1: uint32 = 0
    w2: uint32 = 0
    w3: uint32 = 0

  c = h1 shr 26
  h1 = h1 and poly1305Mask26
  h2 = h2 + c
  c = h2 shr 26
  h2 = h2 and poly1305Mask26
  h3 = h3 + c
  c = h3 shr 26
  h3 = h3 and poly1305Mask26
  h4 = h4 + c
  c = h4 shr 26
  h4 = h4 and poly1305Mask26
  h0 = h0 + c * 5'u64
  c = h0 shr 26
  h0 = h0 and poly1305Mask26
  h1 = h1 + c

  g0 = h0 + 5'u64
  c = g0 shr 26
  g0 = g0 and poly1305Mask26
  g1 = h1 + c
  c = g1 shr 26
  g1 = g1 and poly1305Mask26
  g2 = h2 + c
  c = g2 shr 26
  g2 = g2 and poly1305Mask26
  g3 = h3 + c
  c = g3 shr 26
  g3 = g3 and poly1305Mask26
  g4 = h4 + c - (1'u64 shl 26)

  mask = (g4 shr 63) - 1'u64
  g0 = g0 and mask
  g1 = g1 and mask
  g2 = g2 and mask
  g3 = g3 and mask
  g4 = g4 and mask
  mask = not mask
  h0 = (h0 and mask) or g0
  h1 = (h1 and mask) or g1
  h2 = (h2 and mask) or g2
  h3 = (h3 and mask) or g3
  h4 = (h4 and mask) or g4

  w0 = uint32((h0 or (h1 shl 26)) and 0xffffffff'u64)
  w1 = uint32(((h1 shr 6) or (h2 shl 20)) and 0xffffffff'u64)
  w2 = uint32(((h2 shr 12) or (h3 shl 14)) and 0xffffffff'u64)
  w3 = uint32(((h3 shr 18) or (h4 shl 8)) and 0xffffffff'u64)

  f = uint64(w0) + uint64(pad0)
  w0 = uint32(f and 0xffffffff'u64)
  f = uint64(w1) + uint64(pad1) + (f shr 32)
  w1 = uint32(f and 0xffffffff'u64)
  f = uint64(w2) + uint64(pad2) + (f shr 32)
  w2 = uint32(f and 0xffffffff'u64)
  f = uint64(w3) + uint64(pad3) + (f shr 32)
  w3 = uint32(f and 0xffffffff'u64)

  store32Le(result, 0, w0)
  store32Le(result, 4, w1)
  store32Le(result, 8, w2)
  store32Le(result, 12, w3)

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
    blk: array[poly1305BlockBytes, byte]
    pad0: uint32 = 0
    pad1: uint32 = 0
    pad2: uint32 = 0
    pad3: uint32 = 0
    i: int = 0
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
  result = constantTimeEqual(expected, tag)

when defined(amd64) or defined(i386):
  import ./poly1305_simd
  export poly1305_simd
