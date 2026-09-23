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
  defer:
    secureClearPod(h0)
    secureClearPod(h1)
    secureClearPod(h2)
    secureClearPod(h3)
    secureClearPod(h4)
    secureClearPod(f)

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
