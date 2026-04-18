## ----------------------------------------------------
## Gimli Sponge <- XOF, stream, and tag helpers
## ----------------------------------------------------

import ./gimli

const
  gimliBlockLen = 48
  gimliTagLenDefault* = 16

type
  ByteSeq = seq[uint8]
  GimliSpongeState* = object
    ## st: sponge state.
    st: Gimli_Block
    ## bufs: rate buffer for absorb/squeeze.
    bufs: array[gimliBlockLen, uint8]
    ## l: buffered bytes for absorb.
    l: int
    ## outOffset: current squeeze offset.
    outOffset: int
    ## squeezing: whether state is in squeeze mode.
    squeezing: bool


## loadU32: load a little-endian u32 from bytes.
## bs: byte sequence to read.
## o: byte offset.
proc loadU32(bs: openArray[uint8], o: int): uint32 =
  var
    b0: uint32 = 0
    b1: uint32 = 0
    b2: uint32 = 0
    b3: uint32 = 0
  b0 = uint32(bs[o])
  b1 = uint32(bs[o + 1]) shl 8
  b2 = uint32(bs[o + 2]) shl 16
  b3 = uint32(bs[o + 3]) shl 24
  result = b0 or b1 or b2 or b3


## storeU32: store a little-endian u32 into bytes.
## v: value to store.
## bs: byte sequence to update.
## o: byte offset.
proc storeU32(v: uint32, bs: var ByteSeq, o: int) =
  bs[o] = uint8(v and 0xff)
  bs[o + 1] = uint8((v shr 8) and 0xff)
  bs[o + 2] = uint8((v shr 16) and 0xff)
  bs[o + 3] = uint8((v shr 24) and 0xff)


## absorbBlock: xor a 48-byte block into the gimli state.
## st: gimli state.
## bs: block bytes.
proc absorbBlock(st: var Gimli_Block, bs: ByteSeq) =
  var
    i: int = 0
    offset: int = 0
  i = 0
  offset = 0
  while i < 12:
    st[i] = st[i] xor loadU32(bs, offset)
    i = i + 1
    offset = offset + 4


proc absorbBlockArr(st: var Gimli_Block, bs: array[gimliBlockLen, uint8]) =
  var
    i: int = 0
    offset: int = 0
  i = 0
  offset = 0
  while i < 12:
    st[i] = st[i] xor loadU32(bs, offset)
    i = i + 1
    offset = offset + 4


proc fillRateBuf(st: Gimli_Block, bs: var array[gimliBlockLen, uint8]) =
  var
    i: int = 0
  i = 0
  while i < 12:
    bs[i * 4] = uint8(st[i] and 0xff)
    bs[i * 4 + 1] = uint8((st[i] shr 8) and 0xff)
    bs[i * 4 + 2] = uint8((st[i] shr 16) and 0xff)
    bs[i * 4 + 3] = uint8((st[i] shr 24) and 0xff)
    i = i + 1


proc gimliAbsorbInit*(s: var GimliSpongeState) =
  s.st = default(Gimli_Block)
  s.l = 0
  s.outOffset = 0
  s.squeezing = false


proc gimliAbsorbUpdate*(s: var GimliSpongeState, ms: openArray[uint8]) =
  var
    i: int = 0
  if s.squeezing:
    raise newException(ValueError, "gimli sponge already squeezing")
  i = 0
  while i < ms.len:
    s.bufs[s.l] = ms[i]
    s.l = s.l + 1
    if s.l == gimliBlockLen:
      absorbBlockArr(s.st, s.bufs)
      gimliPermute(s.st)
      s.l = 0
    i = i + 1


proc gimliAbsorbFinal*(s: var GimliSpongeState) =
  var
    i: int = 0
  if s.squeezing:
    return
  i = s.l
  while i < gimliBlockLen:
    s.bufs[i] = 0'u8
    i = i + 1
  s.bufs[s.l] = s.bufs[s.l] xor 0x80'u8
  absorbBlockArr(s.st, s.bufs)
  gimliPermute(s.st)
  s.squeezing = true
  s.outOffset = 0
  fillRateBuf(s.st, s.bufs)


proc gimliSqueezeInto*(s: var GimliSpongeState, ds: var openArray[uint8]) =
  var
    i: int = 0
  if not s.squeezing:
    gimliAbsorbFinal(s)
  i = 0
  while i < ds.len:
    if s.outOffset == gimliBlockLen:
      gimliPermute(s.st)
      fillRateBuf(s.st, s.bufs)
      s.outOffset = 0
    ds[i] = s.bufs[s.outOffset]
    s.outOffset = s.outOffset + 1
    i = i + 1

## fillBlock: populate a 48-byte buffer from src.
## buf: block buffer to update.
## src: input bytes.
## o: offset in src.
## take: number of bytes to copy.
## pad: whether to apply 0x80 padding when take < block size.
proc fillBlock(buf: var ByteSeq, src: openArray[uint8], o, take: int, pad: bool) =
  var
    i: int = 0
  i = 0
  while i < gimliBlockLen:
    if i < take:
      buf[i] = src[o + i]
    else:
      buf[i] = 0'u8
    i = i + 1
  if pad and take < gimliBlockLen:
    buf[take] = buf[take] xor 0x80'u8


## absorbSequence: absorb bytes into the gimli state.
## st: gimli state.
## src: input bytes.
## pad: whether to pad the final partial block.
proc absorbSequence(st: var Gimli_Block, src: openArray[uint8], pad: bool) =
  var
    buf: ByteSeq = @[]
    offset: int = 0
    remaining: int = 0
    take: int = 0
  buf.setLen(gimliBlockLen)
  if src.len == 0 and pad:
    fillBlock(buf, src, 0, 0, true)
    absorbBlock(st, buf)
    gimliPermute(st)
    return
  offset = 0
  while offset < src.len:
    remaining = src.len - offset
    take = gimliBlockLen
    if remaining < take:
      take = remaining
    fillBlock(buf, src, offset, take, pad)
    absorbBlock(st, buf)
    gimliPermute(st)
    offset = offset + take


## squeezeState: write sponge output into bytes.
## st: gimli state (mutated between output blocks).
## outLen: desired output length.
proc squeezeState(st: var Gimli_Block, outLen: int): ByteSeq =
  var
    rs: ByteSeq = @[]
    buf: ByteSeq = @[]
    outOffset: int = 0
    take: int = 0
    i: int = 0
  rs.setLen(outLen)
  buf.setLen(gimliBlockLen)
  outOffset = 0
  while outOffset < outLen:
    i = 0
    while i < 12:
      storeU32(st[i], buf, i * 4)
      i = i + 1
    take = gimliBlockLen
    if outLen - outOffset < take:
      take = outLen - outOffset
    i = 0
    while i < take:
      rs[outOffset + i] = buf[i]
      i = i + 1
    outOffset = outOffset + take
    if outOffset < outLen:
      gimliPermute(st)
  result = rs


## squeezeStateDiscard: advance sponge state for outLen bytes without storing output.
## This is useful for benchmarks where the output buffer is discarded.
proc squeezeStateDiscard(st: var Gimli_Block, outLen: int) =
  var remaining: int = outLen
  var take: int = 0
  if remaining <= 0:
    return
  while remaining > 0:
    take = gimliBlockLen
    if remaining < take:
      take = remaining
    remaining = remaining - take
    if remaining > 0:
      gimliPermute(st)


## gimliXof: sponge output over key + nonce + message.
## ks: key bytes.
## ns: nonce bytes.
## ms: message bytes.
## outLen: output length.
proc gimliXof*(ks, ns, ms: openArray[uint8], outLen: int): ByteSeq =
  var
    st: Gimli_Block
  st = default(Gimli_Block)
  absorbSequence(st, ks, false)
  absorbSequence(st, ns, false)
  absorbSequence(st, ms, true)
  result = squeezeState(st, outLen)


## gimliXofDiscard: absorb key/nonce/message and discard output blocks.
proc gimliXofDiscard*(ks, ns, ms: openArray[uint8], outLen: int) =
  var
    st: Gimli_Block
  st = default(Gimli_Block)
  absorbSequence(st, ks, false)
  absorbSequence(st, ns, false)
  absorbSequence(st, ms, true)
  squeezeStateDiscard(st, outLen)


## gimliTag: compute a Gimli tag for key + nonce + message.
## ks: key bytes.
## ns: nonce bytes.
## ms: message bytes.
## outLen: output length.
proc gimliTag*(ks, ns, ms: openArray[uint8], outLen: int): ByteSeq =
  result = gimliXof(ks, ns, ms, outLen)


## gimliTag: compute a Gimli tag with default length.
## ks: key bytes.
## ns: nonce bytes.
## ms: message bytes.
proc gimliTag*(ks, ns, ms: openArray[uint8]): ByteSeq =
  result = gimliXof(ks, ns, ms, gimliTagLenDefault)


## gimliStreamXor: apply a Gimli-based keystream to input.
## ks: key bytes.
## ns: nonce bytes.
## input: bytes to transform.
proc gimliStreamXor*(ks, ns, input: openArray[uint8]): ByteSeq =
  var
    ksBytes: ByteSeq = @[]
    outBytes: ByteSeq = @[]
    i: int = 0
  ksBytes = gimliXof(ks, ns, @[], input.len)
  outBytes.setLen(input.len)
  i = 0
  while i < input.len:
    outBytes[i] = input[i] xor ksBytes[i]
    i = i + 1
  result = outBytes
