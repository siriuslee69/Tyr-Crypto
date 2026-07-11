## ----------------------------------------------------
## Gimli Sponge <- XOF, stream, and tag helpers
## ----------------------------------------------------

import ./gimli
import ../secure_memory

const
  ## Gimli-Hash uses a 16-byte rate and keeps 32 bytes as capacity.
  gimliBlockLen = 16
  gimliTagLenDefault* = 16
  gimliKeyBytes* = 32
  gimliNonceBytes* = 24
  gimliXofDomain: array[16, uint8] = [
    uint8('T'), uint8('Y'), uint8('R'), uint8('-'),
    uint8('G'), uint8('I'), uint8('M'), uint8('L'),
    uint8('I'), uint8('-'), uint8('X'), uint8('O'),
    uint8('F'), uint8('-'), uint8('v'), uint8('2')
  ]
  gimliTagDomain: array[16, uint8] = [
    uint8('T'), uint8('Y'), uint8('R'), uint8('-'),
    uint8('G'), uint8('I'), uint8('M'), uint8('L'),
    uint8('I'), uint8('-'), uint8('T'), uint8('A'),
    uint8('G'), uint8('-'), uint8('v'), uint8('2')
  ]
  gimliStreamDomain: array[16, uint8] = [
    uint8('T'), uint8('Y'), uint8('R'), uint8('-'),
    uint8('G'), uint8('I'), uint8('M'), uint8('L'),
    uint8('I'), uint8('-'), uint8('S'), uint8('T'),
    uint8('R'), uint8('M'), uint8('-'), uint8('2')
  ]

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


proc absorbBlockArr(st: var Gimli_Block, bs: array[gimliBlockLen, uint8]) =
  var
    i: int = 0
    offset: int = 0
  i = 0
  offset = 0
  while i < 4:
    st[i] = st[i] xor loadU32(bs, offset)
    i = i + 1
    offset = offset + 4


proc fillRateBuf(st: Gimli_Block, bs: var array[gimliBlockLen, uint8]) =
  var
    i: int = 0
  i = 0
  while i < 4:
    bs[i * 4] = uint8(st[i] and 0xff)
    bs[i * 4 + 1] = uint8((st[i] shr 8) and 0xff)
    bs[i * 4 + 2] = uint8((st[i] shr 16) and 0xff)
    bs[i * 4 + 3] = uint8((st[i] shr 24) and 0xff)
    i = i + 1


proc gimliClear*(s: var GimliSpongeState) {.inline, raises: [].} =
  ## Overwrite a keyed sponge after its final output is consumed.
  secureClearPod(s)

proc gimliAbsorbInit*(s: var GimliSpongeState) =
  ## Discard a previous state before beginning a fresh absorb operation.
  gimliClear(s)
  s.st = default(Gimli_Block)
  s.bufs = default(array[gimliBlockLen, uint8])
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
  ## The repository's Gimli permutation vector is the original C reference
  ## variant. Its sponge uses byte-aligned multi-rate padding: `0x1f` at the
  ## message end and `0x80` at the rate boundary.
  s.bufs[s.l] = s.bufs[s.l] xor 0x1f'u8
  s.bufs[gimliBlockLen - 1] = s.bufs[gimliBlockLen - 1] xor 0x80'u8
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

proc absorbFramedInput(s: var GimliSpongeState, domain, ks, ns,
    ms: openArray[uint8]) =
  ## Absorb standard unkeyed input directly. Keyed calls are length-framed so
  ## `(key, nonce, message)` tuples cannot alias one another.
  var
    L: array[8, uint8]
    i: int = 0
    n: uint64 = 0
  if ks.len == 0 and ns.len == 0:
    gimliAbsorbUpdate(s, ms)
    return
  gimliAbsorbUpdate(s, domain)
  n = uint64(ks.len)
  i = 0
  while i < L.len:
    L[i] = uint8((n shr (i * 8)) and 0xff'u64)
    i = i + 1
  gimliAbsorbUpdate(s, L)
  gimliAbsorbUpdate(s, ks)
  n = uint64(ns.len)
  i = 0
  while i < L.len:
    L[i] = uint8((n shr (i * 8)) and 0xff'u64)
    i = i + 1
  gimliAbsorbUpdate(s, L)
  gimliAbsorbUpdate(s, ns)
  n = uint64(ms.len)
  i = 0
  while i < L.len:
    L[i] = uint8((n shr (i * 8)) and 0xff'u64)
    i = i + 1
  gimliAbsorbUpdate(s, L)
  gimliAbsorbUpdate(s, ms)


proc gimliXofWithDomain(ks, ns, ms, domain: openArray[uint8],
    outLen: int): ByteSeq =
  var
    s: GimliSpongeState
  defer:
    gimliClear(s)
  if outLen < 0:
    raise newException(ValueError, "gimli output length must not be negative")
  gimliAbsorbInit(s)
  absorbFramedInput(s, domain, ks, ns, ms)
  gimliAbsorbFinal(s)
  result = newSeq[uint8](outLen)
  gimliSqueezeInto(s, result)


## gimliXof: sponge output over key + nonce + message.
## ks: key bytes.
## ns: nonce bytes.
## ms: message bytes.
## outLen: output length.
proc gimliXof*(ks, ns, ms: openArray[uint8], outLen: int): ByteSeq =
  result = gimliXofWithDomain(ks, ns, ms, gimliXofDomain, outLen)


## gimliXofDiscard: absorb key/nonce/message and discard output blocks.
proc gimliXofDiscard*(ks, ns, ms: openArray[uint8], outLen: int) =
  var
    s: GimliSpongeState
    remaining: int = outLen
    chunk: array[gimliBlockLen, uint8]
    take: int = 0
  defer:
    gimliClear(s)
    secureClearBytes(chunk)
  if outLen < 0:
    raise newException(ValueError, "gimli output length must not be negative")
  gimliAbsorbInit(s)
  absorbFramedInput(s, gimliXofDomain, ks, ns, ms)
  gimliAbsorbFinal(s)
  while remaining > 0:
    take = min(remaining, chunk.len)
    gimliSqueezeInto(s, chunk.toOpenArray(0, take - 1))
    remaining = remaining - take


## gimliTag: compute a Gimli tag for key + nonce + message.
## ks: key bytes.
## ns: nonce bytes.
## ms: message bytes.
## outLen: output length.
proc gimliTag*(ks, ns, ms: openArray[uint8], outLen: int): ByteSeq =
  if ks.len != gimliKeyBytes:
    raise newException(ValueError, "gimli tag requires a 32-byte key")
  if ns.len != gimliNonceBytes:
    raise newException(ValueError, "gimli tag requires a 24-byte nonce")
  result = gimliXofWithDomain(ks, ns, ms, gimliTagDomain, outLen)


## gimliTag: compute a Gimli tag with default length.
## ks: key bytes.
## ns: nonce bytes.
## ms: message bytes.
proc gimliTag*(ks, ns, ms: openArray[uint8]): ByteSeq =
  result = gimliTag(ks, ns, ms, gimliTagLenDefault)


## gimliStreamXor: apply a Gimli-based keystream to input.
## ks: key bytes.
## ns: nonce bytes.
## input: bytes to transform.
proc gimliStreamXor*(ks, ns, input: openArray[uint8]): ByteSeq =
  var
    ksBytes: ByteSeq = @[]
    outBytes: ByteSeq = @[]
    i: int = 0
  defer:
    secureClearBytes(ksBytes)
  if ks.len != gimliKeyBytes:
    raise newException(ValueError, "gimli stream requires a 32-byte key")
  if ns.len != gimliNonceBytes:
    raise newException(ValueError, "gimli stream requires a 24-byte nonce")
  ksBytes = gimliXofWithDomain(ks, ns, @[], gimliStreamDomain, input.len)
  outBytes.setLen(input.len)
  i = 0
  while i < input.len:
    outBytes[i] = input[i] xor ksBytes[i]
    i = i + 1
  result = outBytes
