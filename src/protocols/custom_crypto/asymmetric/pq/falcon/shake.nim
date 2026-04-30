## --------------------------------------------------------
## Falcon Shake <- stateful SHAKE256 reader for Falcon
## --------------------------------------------------------

import ../../../sha3
import ./util

type
  FalconShake256* = object
    state*: Sha3State
    squeezeBlock*: array[shake256RateBytes, byte]
    pos*: int
    initialized*: bool

proc initFalconShake256*(ctx: var FalconShake256, A: openArray[byte]) =
  clearPlainData(ctx)
  shake256AbsorbOnce(ctx.state, A)
  shake256SqueezeBlocksIntoUnchecked(ctx.state, ctx.squeezeBlock)
  ctx.pos = 0
  ctx.initialized = true

proc initFalconShake256*(ctx: var FalconShake256, A0, A1: openArray[byte]) =
  var msg: seq[byte] = @[]
  appendBytes(msg, A0)
  appendBytes(msg, A1)
  initFalconShake256(ctx, msg)
  secureClearBytes(msg)

proc initFalconShake256*(ctx: var FalconShake256, A0, A1, A2: openArray[byte]) =
  var msg: seq[byte] = @[]
  appendBytes(msg, A0)
  appendBytes(msg, A1)
  appendBytes(msg, A2)
  initFalconShake256(ctx, msg)
  secureClearBytes(msg)

proc extractFalconShake256*(ctx: var FalconShake256, dst: var openArray[byte]) =
  var
    produced: int = 0
    take: int = 0
  if not ctx.initialized:
    raise newException(ValueError, "Falcon SHAKE reader is not initialized")
  while produced < dst.len:
    if ctx.pos == shake256RateBytes:
      shake256SqueezeBlocksIntoUnchecked(ctx.state, ctx.squeezeBlock)
      ctx.pos = 0
    take = shake256RateBytes - ctx.pos
    if take > dst.len - produced:
      take = dst.len - produced
    copyMem(addr dst[produced], addr ctx.squeezeBlock[ctx.pos], take)
    produced = produced + take
    ctx.pos = ctx.pos + take
