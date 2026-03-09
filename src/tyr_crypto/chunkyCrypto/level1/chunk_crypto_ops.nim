## ============================================================
## | ChunkyCrypto Chunk Ops <- per-buffer crypto pipeline     |
## ============================================================

import ../../custom_crypto/xchacha20
import ../../custom_crypto/aes_ctr
import ../../custom_crypto/gimli_sponge

const
  xchachaBlockLen = 64

type
  ChunkCryptoState* = object
    ## keyXs: XChaCha20 key bytes.
    keyXs: array[32, uint8]
    ## ns: chunk nonce bytes.
    ns: array[24, uint8]
    ## xCounter: XChaCha20 block counter.
    xCounter: uint32
    ## aes: AES-CTR streaming state.
    aes: AesCtrState
    ## gStream: Gimli keystream sponge.
    gStream: GimliSpongeState
    ## gTag: Gimli tag sponge.
    gTag: GimliSpongeState
    ## streamBufs: reusable keystream buffer.
    streamBufs: seq[uint8]

proc blocksForLen(l, b: int): uint32 =
  ## l: byte length.
  ## b: block size.
  var
    t: int = 0
  if l <= 0:
    return 0'u32
  t = (l + b - 1) div b
  result = uint32(t)

proc deriveAesNonce(ns: array[24, uint8]): array[16, uint8] =
  var
    rs: array[16, uint8]
    i: int = 0
  i = 0
  while i < rs.len:
    rs[i] = ns[i]
    i = i + 1
  result = rs

proc initGimliStream(s: var GimliSpongeState, ks: array[32, uint8],
    ns: array[24, uint8]) =
  gimliAbsorbInit(s)
  gimliAbsorbUpdate(s, ks)
  gimliAbsorbUpdate(s, ns)
  gimliAbsorbFinal(s)

proc initGimliTag(s: var GimliSpongeState, ks: array[32, uint8],
    ns: array[24, uint8]) =
  gimliAbsorbInit(s)
  gimliAbsorbUpdate(s, ks)
  gimliAbsorbUpdate(s, ns)

proc ensureStreamBuf(s: var ChunkCryptoState, l: int) =
  if s.streamBufs.len < l:
    s.streamBufs.setLen(l)

proc gimliStreamXorInPlace(s: var ChunkCryptoState, bs: var openArray[uint8]) =
  var
    l: int = 0
    i: int = 0
  l = bs.len
  if l == 0:
    return
  ensureStreamBuf(s, l)
  gimliSqueezeInto(s.gStream, s.streamBufs.toOpenArray(0, l - 1))
  i = 0
  while i < l:
    bs[i] = bs[i] xor s.streamBufs[i]
    i = i + 1

proc initChunkCryptoState*(s: var ChunkCryptoState, kxs, kas,
    kgs: array[32, uint8], ns: array[24, uint8], b: int) =
  ## kxs: XChaCha20 key.
  ## kas: AES-CTR key.
  ## kgs: Gimli key.
  ## ns: chunk nonce.
  ## b: buffer size for keystream reuse.
  var
    aesNonce: array[16, uint8]
  s.keyXs = kxs
  s.ns = ns
  s.xCounter = 0'u32
  aesNonce = deriveAesNonce(ns)
  s.aes = initAesCtrState(kas, aesNonce)
  initGimliStream(s.gStream, kgs, ns)
  initGimliTag(s.gTag, kgs, ns)
  if b > 0:
    s.streamBufs.setLen(b)
  else:
    s.streamBufs.setLen(0)

proc encryptChunkBuffer*(s: var ChunkCryptoState, bs: var openArray[uint8]) =
  ## bs: plaintext buffer (in-place transformed to ciphertext).
  var
    l: int = 0
    blocks: uint32 = 0
  l = bs.len
  if l == 0:
    return
  xchacha20XorInPlace(s.keyXs, s.ns, s.xCounter, bs)
  blocks = blocksForLen(l, xchachaBlockLen)
  s.xCounter = s.xCounter + blocks
  aesCtrXorInPlace(s.aes, bs, acbAuto)
  gimliStreamXorInPlace(s, bs)
  gimliAbsorbUpdate(s.gTag, bs)

proc decryptChunkBuffer*(s: var ChunkCryptoState, bs: var openArray[uint8]) =
  ## bs: ciphertext buffer (in-place transformed to plaintext).
  var
    l: int = 0
    blocks: uint32 = 0
  l = bs.len
  if l == 0:
    return
  gimliAbsorbUpdate(s.gTag, bs)
  gimliStreamXorInPlace(s, bs)
  aesCtrXorInPlace(s.aes, bs, acbAuto)
  xchacha20XorInPlace(s.keyXs, s.ns, s.xCounter, bs)
  blocks = blocksForLen(l, xchachaBlockLen)
  s.xCounter = s.xCounter + blocks

proc finalizeChunkTag*(s: var ChunkCryptoState, ts: var openArray[uint8]) =
  ## ts: output tag buffer.
  gimliAbsorbFinal(s.gTag)
  gimliSqueezeInto(s.gTag, ts)
