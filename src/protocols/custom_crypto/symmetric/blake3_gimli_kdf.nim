## ----------------------------------------------------------------------
## BLAKE3+Gimli KDF <- block-oriented mixed-stream derivation helpers
## ----------------------------------------------------------------------

import ./blake3/blake3
import ./gimli/gimli_sponge

const
  blake3GimliKdfKeyBytes* = 32
  blake3GimliKdfNonceBytes* = 24

type
  Blake3GimliKdfConfig* = object
    ## keyBytes: output bytes per logical block.
    keyBytes*: int
    ## nonceBytes: fixed nonce bytes for Gimli expansion.
    nonceBytes*: int


proc appendText(B: var seq[uint8], s: string) =
  ## B: destination bytes.
  ## s: ASCII/UTF-8 text to append.
  var
    i: int = 0
  while i < s.len:
    B.add(uint8(ord(s[i])))
    i = i + 1


proc appendLe32(B: var seq[uint8], v: uint32) =
  ## B: destination bytes.
  ## v: little-endian value.
  B.add(uint8(v and 0xff'u32))
  B.add(uint8((v shr 8) and 0xff'u32))
  B.add(uint8((v shr 16) and 0xff'u32))
  B.add(uint8((v shr 24) and 0xff'u32))


proc appendBytes(B: var seq[uint8], A: openArray[uint8]) =
  ## B: destination bytes.
  ## A: source bytes.
  var
    i: int = 0
  while i < A.len:
    B.add(A[i])
    i = i + 1


proc sliceBytes(A: openArray[uint8], first, n: int): seq[uint8] =
  ## A: source bytes.
  ## first/n: start offset and number of bytes.
  var
    i: int = 0
  result = newSeq[uint8](n)
  while i < n:
    result[i] = A[first + i]
    i = i + 1


proc initBlake3GimliKdfConfig*(keyBytes: int = blake3GimliKdfKeyBytes,
    nonceBytes: int = blake3GimliKdfNonceBytes): Blake3GimliKdfConfig =
  ## keyBytes: output bytes per logical block.
  ## nonceBytes: fixed nonce bytes for Gimli expansion.
  if keyBytes <= 0:
    raise newException(ValueError, "BLAKE3+Gimli KDF key bytes must be positive")
  if nonceBytes <= 0:
    raise newException(ValueError, "BLAKE3+Gimli KDF nonce bytes must be positive")
  result.keyBytes = keyBytes
  result.nonceBytes = nonceBytes


proc deriveBlake3GimliNonce*(material: openArray[uint8],
    nonceLabel: string = "tyr.blake3-gimli.kdf.nonce.v1",
    cfg: Blake3GimliKdfConfig = initBlake3GimliKdfConfig()): seq[uint8] =
  ## material: secret derivation context bytes.
  ## nonceLabel: domain-separated nonce derivation label.
  ## cfg: KDF size configuration.
  result = blake3DeriveKey(nonceLabel, material,
    cfg.nonceBytes)


proc deriveBlake3GimliBlocks*(domain: string, secret, salt: openArray[uint8],
    firstBlock, blockCount: int,
    nonceLabel: string = "tyr.blake3-gimli.kdf.nonce.v1",
    cfg: Blake3GimliKdfConfig = initBlake3GimliKdfConfig()): seq[uint8] =
  ## domain/secret/salt: domain-separated KDF inputs.
  ## firstBlock/blockCount: one-indexed logical block range.
  ## nonceLabel: domain-separated nonce derivation label.
  ## cfg: KDF size configuration.
  var
    material: seq[uint8] = @[]
    root: seq[uint8] = @[]
    nonce: seq[uint8] = @[]
    blakeStream: seq[uint8] = @[]
    gimliStream: seq[uint8] = @[]
    mixedStream: seq[uint8] = @[]
    outStart: int = 0
    outLen: int = 0
    totalLen: int = 0
    i: int = 0
  if firstBlock < 1 or blockCount < 1:
    raise newException(ValueError, "invalid KDF block range")
  appendText(material, domain)
  appendLe32(material, uint32(firstBlock))
  appendLe32(material, uint32(blockCount))
  appendBytes(material, salt)
  appendBytes(material, secret)
  root = blake3DeriveKey(domain & ".root", material, cfg.keyBytes)
  nonce = deriveBlake3GimliNonce(material, nonceLabel, cfg)
  totalLen = (firstBlock + blockCount - 1) * cfg.keyBytes
  blakeStream = blake3KeyedHash(root, material, totalLen)
  gimliStream = gimliXof(root, nonce, material, totalLen)
  mixedStream = newSeq[uint8](totalLen)
  while i < totalLen:
    mixedStream[i] = blakeStream[i] xor gimliStream[i]
    i = i + 1
  outStart = (firstBlock - 1) * cfg.keyBytes
  outLen = blockCount * cfg.keyBytes
  result = sliceBytes(mixedStream, outStart, outLen)


proc deriveBlake3GimliStageKey*(secret, salt: openArray[uint8], stage: int,
    stageInputLabel: string = "tyr.stage.secret.v1",
    rootLabel: string = "tyr.blake3-gimli.stage.root.v1",
    finalLabel: string = "tyr.stage.key.v1",
    nonceLabel: string = "tyr.blake3-gimli.kdf.nonce.v1",
    cfg: Blake3GimliKdfConfig = initBlake3GimliKdfConfig()): seq[uint8] =
  ## secret/salt/stage: cumulative stage secret and profile salt.
  ## stageInputLabel/rootLabel/finalLabel/nonceLabel: domain-separated labels.
  ## cfg: KDF size configuration.
  var
    material: seq[uint8] = @[]
    nonce: seq[uint8] = @[]
    root: seq[uint8] = @[]
    mix: seq[uint8] = @[]
    finalMaterial: seq[uint8] = @[]
  if stage < 1:
    raise newException(ValueError, "invalid stage")
  appendText(material, stageInputLabel)
  appendLe32(material, uint32(stage))
  appendBytes(material, salt)
  appendBytes(material, secret)
  root = blake3DeriveKey(rootLabel, material,
    cfg.keyBytes)
  nonce = deriveBlake3GimliNonce(material, nonceLabel, cfg)
  mix = gimliXof(root, nonce, material, cfg.keyBytes)
  appendText(finalMaterial, finalLabel)
  appendLe32(finalMaterial, uint32(stage))
  appendBytes(finalMaterial, salt)
  appendBytes(finalMaterial, mix)
  result = blake3KeyedHash(root, finalMaterial, cfg.keyBytes)
