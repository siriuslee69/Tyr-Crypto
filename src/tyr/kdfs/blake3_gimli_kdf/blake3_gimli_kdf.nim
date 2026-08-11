## ----------------------------------------------------------------------
## BLAKE3+Gimli KDF <- block-oriented mixed-stream derivation helpers
## ----------------------------------------------------------------------

import ../../hashes/blake3
import ../../ciphers/gimli_sponge
import ../../helpers/secure_memory

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


proc appendLe64(B: var seq[uint8], v: uint64) =
  ## B: destination bytes.
  ## v: little-endian value.
  var
    i: int = 0
  while i < 8:
    B.add(uint8((v shr (i * 8)) and 0xff'u64))
    i = i + 1


proc appendBytes(B: var seq[uint8], A: openArray[uint8]) =
  ## B: destination bytes.
  ## A: source bytes.
  var
    i: int = 0
  while i < A.len:
    B.add(A[i])
    i = i + 1


proc appendFramedText(B: var seq[uint8], s: string) =
  ## Prefix text with its byte length so adjacent fields cannot alias.
  appendLe64(B, uint64(s.len))
  appendText(B, s)


proc appendFramedBytes(B: var seq[uint8], A: openArray[uint8]) =
  ## Prefix bytes with their length so salt/secret boundaries are unique.
  appendLe64(B, uint64(A.len))
  appendBytes(B, A)


proc validateConfig(cfg: Blake3GimliKdfConfig) =
  if cfg.keyBytes <= 0:
    raise newException(ValueError, "BLAKE3+Gimli KDF key bytes must be positive")
  if cfg.nonceBytes != gimliNonceBytes:
    raise newException(ValueError, "BLAKE3+Gimli KDF nonce must be 24 bytes")


proc checkedProduct(a, b: int, label: string): int =
  if a < 0 or b < 0 or (b != 0 and a > high(int) div b):
    raise newException(ValueError, label & " is too large")
  result = a * b


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
  if nonceBytes != gimliNonceBytes:
    raise newException(ValueError, "BLAKE3+Gimli KDF nonce must be 24 bytes")
  result.keyBytes = keyBytes
  result.nonceBytes = nonceBytes


proc deriveBlake3GimliNonce*(material: openArray[uint8],
    nonceLabel: string = "tyr.blake3-gimli.kdf.nonce.v1",
    cfg: Blake3GimliKdfConfig = initBlake3GimliKdfConfig()): seq[uint8] =
  ## material: secret derivation context bytes.
  ## nonceLabel: domain-separated nonce derivation label.
  ## cfg: KDF size configuration.
  validateConfig(cfg)
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
    lastBlock: int = 0
    i: int = 0
  defer:
    secureClearBytes(material)
    secureClearBytes(root)
    secureClearBytes(nonce)
    secureClearBytes(blakeStream)
    secureClearBytes(gimliStream)
    secureClearBytes(mixedStream)
  validateConfig(cfg)
  if firstBlock < 1 or blockCount < 1:
    raise newException(ValueError, "invalid KDF block range")
  if firstBlock > high(int) - (blockCount - 1):
    raise newException(ValueError, "KDF block range is too large")
  lastBlock = firstBlock + blockCount - 1
  if uint64(firstBlock) > uint64(high(uint32)) or
      uint64(blockCount) > uint64(high(uint32)):
    raise newException(ValueError, "KDF block range exceeds its encoding")
  appendFramedText(material, domain)
  appendLe32(material, uint32(firstBlock))
  appendLe32(material, uint32(blockCount))
  appendFramedBytes(material, salt)
  appendFramedBytes(material, secret)
  root = blake3DeriveKey(domain & ".root", material,
    blake3GimliKdfKeyBytes)
  nonce = deriveBlake3GimliNonce(material, nonceLabel, cfg)
  totalLen = checkedProduct(lastBlock, cfg.keyBytes, "KDF output range")
  blakeStream = blake3KeyedHash(root, material, totalLen)
  gimliStream = gimliXof(root, nonce, material, totalLen)
  mixedStream = newSeq[uint8](totalLen)
  while i < totalLen:
    mixedStream[i] = blakeStream[i] xor gimliStream[i]
    i = i + 1
  outStart = checkedProduct(firstBlock - 1, cfg.keyBytes, "KDF output offset")
  outLen = checkedProduct(blockCount, cfg.keyBytes, "KDF output length")
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
  defer:
    secureClearBytes(material)
    secureClearBytes(nonce)
    secureClearBytes(root)
    secureClearBytes(mix)
    secureClearBytes(finalMaterial)
  validateConfig(cfg)
  if stage < 1:
    raise newException(ValueError, "invalid stage")
  if uint64(stage) > uint64(high(uint32)):
    raise newException(ValueError, "stage exceeds its encoding")
  appendFramedText(material, stageInputLabel)
  appendLe32(material, uint32(stage))
  appendFramedBytes(material, salt)
  appendFramedBytes(material, secret)
  root = blake3DeriveKey(rootLabel, material,
    blake3GimliKdfKeyBytes)
  nonce = deriveBlake3GimliNonce(material, nonceLabel, cfg)
  mix = gimliXof(root, nonce, material, cfg.keyBytes)
  appendFramedText(finalMaterial, finalLabel)
  appendLe32(finalMaterial, uint32(stage))
  appendFramedBytes(finalMaterial, salt)
  appendFramedBytes(finalMaterial, mix)
  result = blake3KeyedHash(root, finalMaterial, cfg.keyBytes)
