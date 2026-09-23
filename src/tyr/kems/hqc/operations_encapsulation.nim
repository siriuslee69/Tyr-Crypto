proc hqcTyrEncapsDerand*(v: HqcVariant, pk: openArray[byte],
    randomness: openArray[byte]): HqcTyrCipher
    {.role: {encryptor}, otterTrace.} =
  ## v/pk/randomness: the parameter set, the recipient's public key, and
  ## exactly `messageBytes + 16` bytes of randomness.
  ## Encapsulate with caller-supplied randomness, for tests and vectors.
  var
    p: HqcParams = params(v)
    c = default(HqcPkeCipher)
    m = default(array[hqcMaxMessageBytes, byte])
    salt = default(array[hqcSaltBytes, byte])
    hashEk = default(array[hqcSharedSecretBytes, byte])
    kTheta = default(array[hqcSharedSecretBytes + hqcSeedBytes, byte])
    theta = default(array[hqcSeedBytes, byte])
    G: seq[uint16] = @[]
    W: seq[uint64] = @[]
    i: int = 0
  if pk.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid HQC public key length")
  if randomness.len != p.encapsRandomBytes:
    raise newException(ValueError,
      "HQC encaps randomness must be " & $p.encapsRandomBytes & " bytes")
  i = 0
  while i < p.messageBytes:
    m[i] = randomness[i]
    i = i + 1
  i = 0
  while i < hqcSaltBytes:
    salt[i] = randomness[p.messageBytes + i]
    i = i + 1
  G = genPoly(v)
  W = newHqcMulScratch(p)
  c.u = newHqcVec(p.vecNWords)
  c.v = newHqcVec(p.vecNWords)
  ## K and theta both come out of one hash, so the shared secret and the
  ## ciphertext are locked to each other.
  hashH(hashEk, pk)
  hashG(kTheta, hashEk, m.toOpenArray(0, p.messageBytes - 1), salt)
  i = 0
  while i < hqcSeedBytes:
    theta[i] = kTheta[hqcSharedSecretBytes + i]
    i = i + 1
  pkeEncrypt(c, pk, m.toOpenArray(0, p.messageBytes - 1), theta, p, G, W)
  result.variant = v
  result.ciphertext = newSeq[byte](p.ciphertextBytes)
  packCiphertext(result.ciphertext, c, salt, p)
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  i = 0
  while i < p.sharedSecretBytes:
    result.sharedSecret[i] = kTheta[i]
    i = i + 1
  hqcWipeBytes(m)
  hqcWipeBytes(kTheta)
  hqcWipeBytes(theta)
  hqcWipeWords(W)

## Reference: [HQC-20250822] HQC.KEM encapsulation; encapsulation entry point for `hqcTyrEncaps`; pitfall: an empty seed must reach for system entropy, never for a default value.
proc hqcTyrEncaps*(v: HqcVariant, pk: openArray[byte],
    randomness: seq[byte] = @[]): HqcTyrCipher
    {.role: {encryptor}, otterTrace.} =
  ## v/pk/randomness: the parameter set, the recipient's public key, and
  ## optionally exactly `messageBytes + 16` bytes of fixed randomness.
  var
    p: HqcParams = params(v)
    material: seq[byte] = @[]
  if randomness.len > 0 and randomness.len != p.encapsRandomBytes:
    raise newException(ValueError,
      "HQC seeded encaps requires " & $p.encapsRandomBytes & " bytes")
  if randomness.len == 0:
    material = cryptoRandomBytes(p.encapsRandomBytes)
  else:
    material = randomness
  result = hqcTyrEncapsDerand(v, pk, material)
  hqcWipeBytes(material)

## Reference: [HQC-20250822] HQC.KEM decapsulation; implicit rejection for `hqcTyrTryDecapsInternal`; pitfall: the `ok` flag is diagnostic only, and exposing it to a peer turns decapsulation into a ciphertext-validity oracle.

