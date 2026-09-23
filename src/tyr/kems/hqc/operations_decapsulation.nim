proc hqcTyrTryDecapsInternal(v: HqcVariant, sk, ct: openArray[byte]):
    tuple[sharedSecret: seq[byte], ok: bool] {.role: {decryptor}.} =
  ## v/sk/ct: the parameter set, the secret key, the received ciphertext.
  ##
  ## Decrypt, then rebuild the ciphertext from what came out. Only an
  ## exact match yields the real shared secret; anything else yields the
  ## rejection key, with no branch anywhere between the two.
  var
    p: HqcParams = params(v)
    c = default(HqcPkeCipher)
    cPrime = default(HqcPkeCipher)
    mPrime = default(array[hqcMaxMessageBytes, byte])
    hashEk = default(array[hqcSharedSecretBytes, byte])
    kTheta = default(array[hqcSharedSecretBytes + hqcSeedBytes, byte])
    kBar = default(array[hqcSharedSecretBytes, byte])
    theta = default(array[hqcSeedBytes, byte])
    G: seq[uint16] = @[]
    W: seq[uint64] = @[]
    uBytes: seq[byte] = @[]
    vBytes: seq[byte] = @[]
    sigmaOffset: int = 0
    saltOffset: int = 0
    mismatch: byte = 0
    keepMask: byte = 0
    i: int = 0
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid HQC secret key length")
  if ct.len != p.ciphertextBytes:
    raise newException(ValueError, "invalid HQC ciphertext length")
  sigmaOffset = skSigmaOffset(p)
  saltOffset = ctSaltOffset(p)
  G = genPoly(v)
  W = newHqcMulScratch(p)
  c.u = newHqcVec(p.vecNWords)
  c.v = newHqcVec(p.vecNWords)
  cPrime.u = newHqcVec(p.vecNWords)
  cPrime.v = newHqcVec(p.vecNWords)
  unpackCiphertext(c, ct, p)
  pkeDecrypt(mPrime, sk.toOpenArray(skSeedOffset(p), sigmaOffset - 1), c, p, W)
  ## Rebuild the shared secret and the encryption randomness from what
  ## decryption produced. A wrong message gives a wrong theta, which
  ## gives a ciphertext that cannot match.
  hashH(hashEk, sk.toOpenArray(0, p.publicKeyBytes - 1))
  hashG(kTheta, hashEk, mPrime.toOpenArray(0, p.messageBytes - 1),
    ct.toOpenArray(saltOffset, saltOffset + hqcSaltBytes - 1))
  i = 0
  while i < hqcSeedBytes:
    theta[i] = kTheta[hqcSharedSecretBytes + i]
    i = i + 1
  pkeEncrypt(cPrime, sk.toOpenArray(0, p.publicKeyBytes - 1),
    mPrime.toOpenArray(0, p.messageBytes - 1), theta, p, G, W)
  uBytes = hqcVecToByteSeq(cPrime.u, p.vecNBytes)
  vBytes = hqcVecToByteSeq(cPrime.v, p.vecN1n2Bytes)
  ## The rejection key. It is built whether or not it is needed, so the
  ## work done never depends on whether the ciphertext was valid.
  hashJ(kBar, hashEk, sk.toOpenArray(sigmaOffset, sigmaOffset + p.messageBytes - 1),
    ct.toOpenArray(0, p.vecNBytes - 1),
    ct.toOpenArray(p.vecNBytes, saltOffset - 1),
    ct.toOpenArray(saltOffset, saltOffset + hqcSaltBytes - 1))
  mismatch = hqcVecCompare(ct, uBytes, p.vecNBytes)
  mismatch = mismatch or hqcVecCompare(ct.toOpenArray(p.vecNBytes, saltOffset - 1),
    vBytes, p.vecN1n2Bytes)
  ## keepMask is 0xff when everything matched and 0x00 when it did not.
  keepMask = mismatch - 1'u8
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  i = 0
  while i < p.sharedSecretBytes:
    result.sharedSecret[i] = (kTheta[i] and keepMask) or
      (kBar[i] and (not keepMask))
    i = i + 1
  result.ok = mismatch == 0'u8
  ## The rebuilt ciphertext comes from m'; for a forged ciphertext it is
  ## not public, so it goes with the rest.
  hqcWipeWords(cPrime.u)
  hqcWipeWords(cPrime.v)
  hqcWipeBytes(uBytes)
  hqcWipeBytes(vBytes)
  hqcWipeBytes(mPrime)
  hqcWipeBytes(kTheta)
  hqcWipeBytes(kBar)
  hqcWipeBytes(theta)
  hqcWipeWords(W)

