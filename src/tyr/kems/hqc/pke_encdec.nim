proc pkeEncrypt*(c: var HqcPkeCipher, ek: openArray[byte], m: openArray[byte],
    theta: openArray[byte], p: HqcParams, G: openArray[uint16],
    W: var seq[uint64]) {.role: {encryptor}, raises: [ValueError].} =
  ## c/ek/m/theta/p/G/W: the ciphertext, the public key, the message
  ## bytes, the 32-byte encryption seed, the parameter set, the
  ## Reed-Solomon generator, and multiplication scratch.
  ##
  ## `theta` fixes every random choice here, so the same inputs always
  ## give the same ciphertext. Decapsulation relies on that to check a
  ## ciphertext by rebuilding it.
  var
    X = default(HqcXof)
    h: HqcVec = @[]
    s: HqcVec = @[]
    r1: HqcVec = @[]
    r2: HqcVec = @[]
    e: HqcVec = @[]
    tmp: HqcVec = @[]
  h = newHqcVec(p.vecNWords)
  s = newHqcVec(p.vecNWords)
  r1 = newHqcVec(p.vecNWords)
  r2 = newHqcVec(p.vecNWords)
  e = newHqcVec(p.vecNWords)
  tmp = newHqcVec(p.vecNWords)
  xofInit(X, theta)
  ekFromString(h, s, ek, p)
  sampleFixedWeightEnc(r2, X, p.omegaR, p)
  sampleFixedWeightEnc(e, X, p.omegaE, p)
  sampleFixedWeightEnc(r1, X, p.omegaR, p)
  xofClear(X)
  ## u = r1 + r2*h
  vecMul(c.u, r2, h, p, W)
  hqcVecAdd(c.u, r1, c.u, p.vecNWords)
  ## v = codeword(m) + Truncate(r2*s + e)
  codeEncode(c.v, m, p, G)
  vecMul(tmp, r2, s, p, W)
  hqcVecAdd(tmp, e, tmp, p.vecNWords)
  hqcVecTruncate(tmp, p)
  hqcVecAdd(c.v, c.v, tmp, p.vecN1n2Words)
  hqcWipeWords(r1)
  hqcWipeWords(r2)
  hqcWipeWords(e)
  hqcWipeWords(tmp)

## Reference: [HQC-20250822] HQC.PKE decryption; message recovery for `pkeDecrypt`; pitfall: decoding never reports failure, so the caller must decide validity by re-encrypting.
proc pkeDecrypt*(m: var openArray[byte], dk: openArray[byte],
    c: HqcPkeCipher, p: HqcParams, W: var seq[uint64])
    {.role: {decryptor}, raises: [ValueError].} =
  ## m/dk/c/p/W: the recovered message bytes, the 32-byte secret seed, the
  ## ciphertext, the parameter set, and multiplication scratch.
  ##
  ## v - Truncate(u*y) is the codeword plus sparse noise. The concatenated
  ## code strips the noise. If there was too much noise the result is
  ## simply the wrong message - it is the KEM layer above that notices.
  var
    y: HqcVec = @[]
    tmp1: HqcVec = @[]
    tmp2: HqcVec = @[]
  y = newHqcVec(p.vecNWords)
  tmp1 = newHqcVec(p.vecNWords)
  tmp2 = newHqcVec(p.vecNWords)
  dkFromString(y, dk, p)
  vecMul(tmp1, y, c.u, p, W)
  hqcVecTruncate(tmp1, p)
  hqcVecAdd(tmp2, c.v, tmp1, p.vecN1n2Words)
  codeDecode(m, tmp2, p)
  hqcWipeWords(y)
  hqcWipeWords(tmp1)
  hqcWipeWords(tmp2)

