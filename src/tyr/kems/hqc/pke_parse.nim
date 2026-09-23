## Reference: [HQC-20250822] encryption key parsing; public-key expansion for `ekFromString`; pitfall: `h` is never stored, only the 32-byte seed it grows from.
proc ekFromString(h, s: var HqcVec, ek: openArray[byte], p: HqcParams)
    {.role: {parser}, raises: [ValueError].} =
  ## h/s/ek/p: the two halves of the public key, its bytes, the parameters.
  ##
  ## Only `s` travels as data. `h` is regrown from the 32-byte seed that
  ## sits in front of it, which is why the public key is barely longer
  ## than one bit string instead of two.
  var
    X = default(HqcXof)
    i: int = 0
  xofInit(X, ek.toOpenArray(0, hqcSeedBytes - 1))
  vecSetRandom(h, X, p)
  xofClear(X)
  i = 0
  while i < p.vecNWords:
    s[i] = 0'u64
    i = i + 1
  hqcBytesToWords(s, ek, hqcSeedBytes, p.vecNBytes)

## Reference: [HQC-20250822] decryption key parsing; secret expansion for `dkFromString`; pitfall: this must draw the SAME first fixed-weight vector that key generation drew, so the sampler and its order cannot change.
proc dkFromString(y: var HqcVec, dk: openArray[byte], p: HqcParams)
    {.role: {parser}, raises: [ValueError].} =
  ## y/dk/p: the recovered secret vector, its bytes, and the parameters.
  ## Regrow the secret `y` from the seed key generation kept.
  var
    X = default(HqcXof)
    i: int = 0
  i = 0
  while i < p.vecNWords:
    y[i] = 0'u64
    i = i + 1
  xofInit(X, dk.toOpenArray(0, hqcSeedBytes - 1))
  sampleFixedWeightKey(y, X, p.omega, p)
  xofClear(X)
