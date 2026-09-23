## Reference: [HQC-20250822] HQC.KEM decapsulation; decapsulation entry point for `hqcTyrDecaps`; pitfall: callers must consume the returned secret uniformly, because a rejected ciphertext also returns 32 plausible bytes.
proc hqcTyrDecaps*(v: HqcVariant, sk, ct: openArray[byte]): seq[byte]
    {.role: {decryptor}, otterTrace.} =
  ## v/sk/ct: the parameter set, your secret key, the ciphertext received.
  ## Recover the shared secret. A damaged or forged ciphertext yields a
  ## different but equally normal-looking secret rather than an error.
  result = hqcTyrTryDecapsInternal(v, sk, ct).sharedSecret

when defined(tyrCryptoTestHooks):
  ## Reference: [HQC-20250822] HQC.KEM decapsulation; test-only validity flag for `hqcTyrTryDecaps`; pitfall: this must stay behind a build flag so no shipped build can expose the oracle.
  proc hqcTyrTryDecaps*(v: HqcVariant, sk, ct: openArray[byte]):
      tuple[sharedSecret: seq[byte], ok: bool] =
    ## v/sk/ct: the parameter set, the secret key, the ciphertext.
    ## Test-only view of whether the ciphertext was genuine.
    result = hqcTyrTryDecapsInternal(v, sk, ct)

