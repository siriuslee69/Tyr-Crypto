## ---------------------------------------------------------------------
## | HQC Parsing <- where every byte of a key or ciphertext lives       |
## ---------------------------------------------------------------------
##
## The three byte strings HQC puts on the wire are plain concatenations
## with no lengths, tags or padding. Each field starts where the last one
## ended, so one wrong offset silently reads the wrong thing. That is why
## every offset is computed here, once, from the parameter record.
##
##   public key   [ seed_ek 32 ][ s                                    ]
##                0            32                     32 + vecNBytes
##
##   secret key   [ public key ][ seed_dk 32 ][ sigma ][ seed_kem 32   ]
##                0          pkBytes      +32      +msgBytes      +32
##
##   ciphertext   [ u          ][ v                 ][ salt 16        ]
##                0        vecNBytes    +vecN1n2Bytes           +16
##
## `seed_kem` is the seed the whole key grew from. It is kept so a holder
## can regenerate the key, and decapsulation never reads it.
##
## Reference: [HQC-20250822] key and ciphertext encoding; ported from the
## reference implementation's `parsing.c` and `kem.c`.

import runePragmas
import ./params
import ./types
import ./util

## Reference: [HQC-20250822] decapsulation key layout; offset of the secret seed for `skSeedOffset`; pitfall: the public key is repeated in front of it, so the offset is not zero.
proc skSeedOffset*(p: HqcParams): int {.inline, role: {parser}, raises: [].} =
  ## p: the parameter set.
  ## Where `seed_dk`, the 32 bytes the secret grows from, starts.
  result = p.publicKeyBytes

## Reference: [HQC-20250822] decapsulation key layout; offset of the rejection secret for `skSigmaOffset`; pitfall: sigma is `messageBytes` long, not a fixed 32.
proc skSigmaOffset*(p: HqcParams): int {.inline, role: {parser}, raises: [].} =
  ## p: the parameter set.
  ## Where `sigma`, the rejection secret, starts.
  result = p.publicKeyBytes + hqcSeedBytes

## Reference: [HQC-20250822] ciphertext layout; offset of the salt for `ctSaltOffset`; pitfall: the salt sits after both ciphertext halves, not between them.
proc ctSaltOffset*(p: HqcParams): int {.inline, role: {parser}, raises: [].} =
  ## p: the parameter set.
  ## Where the 16 salt bytes start.
  result = p.vecNBytes + p.vecN1n2Bytes

## Reference: [HQC-20250822] decapsulation key layout; secret key assembly for `packSecretKey`; pitfall: every one of the four pieces has its own length, and a wrong one shifts all that follow.
proc packSecretKey*(dst: var openArray[byte], ek, dkPke, sigma,
    seedKem: openArray[byte], p: HqcParams) {.role: {dataWriter}, raises: [].} =
  ## dst/ek/dkPke/sigma/seedKem/p: the secret key bytes, the public key,
  ## the 32-byte secret seed, the rejection secret, the seed the whole
  ## key grew from, and the parameter set.
  var
    i: int = 0
  while i < p.publicKeyBytes:
    dst[i] = ek[i]
    i = i + 1
  i = 0
  while i < hqcSeedBytes:
    dst[skSeedOffset(p) + i] = dkPke[i]
    i = i + 1
  i = 0
  while i < p.messageBytes:
    dst[skSigmaOffset(p) + i] = sigma[i]
    i = i + 1
  i = 0
  while i < hqcSeedBytes:
    dst[skSigmaOffset(p) + p.messageBytes + i] = seedKem[i]
    i = i + 1

## Reference: [HQC-20250822] ciphertext layout; ciphertext assembly for `packCiphertext`; pitfall: `u` is `vecNBytes` long and `v` is `vecN1n2Bytes`, and the two differ.
proc packCiphertext*(dst: var openArray[byte], c: HqcPkeCipher,
    salt: openArray[byte], p: HqcParams) {.role: {dataWriter}, raises: [].} =
  ## dst/c/salt/p: the ciphertext bytes, the two halves as bit strings,
  ## the salt, and the parameter set.
  var
    i: int = 0
  hqcWordsToBytes(dst, c.u, p.vecNBytes)
  i = 0
  while i < p.vecN1n2Bytes:
    dst[p.vecNBytes + i] = byte((c.v[i shr 3] shr (8 * (i and 7))) and 0xff'u64)
    i = i + 1
  i = 0
  while i < hqcSaltBytes:
    dst[ctSaltOffset(p) + i] = salt[i]
    i = i + 1

## Reference: [HQC-20250822] ciphertext layout; ciphertext reading for `unpackCiphertext`; pitfall: the spare bits above `n` are deliberately NOT masked, so a ciphertext that sets them fails the re-encryption check instead of being quietly accepted.
proc unpackCiphertext*(c: var HqcPkeCipher, ct: openArray[byte], p: HqcParams)
    {.role: {parser}, raises: [].} =
  ## c/ct/p: the two halves to fill, the received bytes, the parameters.
  hqcBytesToWords(c.u, ct, 0, p.vecNBytes)
  hqcBytesToWords(c.v, ct, p.vecNBytes, p.vecN1n2Bytes)
