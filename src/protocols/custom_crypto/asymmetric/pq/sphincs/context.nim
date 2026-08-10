## -------------------------------------------------------
## SPHINCS Context <- public/secret seed context container
## -------------------------------------------------------

import ./params
import ./util

type
  SphincsCtx* = object
    pubSeed*: array[spxN, byte]
    skSeed*: array[spxN, byte]

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `initCtx`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc initCtx*(ctx: var SphincsCtx, pkSeed, skSeed: openArray[byte]) =
  copyMem(addr ctx.pubSeed[0], unsafeAddr pkSeed[0], spxN)
  copyMem(addr ctx.skSeed[0], unsafeAddr skSeed[0], spxN)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `clearCtx`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearCtx*(ctx: var SphincsCtx) {.raises: [].} =
  ## Keep the secret seed context wipe explicit so signing/keygen call sites
  ## do not leave raw key material in reusable stack memory.
  clearSensitivePlainData(ctx)
