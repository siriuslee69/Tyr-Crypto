## -------------------------------------------------------
## SPHINCS Context <- public/secret seed context container
## -------------------------------------------------------

import ./params
import ./util

type
  SphincsCtx* = object
    pubSeed*: array[spxN, byte]
    skSeed*: array[spxN, byte]

proc initCtx*(ctx: var SphincsCtx, pkSeed, skSeed: openArray[byte]) =
  copyMem(addr ctx.pubSeed[0], unsafeAddr pkSeed[0], spxN)
  copyMem(addr ctx.skSeed[0], unsafeAddr skSeed[0], spxN)

proc clearCtx*(ctx: var SphincsCtx) {.raises: [].} =
  ## Keep the secret seed context wipe explicit so signing/keygen call sites
  ## do not leave raw key material in reusable stack memory.
  clearSensitivePlainData(ctx)
