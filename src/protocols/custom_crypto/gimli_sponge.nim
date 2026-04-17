## -----------------------------------------------------
## Gimli Sponge <- compatibility facade to gimli folder
## -----------------------------------------------------

import ./gimli/gimli_sponge

export gimli_sponge

proc gimliTyrXof*(ks, ns, ms: openArray[uint8], outLen: int): seq[uint8] =
  ## Tyr-suffixed alias for the local Gimli XOF.
  result = gimliXof(ks, ns, ms, outLen)

proc gimliTyrTag*(ks, ns, ms: openArray[uint8], outLen: int): seq[uint8] =
  ## Tyr-suffixed alias for the local Gimli tag helper.
  result = gimliTag(ks, ns, ms, outLen)

proc gimliTyrStreamXor*(ks, ns, input: openArray[uint8]): seq[uint8] =
  ## Tyr-suffixed alias for the local Gimli stream-xor helper.
  result = gimliStreamXor(ks, ns, input)
