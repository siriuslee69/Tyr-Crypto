## ---------------------------------------------------------------------
## | Signature Single <- compile exactly ONE family, by build flag      |
## | -d:tyrSigFalcon  ->  only Falcon enters the build                  |
## ---------------------------------------------------------------------
##
## For small devices. This file compiles no code of its own; it only decides
## which family module the compiler is allowed to see. An unused module is
## still parsed and type-checked for your target, so `when` is the only tier
## that keeps a family out of the build entirely.
##
##   flag                    compiles     call it with
##   ---------------------   ----------   -------------------------------
##   -d:tyrSigDilithium      Dilithium    dilithiumTyrSign(dilithium65, ..)
##   -d:tyrSigFalcon         Falcon       falconTyrSign(falcon512, ..)
##   -d:tyrSigSphincs        SPHINCS+     sphincsTyrSign(..)
##   -d:tyrSigEd25519        Ed25519      ed25519TyrSign(msg, sk)

import ./types
export types

when defined(tyrSigDilithium):
  when defined(tyrSigFalcon) or defined(tyrSigSphincs) or defined(tyrSigEd25519):
    {.error: "pick only one -d:tyrSig... flag".}
  import ./dilithium
  export dilithium

elif defined(tyrSigFalcon):
  when defined(tyrSigSphincs) or defined(tyrSigEd25519):
    {.error: "pick only one -d:tyrSig... flag".}
  import ./falcon
  export falcon

elif defined(tyrSigSphincs):
  when defined(tyrSigEd25519):
    {.error: "pick only one -d:tyrSig... flag".}
  import ./sphincs
  export sphincs

elif defined(tyrSigEd25519):
  import ./ed25519
  export ed25519

else:
  {.error: "tyr/signatures/single needs one -d:tyrSig... flag " &
    "(tyrSigDilithium, tyrSigFalcon, tyrSigSphincs, tyrSigEd25519). " &
    "For every family at once use `import tyr/signatures` instead.".}
