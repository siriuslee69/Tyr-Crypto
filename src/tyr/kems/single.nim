## ---------------------------------------------------------------------
## | KEM Single <- compile exactly ONE family, chosen by a build flag    |
## | -d:tyrKemKyber  ->  only Kyber enters the build                     |
## ---------------------------------------------------------------------
##
## What this is for
## ----------------
## Small devices. A microcontroller build should contain the one algorithm
## the device uses and nothing else. This file compiles no code of its own;
## it only decides which family module the compiler is allowed to see.
##
##   nim c -d:tyrKemKyber myfirmware.nim
##     -> Kyber only. McEliece, Frodo, BIKE, NTRU and SABER are never
##        imported, so they are never parsed, never compiled, never linked.
##
## Why not just rely on the optimiser
## ----------------------------------
## Nim does drop code you never call, so on a normal desktop build the
## optimiser gets you the same binary. The difference shows on a device:
##
##   an unused module is still PARSED and TYPE-CHECKED for your target
##
## If a family pulls in something the target has no answer for, the build
## fails even though the code would have been dropped later. `when` is the
## only tier that prevents the module being looked at in the first place.
##
## The flags
## ---------
##
##   flag                  compiles      call it with
##   -------------------   -----------   --------------------------
##   -d:tyrKemKyber        Kyber         kyberTyrKeypair(kyber768)
##   -d:tyrKemMcEliece     McEliece      mcelieceTyrKeypair(...)
##   -d:tyrKemFrodo        Frodo         frodoTyrKeypair(...)
##   -d:tyrKemBike         BIKE          bikeTyrKeypair(bikeL1)
##   -d:tyrKemNtru         NTRU          ntruTyrKeypair(...)
##   -d:tyrKemSaber        SABER         saberTyrKeypair(...)
##
## Naming two at once is refused below rather than letting the first win.
## Naming none is refused too - importing this file means you intended to
## pick one, so silence would be a mistake, not a default.

import ./types
export types

when defined(tyrKemKyber):
  when defined(tyrKemMcEliece) or defined(tyrKemFrodo) or defined(tyrKemBike) or
      defined(tyrKemNtru) or defined(tyrKemSaber):
    {.error: "pick only one -d:tyrKem... flag".}
  import ./kyber
  export kyber

elif defined(tyrKemMcEliece):
  when defined(tyrKemFrodo) or defined(tyrKemBike) or defined(tyrKemNtru) or
      defined(tyrKemSaber):
    {.error: "pick only one -d:tyrKem... flag".}
  import ./mceliece
  export mceliece

elif defined(tyrKemFrodo):
  when defined(tyrKemBike) or defined(tyrKemNtru) or defined(tyrKemSaber):
    {.error: "pick only one -d:tyrKem... flag".}
  import ./frodo
  export frodo

elif defined(tyrKemBike):
  when defined(tyrKemNtru) or defined(tyrKemSaber):
    {.error: "pick only one -d:tyrKem... flag".}
  import ./bike
  export bike

elif defined(tyrKemNtru):
  when defined(tyrKemSaber):
    {.error: "pick only one -d:tyrKem... flag".}
  import ./ntru
  export ntru

elif defined(tyrKemSaber):
  import ./saber
  export saber

else:
  {.error: "tyr/kems/single needs one -d:tyrKem... flag " &
    "(tyrKemKyber, tyrKemMcEliece, tyrKemFrodo, tyrKemBike, tyrKemNtru, tyrKemSaber). " &
    "For every family at once use `import tyr/kems` instead.".}
