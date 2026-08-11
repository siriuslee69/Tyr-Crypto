## ---------------------------------------------------------------------
## | MAC Single <- compile exactly ONE authenticator, by build flag     |
## ---------------------------------------------------------------------
##
##   -d:tyrMacPoly1305   ->  poly1305Tag(key, msg)     (one-time key!)
##   -d:tyrMacHmac       ->  the hash-based MACs (BLAKE3 / Gimli / SHA-3)
##
## The three hash-based constructions share one module, so they arrive
## together; Poly1305 is independent and can stand alone.

import ./types
export types

when defined(tyrMacPoly1305):
  when defined(tyrMacHmac):
    {.error: "pick only one -d:tyrMac... flag".}
  import ./poly1305
  export poly1305
elif defined(tyrMacHmac):
  import ./hmac
  export hmac
else:
  {.error: "tyr/macs/single needs one -d:tyrMac... flag " &
    "(tyrMacPoly1305, tyrMacHmac). " &
    "For every family at once use `import tyr/macs` instead.".}
