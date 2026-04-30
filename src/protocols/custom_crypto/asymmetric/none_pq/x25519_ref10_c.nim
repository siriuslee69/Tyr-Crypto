## --------------------------------------------------------------
## X25519 Ref10 C <- exact local ref10 scalar core for correctness
## --------------------------------------------------------------

{.compile: "x25519_ref10_scalar.c".}

proc tyr_x25519_ref10_scalarmult*(q: ptr uint8, n: ptr uint8, p: ptr uint8): cint {.cdecl, importc.}
proc tyr_x25519_ref10_scalarmult_base*(q: ptr uint8, n: ptr uint8): cint {.cdecl, importc.}
