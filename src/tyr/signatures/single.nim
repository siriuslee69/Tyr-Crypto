## ---------------------------------------------------------------------
## | Signature Single <- import ONE family, or all, from one flag        |
## | no flag -> every family    -d:tyrSig=falcon -> Falcon alone         |
## ---------------------------------------------------------------------
##
##     import tyr/signatures/single
##     var kp = keypairSingle(sfFalcon)      # compile-time choice, no flag
##
## Then for a small build, add one flag and change nothing in your source:
##
##     nim c -d:tyrSig=falcon myfirmware.nim
##
##   -d:tyrSig=<name>   compiles     names
##   ----------------   ----------   -----------------------------
##   (omitted)          all          every family below
##   dilithium          Dilithium    dilithiumTyrSign(dilithium65, ..)
##   falcon             Falcon       falconTyrSign(falcon512, ..)
##   sphincs            SPHINCS+     sphincsTyrSign(..)
##   ed25519            Ed25519      ed25519TyrSign(msg, sk)
##
## Nim resolves imports before any of your code exists, so what enters the
## build is a build-time decision by nature. This keeps it to one flag and
## makes the no-flag case work.

import ./types
export types

const tyrSig* {.strdefine.}: string = ""
  ## Which single signature family to compile. Empty (default) means all.

when tyrSig == "":
  import ./dilithium
  import ./falcon
  import ./sphincs
  import ./ed25519
  export dilithium, falcon, sphincs, ed25519
elif tyrSig == "dilithium":
  import ./dilithium
  export dilithium
elif tyrSig == "falcon":
  import ./falcon
  export falcon
elif tyrSig == "sphincs":
  import ./sphincs
  export sphincs
elif tyrSig == "ed25519":
  import ./ed25519
  export ed25519
else:
  {.error: "unknown -d:tyrSig=" & tyrSig &
    " (expected: dilithium, falcon, sphincs, ed25519, or omit the flag for all)".}

proc signSingle*(f: static SigFamily, msg, sk: openArray[byte]): seq[byte] =
  ## f/msg/sk: family as a COMPILE-TIME value, bytes to sign, secret key.
  ## The branch is chosen while compiling; asking for a family this build
  ## excluded is a compile error naming the flag to change.
  when f == sfDilithium:
    when not declared(dilithiumTyrSign):
      {.error: "Dilithium is not in this build; use -d:tyrSig=dilithium or omit the flag".}
    else: result = dilithiumTyrSign(dilithium65, msg, sk)
  elif f == sfFalcon:
    when not declared(falconTyrSign):
      {.error: "Falcon is not in this build; use -d:tyrSig=falcon or omit the flag".}
    else: result = falconTyrSign(falcon512, msg, sk)
  elif f == sfSphincs:
    when not declared(sphincsTyrSign):
      {.error: "SPHINCS+ is not in this build; use -d:tyrSig=sphincs or omit the flag".}
    else: result = sphincsTyrSign(sphincsShake128fSimple, msg, sk)
  elif f == sfEd25519:
    when not declared(ed25519TyrSign):
      {.error: "Ed25519 is not in this build; use -d:tyrSig=ed25519 or omit the flag".}
    else: result = ed25519TyrSign(msg, sk)
