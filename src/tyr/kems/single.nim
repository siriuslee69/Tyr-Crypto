## ---------------------------------------------------------------------
## | KEM Single <- import ONE family, or all of them, from one flag      |
## | no flag -> every family    -d:tyrKem=kyber -> Kyber alone           |
## ---------------------------------------------------------------------
##
## Usable straight away, no flag required
## -------------------------------------
##
##     import tyr/kems/single
##
##     var kp = keypairSingle(kfKyber)        # <- compile-time choice
##
## With no flag this behaves like the full library: every family is
## available, and `keypairSingle` picks between them WHILE COMPILING, so
## there is no runtime branch and no cost.
##
## Then, when you want a small build, add one flag and change nothing else:
##
##     nim c -d:tyrKem=kyber myfirmware.nim
##
## Now only Kyber is compiled. The same `keypairSingle(kfKyber)` call keeps
## working; asking for any other family becomes a compile error naming the
## flag you would need. Your source does not change between the two builds.
##
##   -d:tyrKem=<name>     compiles          names
##   ------------------   ---------------   --------------------------
##   (omitted)            every family      all of them
##   kyber                Kyber             kyberTyrKeypair(kyber768)
##   mceliece             Classic McEliece  mcelieceTyrKeypair(...)
##   frodo                FrodoKEM          frodoTyrKeypair(...)
##   bike                 BIKE              bikeTyrKeypair(bikeL1)
##   ntru                 NTRU              ntruTyrKeypair(...)
##   saber                SABER             saberTyrKeypair(...)
##
## Why a build flag and not a call in your code
## --------------------------------------------
## Nim resolves every `import` before any of your code exists. A `case` or
## `when` written inside a proc runs long after all the imports have already
## been read, so it cannot un-import anything. Choosing what enters the
## build is therefore a build-time decision by nature. This file keeps that
## decision down to ONE flag with a readable value, and makes the no-flag
## case work, which is as close to "from inside the code" as the language
## allows.

import ./types
export types

const tyrKem* {.strdefine.}: string = ""
  ## Which single KEM family to compile. Empty (the default) means all.

when tyrKem == "":
  import ./kyber
  import ./mceliece
  import ./frodo
  import ./bike
  import ./ntru
  import ./saber
  export kyber, mceliece, frodo, bike, ntru, saber
elif tyrKem == "kyber":
  import ./kyber
  export kyber
elif tyrKem == "mceliece":
  import ./mceliece
  export mceliece
elif tyrKem == "frodo":
  import ./frodo
  export frodo
elif tyrKem == "bike":
  import ./bike
  export bike
elif tyrKem == "ntru":
  import ./ntru
  export ntru
elif tyrKem == "saber":
  import ./saber
  export saber
else:
  {.error: "unknown -d:tyrKem=" & tyrKem &
    " (expected: kyber, mceliece, frodo, bike, ntru, saber, or omit the flag for all)".}

proc keypairSingle*(f: static KemFamily, seed: seq[byte] = @[]): KemKeypair =
  ## f/seed: family named as a COMPILE-TIME value, plus optional fixed
  ## randomness for reproducible tests.
  ##
  ## `f` is `static`, so the branch below is chosen while compiling and the
  ## others are discarded. Asking for a family this build excluded is a
  ## compile error telling you which flag to change.
  when f == kfKyber:
    when not declared(kyberTyrKeypair):
      {.error: "Kyber is not in this build; use -d:tyrKem=kyber or omit the flag".}
    else:
      var t = kyberTyrKeypair(kyber768, seed)
      result = KemKeypair(family: kfKyber, public: t.publicKey, secret: t.secretKey)
  elif f == kfMcEliece:
    when not declared(mcelieceTyrKeypair):
      {.error: "McEliece is not in this build; use -d:tyrKem=mceliece or omit the flag".}
    else:
      var t = mcelieceTyrKeypair(mceliece6688128f, seed)
      result = KemKeypair(family: kfMcEliece, public: t.publicKey, secret: t.secretKey)
  elif f == kfFrodo:
    when not declared(frodoTyrKeypair):
      {.error: "Frodo is not in this build; use -d:tyrKem=frodo or omit the flag".}
    else:
      var t = frodoTyrKeypair(frodo640shake, seed)
      result = KemKeypair(family: kfFrodo, public: t.publicKey, secret: t.secretKey)
  elif f == kfBike:
    when not declared(bikeTyrKeypair):
      {.error: "BIKE is not in this build; use -d:tyrKem=bike or omit the flag".}
    else:
      var t = bikeTyrKeypair(bikeL1, seed)
      result = KemKeypair(family: kfBike, public: t.publicKey, secret: t.secretKey)
  elif f == kfNtru:
    when not declared(ntruTyrKeypair):
      {.error: "NTRU is not in this build; use -d:tyrKem=ntru or omit the flag".}
    else:
      var t = ntruTyrKeypair(ntruhps2048509, seed)
      result = KemKeypair(family: kfNtru, public: t.publicKey, secret: t.secretKey)
  elif f == kfSaber:
    when not declared(saberTyrKeypair):
      {.error: "SABER is not in this build; use -d:tyrKem=saber or omit the flag".}
    else:
      var t = saberTyrKeypair(saber, seed)
      result = KemKeypair(family: kfSaber, public: t.publicKey, secret: t.secretKey)
