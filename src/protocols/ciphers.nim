## ---------------------------------------------------------------------
## | Ciphers <- choose at COMPILE time how much cipher code to build    |
## | -d:tyrCipherX -> only X    |    no flag -> all four + runtime pick |
## ---------------------------------------------------------------------
##
## What this file does
## -------------------
## This file compiles nothing of its own. It only decides which other files
## get compiled, based on a flag handed to the compiler. That keeps the
## decision in one readable place.
##
## Two ways to build
## -----------------
##
##   1. DEFAULT - you pass no flag
##
##        nim c myprogram.nim
##
##      All four ciphers are built, plus `cipher_runtime`, which lets the
##      program choose between them while it runs:
##
##        var c: TyrCipher = parseTyrCipher(readConfigValue())
##        var out: seq[byte] = tyrCipherEncrypt(c, key, nonce, message)
##
##      Pick this unless you have a reason not to. It is what every other
##      Tyr repo expects.
##
##   2. SINGLE CIPHER - you name one
##
##        nim c -d:tyrCipherXChaCha20 myprogram.nim
##
##      Only that cipher is compiled. The unrelated ones never enter the
##      build. Measured on this repo, a program that calls XChaCha20:
##
##        -d:tyrCipherXChaCha20   ->   9 C files, 126 KiB binary
##        (default, all four)     ->  17 C files, 175 KiB binary
##
##      One honest wrinkle: XChaCha20 is BUILT ON ChaCha20. It stretches the
##      nonce with a step called HChaCha20 and then runs the ordinary
##      ChaCha20 core. So `-d:tyrCipherXChaCha20` still compiles the
##      ChaCha20 core, because XChaCha20 cannot work without it. AES-CTR and
##      Gimli are genuinely absent. The other three flags pull in nothing but
##      their own algorithm.
##
##      You call the algorithm directly by its own name:
##
##        var out: seq[byte] = xchacha20Xor(key, nonce, message)
##
##      `TyrCipher`, `tyrCipherEncrypt` and friends do NOT exist in this
##      build. That is the point: a runtime choice between four ciphers is
##      meaningless when only one was compiled.
##
## The flags
## ---------
##
##   flag                        builds only        call it with
##   -------------------------   ----------------   --------------------
##   -d:tyrCipherXChaCha20       XChaCha20          xchacha20Xor(...)
##   -d:tyrCipherChaCha20        ChaCha20           chacha20Xor(...)
##   -d:tyrCipherAesCtr          AES-CTR            aesCtrXor(...)
##   -d:tyrCipherGimli           Gimli stream       gimliStreamXor(...)
##   (none)                      all four           tyrCipherEncrypt(...)
##
## Naming two flags at once is refused below, rather than quietly letting
## the first one win.
##
## Why bother, when the compiler already drops unused code
## -------------------------------------------------------
## Usually it does, and for a normal program the default build is right.
## This switch is for the cases where "usually" is not good enough: a build
## where an algorithm must be provably absent rather than merely unreachable,
## or a target so small that compiling the other three is wasted work.
##
## ⚠ Reach for the flag through THIS file, not through `tyr_crypto`
## ----------------------------------------------------------------
## `tyr_crypto` is the whole library. It pulls in the certificate code, the
## post-quantum families and the composite suites, and those import the
## ciphers for their own use. So this:
##
##     import tyr_crypto            # with -d:tyrCipherAesCtr
##
## still compiles the other three ciphers, because something else asked for
## them. The flag only removes `TyrCipher` and its runtime `case`.
##
## For a build that genuinely contains one cipher and nothing else, import
## this file on its own:
##
##     import tyr_crypto/protocols/ciphers    # with -d:tyrCipherAesCtr

when defined(tyrCipherXChaCha20):
  when defined(tyrCipherChaCha20) or defined(tyrCipherAesCtr) or
      defined(tyrCipherGimli):
    {.error: "pick only one -d:tyrCipher... flag".}
  import ./custom_crypto/symmetric/chacha/xchacha20
  export xchacha20

elif defined(tyrCipherChaCha20):
  when defined(tyrCipherAesCtr) or defined(tyrCipherGimli):
    {.error: "pick only one -d:tyrCipher... flag".}
  import ./custom_crypto/symmetric/chacha/chacha20
  export chacha20

elif defined(tyrCipherAesCtr):
  when defined(tyrCipherGimli):
    {.error: "pick only one -d:tyrCipher... flag".}
  import ./custom_crypto/symmetric/aes/aes_ctr
  export aes_ctr

elif defined(tyrCipherGimli):
  import ./custom_crypto/symmetric/gimli/gimli_sponge
  export gimli_sponge

else:
  import ./ciphers/cipher_runtime
  export cipher_runtime
