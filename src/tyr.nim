## ---------------------------------------------------------------------
## | Tyr <- everything, with one name per operation                     |
## ---------------------------------------------------------------------
##
## Four ways to reach any algorithm
## --------------------------------
## Every module (kems, signatures, hashes, macs, kdfs, ciphers) offers the
## same four call shapes. Pick by how you know which algorithm you want.
##
##   1. import tyr                     EVERYTHING, one name per operation
##
##        keypair(kyber768)            <- the compiler picks Kyber because
##        keypair(dilithium65)            of the argument's TYPE
##        digest(hfBlake3, data)
##
##   2. import tyr/kems/mceliece       ONE family, by its own long name
##
##        mcelieceTyrKeypair(mceliece6688128f)
##
##      Only that family is compiled. Use this when you know the algorithm
##      while writing the code and want a small build.
##
##   3. import tyr/kems/dynamic        choose from a VALUE while running
##
##        var c = AnyKem(family: parseKemFamily(cfgString), ...)
##        var kp = keypairOf(c)
##
##      For when the algorithm is named in a config file or a message
##      header. Every family is compiled in, because any could be chosen.
##
##   4. import tyr/kems/single         ONE family, chosen by a BUILD FLAG
##      -d:tyrKem=kyber
##        keypairSingle(kfKyber)
##
##      For small devices. Usable with no flag at all - then every family
##      is available and the choice is still settled while compiling. Add
##      the flag and nothing else is even parsed, so a family that cannot
##      compile for your target never gets in the way.
##
## The names differ per tier (`keypair` / `keypairOf` / `keypairSingle` /
## `kyberTyrKeypair`) so all four can be imported side by side without
## ever colliding.
##
## A fifth shape: typed material
## -----------------------------
## Beside the four tiers, each module offers a `material` surface whose
## types carry the exact key and nonce sizes, turning a wrong length into
## a compile error instead of a runtime check:
##
##     var m = xchacha20cipherM(key: k, nonce: n)
##     var ct = encrypt(message, m)
##
## See `tyr/helpers/material` for what the five share.
##
## Where things live
## -----------------
##
##   tyr/kems         key agreement      Kyber McEliece Frodo BIKE NTRU SABER
##   tyr/signatures   proving authorship Dilithium Falcon SPHINCS+ Ed25519
##   tyr/hashes       fingerprints       BLAKE3 SHA-256 SHA-512 SHA-3
##   tyr/macs         keyed fingerprints BLAKE3-keyed Gimli Poly1305 HMAC-SHA3
##   tyr/kdfs         key derivation     Argon2i Argon2id BLAKE3+Gimli custom
##   tyr/ciphers      encryption         XChaCha20 ChaCha20 AES-CTR Gimli
##   tyr/aeads        encrypt + verify   composite suites
##   tyr/certs        X.509 handling
##   tyr/otp          HOTP / TOTP codes
##   tyr/helpers      shared plumbing
##   tyr/bindings     optional native backends (libsodium, liboqs, OpenSSL)
##
## Each module folder also holds `types.nim`, which explains that family of
## algorithms in plain words and carries the safety warnings. Read those
## first - the nonce, one-time-key and password warnings live there.
## Alongside it sits `material.nim`, that module's typed material surface.

import ./tyr/kems
import ./tyr/signatures
import ./tyr/hashes
import ./tyr/macs
import ./tyr/kdfs
import ./tyr/ciphers
import ./tyr/otp
import ./tyr/aeads
import ./tyr/certs/chain
import ./tyr/signatures/registry
import ./tyr/helpers/random
import ./tyr/helpers/tiers

export kems
export signatures
export hashes
export macs
export kdfs
export ciphers
export otp
export aeads
export chain
export registry
export random
export tiers
