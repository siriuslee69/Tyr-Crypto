## -----------------------------------------------------------
## PIN/Password KDF + Key Wrap Interface
## -> Derive keys from user secrets and wrap master keys
## -> Uses Argon2id + XChaCha20-Poly1305 (libsodium)
## -----------------------------------------------------------
##
##   password/common       types, labels, Secret holder   (always)
##   password/argon        password -> keys, KEX seeds    (-d:hasLibsodium)
##   password/keywrap      PIN-wrapped master key         (-d:hasLibsodium)
##   password/unavailable  same names, each one raises    (without it)

import ./password/common
export common

when defined(hasLibsodium):
  import ./password/argon
  import ./password/keywrap
  export argon.deriveSymmetricKeysFromBytesWithSalt, argon.deriveSymmetricKeysFromBytes,
    argon.deriveSymmetricKeysFromString,
    argon.deriveHybridKexDuoSeedFromBytesWithSalt, argon.deriveHybridKexTripleSeedFromBytesWithSalt,
    argon.deriveHybridKexDuoSeedFromBytes, argon.deriveHybridKexTripleSeedFromBytes,
    argon.deriveHybridKexDuoSeedFromString, argon.deriveHybridKexTripleSeedFromString,
    argon.derivePasswordPinSecretFromBytesWithSalt, argon.derivePasswordPinSecretFromStringWithSalt,
    argon.derivePatternBytesFromPasswordPinWithSalt
  export keywrap
else:
  import ./password/unavailable
  export unavailable
