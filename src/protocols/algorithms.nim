## ----------------------------------------------------------
## Cipher Suites <- authenticated composite algorithm choices
## ----------------------------------------------------------

type
  CipherSuite* = enum
    csXChaCha20Blake3,
    csXChaCha20Gimli,
    csAesGimli,
    csXChaCha20AesGimli,
    csXChaCha20AesGimliPoly1305,
    csAes256Gcm

  AuthType* = enum
    atBlake3,
    atPoly1305,
    atGimli,
    atGimliPoly1305,
    atAeadTag,
    atAesGcm
