## ---------------------------------------------------------------------
## | Cipher Single <- import ONE family, or all, from one flag
## | no flag -> everything    -d:tyrCipher=<name> -> that one alone
## ---------------------------------------------------------------------
##
##     import tyr/ciphers/single        # works with no flag at all
##
## Add one flag for a small build; your source does not change:
##
##     nim c -d:tyrCipher=<name> myfirmware.nim
##
## Nim resolves every import before any of your code exists, so what
## enters the build is a build-time decision by nature. This keeps that
## decision down to one flag, and makes the no-flag case work.

import ./types
export types

const tyrCipher* {.strdefine.}: string = ""
  ## Which single family to compile. Empty (the default) means all.

when tyrCipher == "":
  import ./chacha20
  import ./xchacha20
  import ./aes_ctr
  import ./gimli_sponge
  export chacha20, xchacha20, aes_ctr, gimli_sponge
elif tyrCipher == "chacha20":
  import ./chacha20
  export chacha20
elif tyrCipher == "xchacha20":
  import ./xchacha20
  export xchacha20
elif tyrCipher == "aesctr":
  import ./aes_ctr
  export aes_ctr
elif tyrCipher == "gimli":
  import ./gimli_sponge
  export gimli_sponge
else:
  {.error: "unknown -d:tyrCipher=" & tyrCipher &
    " (expected: chacha20, xchacha20, aesctr, gimli, or omit the flag for all)".}

proc encryptSingle*(f: static CipherFamily,
    k, n, plain: openArray[byte]): seq[byte] =
  ## f/k/n/plain: family as a COMPILE-TIME value, key, nonce, bytes.
  ## ⚠ The nonce must never repeat under one key - see `types.nim`.
  when f == cfXChaCha20:
    when not declared(xchacha20Xor):
      {.error: "XChaCha20 is not in this build; use -d:tyrCipher=xchacha20 or omit the flag".}
    else:
      result = xchacha20Xor(k, n, plain)
  elif f == cfChaCha20:
    when not declared(chacha20Xor):
      {.error: "ChaCha20 is not in this build; use -d:tyrCipher=chacha20 or omit the flag".}
    else:
      result = chacha20Xor(k, n, plain)
  elif f == cfAesCtr:
    when not declared(aesCtrXor):
      {.error: "AES-CTR is not in this build; use -d:tyrCipher=aesctr or omit the flag".}
    else:
      result = aesCtrXor(k, n, plain)
  elif f == cfGimliStream:
    when not declared(gimliStreamXor):
      {.error: "Gimli is not in this build; use -d:tyrCipher=gimli or omit the flag".}
    else:
      result = gimliStreamXor(k, n, plain)

proc decryptSingle*(f: static CipherFamily,
    k, n, cipherText: openArray[byte]): seq[byte] =
  ## Same work as `encryptSingle`; these ciphers undo themselves.
  result = encryptSingle(f, k, n, cipherText)
