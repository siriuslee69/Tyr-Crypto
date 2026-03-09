import ../common

when defined(hasNimcrypto):
  import nimcrypto/[aes, gcm, sha2, sha3, blake2]

  type
    Aes256GcmContext* = object
      ctx: GCM[aes256]

  proc init*(context: var Aes256GcmContext, key, iv: openArray[byte]) =
    if key.len != 32:
      raise newException(ValueError, "AES-256-GCM requires 32-byte key")
    if iv.len == 0:
      raise newException(ValueError, "Initialisation vector must not be empty")
    context.ctx.init(key, iv)

  proc aad*(context: var Aes256GcmContext, data: openArray[byte]) =
    if data.len > 0:
      context.ctx.addAad(data)

  proc encrypt*(context: var Aes256GcmContext, plaintext: openArray[byte]): seq[byte] =
    context.ctx.encrypt(plaintext)

  proc decrypt*(context: var Aes256GcmContext, ciphertext: openArray[byte]): seq[byte] =
    context.ctx.decrypt(ciphertext)

  proc decrypt*(context: var Aes256GcmContext, ciphertext,
      tag: openArray[byte]): seq[byte] =
    if tag.len == 0:
      raise newException(ValueError, "authentication tag must not be empty")
    result = newSeq[byte](ciphertext.len)
    if not context.ctx.decrypt(ciphertext, result, tag):
      raise newException(ValueError, "AES-256-GCM authentication tag mismatch")

  proc tag*(context: var Aes256GcmContext): array[16, byte] =
    context.ctx.getTag()

  proc blake2b*(output: var openArray[byte], input: openArray[byte]) =
    if output.len == 0:
      raise newException(ValueError, "output buffer must not be empty")
    blake2.hash(output, input)

else:
  type
    Aes256GcmContext* = object
      dummy*: byte

  proc init*(context: var Aes256GcmContext, key, iv: openArray[byte]) =
    discard context.dummy
    discard key
    discard iv
    raiseUnavailable("nimcrypto", "hasNimcrypto")

  proc aad*(context: var Aes256GcmContext, data: openArray[byte]) =
    discard context.dummy
    discard data
    raiseUnavailable("nimcrypto", "hasNimcrypto")

  proc encrypt*(context: var Aes256GcmContext, plaintext: openArray[byte]): seq[byte] =
    discard context.dummy
    discard plaintext
    raiseUnavailable("nimcrypto", "hasNimcrypto")
    return @[]

  proc decrypt*(context: var Aes256GcmContext, ciphertext: openArray[byte]): seq[byte] =
    discard context.dummy
    discard ciphertext
    raiseUnavailable("nimcrypto", "hasNimcrypto")
    return @[]

  proc decrypt*(context: var Aes256GcmContext, ciphertext,
      tag: openArray[byte]): seq[byte] =
    discard context.dummy
    discard ciphertext
    discard tag
    raiseUnavailable("nimcrypto", "hasNimcrypto")
    return @[]

  proc tag*(context: var Aes256GcmContext): array[16, byte] =
    discard context.dummy
    raiseUnavailable("nimcrypto", "hasNimcrypto")
    var zero: array[16, byte]
    return zero

  proc blake2b*(output: var openArray[byte], input: openArray[byte]) =
    discard output
    discard input
    raiseUnavailable("nimcrypto", "hasNimcrypto")
