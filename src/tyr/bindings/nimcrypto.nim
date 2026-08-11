import ../helpers/errors
import ../helpers/secure_memory

when defined(hasNimcrypto):
  import nimcrypto/[bcmode, blake2, rijndael]

  type
    Aes256GcmContext* = object
      ctx: GCM[aes256]
      key: array[32, byte]
      iv: seq[byte]
      aadData: seq[byte]
      initialized: bool
      started: bool
      payloadUsed: bool

  proc start(context: var Aes256GcmContext) =
    if not context.initialized:
      raise newException(ValueError, "AES-256-GCM context is not initialized")
    if context.started:
      return
    context.ctx.init(context.key, context.iv, context.aadData)
    context.started = true

  proc init*(context: var Aes256GcmContext, key, iv: openArray[byte]) =
    if key.len != 32:
      raise newException(ValueError, "AES-256-GCM requires 32-byte key")
    if iv.len != 12:
      raise newException(ValueError, "AES-256-GCM requires a 12-byte initialisation vector")
    context.ctx.clear()
    secureClearBytes(context.key)
    secureClearBytes(context.iv)
    secureClearBytes(context.aadData)
    for i in 0 ..< context.key.len:
      context.key[i] = key[i]
    context.iv = @iv
    context.aadData = @[]
    context.initialized = true
    context.started = false
    context.payloadUsed = false

  proc aad*(context: var Aes256GcmContext, data: openArray[byte]) =
    if not context.initialized:
      raise newException(ValueError, "AES-256-GCM context is not initialized")
    if context.started:
      raise newException(ValueError, "AES-256-GCM AAD must be supplied before payload data")
    if data.len > 0:
      context.aadData.add(data)

  proc encrypt*(context: var Aes256GcmContext, plaintext: openArray[byte]): seq[byte] =
    if context.payloadUsed:
      raise newException(ValueError, "AES-256-GCM context already processed a payload")
    context.start()
    context.payloadUsed = true
    result = newSeq[byte](plaintext.len)
    context.ctx.encrypt(plaintext, result)

  proc decrypt*(context: var Aes256GcmContext, ciphertext,
      tag: openArray[byte]): seq[byte] =
    if tag.len != 16:
      raise newException(ValueError, "AES-256-GCM authentication tag must be 16 bytes")
    if context.payloadUsed:
      raise newException(ValueError, "AES-256-GCM context already processed a payload")
    context.start()
    context.payloadUsed = true
    result = newSeq[byte](ciphertext.len)
    if not context.ctx.decrypt(ciphertext, result, tag):
      secureClearBytes(result)
      raise newException(ValueError, "AES-256-GCM authentication tag mismatch")

  proc tag*(context: var Aes256GcmContext): array[16, byte] =
    if not context.payloadUsed:
      raise newException(ValueError, "AES-256-GCM tag requires a processed payload")
    context.ctx.getTag()

  proc clear*(context: var Aes256GcmContext) =
    context.ctx.clear()
    secureClearBytes(context.key)
    secureClearBytes(context.iv)
    secureClearBytes(context.aadData)
    context.initialized = false
    context.started = false
    context.payloadUsed = false

  proc blake2b*(output: var openArray[byte], input: openArray[byte]) =
    if output.len == 48:
      var ctx: blake2_384
      ctx.init()
      ctx.update(input)
      discard ctx.finish(output)
      ctx.clear()
      return
    if output.len == 64:
      var ctx: blake2_512
      ctx.init()
      ctx.update(input)
      discard ctx.finish(output)
      ctx.clear()
      return
    raise newException(ValueError, "BLAKE2b output must be 48 or 64 bytes")

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

  proc clear*(context: var Aes256GcmContext) =
    discard context.dummy

  proc blake2b*(output: var openArray[byte], input: openArray[byte]) =
    discard output
    discard input
    raiseUnavailable("nimcrypto", "hasNimcrypto")
