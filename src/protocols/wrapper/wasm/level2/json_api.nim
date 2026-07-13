## ------------------------------------------------------
## Wasm JSON API <- invoke Tyr basic JSON and hash surfaces
## ------------------------------------------------------

import ../../basic_api as basicApi
import ../../../custom_crypto/blake3 as blake3Impl
import ../../../custom_crypto/gimli_sponge
import ../../../custom_crypto/hmac as hmacImpl
import ../../../custom_crypto/x25519 as x25519Impl
import ../../../custom_crypto/kyber as kyberImpl
import ../level0/types
import ../level1/json_codec

proc capabilitiesJson*(): string =
  try:
    result = buildCapabilitiesJson(wasmAbiVersion, buildCapabilities())
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc basicEncryptJson*(reqJson: string): string =
  try:
    var req = decodeBasicEncryptRequest(reqJson)
    var payload = basicApi.symEnc(req.algo, req.key, req.nonce, req.message)
    result = buildBasicCipherJson(req.algo, payload)
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc basicDecryptJson*(reqJson: string): string =
  try:
    var req = decodeBasicDecryptRequest(reqJson)
    var payload = basicApi.symDec(req.algo, req.key, req.nonce, req.payload)
    result = buildBasicCipherJson(req.algo, payload)
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc blake3HashJson*(reqJson: string): string =
  try:
    var req = decodeHashRequest(reqJson)
    var digest = blake3Impl.blake3Hash(req.input,
      if req.outLen == 0'u16: 32 else: int(req.outLen))
    result = buildBytesJson("blake3Hash", digest)
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc blake3KeyedHashJson*(reqJson: string): string =
  try:
    var req = decodeKeyedHashRequest(reqJson)
    var digest = blake3Impl.blake3KeyedHash(req.key, req.input,
      if req.outLen == 0'u16: 32 else: int(req.outLen))
    result = buildBytesJson("blake3KeyedHash", digest)
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc gimliHashJson*(reqJson: string): string =
  try:
    var req = decodeHashRequest(reqJson)
    var digest = gimliXof(@[], @[], req.input,
      if req.outLen == 0'u16: 32 else: int(req.outLen))
    result = buildBytesJson("gimliHash", digest)
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc sha3HashJson*(reqJson: string): string =
  try:
    var req = decodeHashRequest(reqJson)
    var digest = hmacImpl.sha3Hash(req.input,
      if req.outLen == 0'u16: 32 else: int(req.outLen))
    result = buildBytesJson("sha3Hash", digest)
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc kemKeypairJson*(reqJson: string): string =
  var req: WasmKemKeypairRequest
  try:
    req = decodeKemKeypairRequest(reqJson)
    case req.algo
    of "x25519":
      var kp = if req.seed.len == 0: x25519Impl.x25519TyrKeypair()
        else: x25519Impl.x25519TyrKeypairFromSeed(req.seed)
      result = buildKemKeypairJson(req.algo, kp.publicKey, kp.secretKey)
    of "kyber768":
      var kp = kyberImpl.kyberTyrKeypair(kyberImpl.kyber768, req.seed)
      result = buildKemKeypairJson(req.algo, kp.publicKey, kp.secretKey)
    of "kyber1024":
      var kp = kyberImpl.kyberTyrKeypair(kyberImpl.kyber1024, req.seed)
      result = buildKemKeypairJson(req.algo, kp.publicKey, kp.secretKey)
    else:
      result = buildErrorJson("unsupported wasm KEM algorithm")
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc kemEncapsJson*(reqJson: string): string =
  var req: WasmKemEncapsRequest
  try:
    req = decodeKemEncapsRequest(reqJson)
    case req.algo
    of "x25519":
      var kp = if req.seed.len == 0: x25519Impl.x25519TyrKeypair()
        else: x25519Impl.x25519TyrKeypairFromSeed(req.seed)
      var shared = x25519Impl.x25519TyrShared(kp.secretKey, req.receiverPublicKey)
      result = buildKemCipherJson(req.algo, kp.publicKey, shared)
    of "kyber768":
      var cipher = kyberImpl.kyberTyrEncaps(kyberImpl.kyber768,
        req.receiverPublicKey, req.seed)
      result = buildKemCipherJson(req.algo, cipher.ciphertext, cipher.sharedSecret)
    of "kyber1024":
      var cipher = kyberImpl.kyberTyrEncaps(kyberImpl.kyber1024,
        req.receiverPublicKey, req.seed)
      result = buildKemCipherJson(req.algo, cipher.ciphertext, cipher.sharedSecret)
    else:
      result = buildErrorJson("unsupported wasm KEM algorithm")
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)

proc kemDecapsJson*(reqJson: string): string =
  var req: WasmKemDecapsRequest
  try:
    req = decodeKemDecapsRequest(reqJson)
    case req.algo
    of "x25519":
      var shared = x25519Impl.x25519TyrShared(req.receiverSecretKey, req.ciphertext)
      result = buildKemSecretJson(req.algo, shared)
    of "kyber768":
      var shared = kyberImpl.kyberTyrDecaps(kyberImpl.kyber768,
        req.receiverSecretKey, req.ciphertext)
      result = buildKemSecretJson(req.algo, shared)
    of "kyber1024":
      var shared = kyberImpl.kyberTyrDecaps(kyberImpl.kyber1024,
        req.receiverSecretKey, req.ciphertext)
      result = buildKemSecretJson(req.algo, shared)
    else:
      result = buildErrorJson("unsupported wasm KEM algorithm")
  except CatchableError as exc:
    result = buildErrorJson(exc.msg)
