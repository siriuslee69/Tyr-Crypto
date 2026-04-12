## ------------------------------------------------------
## Wasm JSON API <- invoke Tyr basic JSON and hash surfaces
## ------------------------------------------------------

import ../../basic_api as basicApi
import ../../../custom_crypto/blake3 as blake3Impl
import ../../../custom_crypto/gimli_sponge
import ../../../custom_crypto/hmac as hmacImpl
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
