## -------------------------------------------------------
## Wasm C Exports <- Emscripten-facing C ABI entrypoints
## -------------------------------------------------------

import ./level0/types
import ./level2/json_api

proc NimMain() {.importc.}

var
  runtimeReady: bool = false
  responseBuffer: string = "{\"ok\":false,\"error\":\"runtime not initialised\"}"

proc ensureRuntime() =
  if runtimeReady:
    return
  NimMain()
  runtimeReady = true

proc requestString(reqJson: cstring): string =
  if reqJson == nil:
    return ""
  result = $reqJson

proc setResponse(value: string): cstring =
  responseBuffer = value
  result = responseBuffer.cstring

proc tyrWasmAbiVersion*(): cint {.exportc: "tyr_wasm_abi_version", cdecl.} =
  result = cint(wasmAbiVersion)

proc tyrWasmCapabilitiesJson*(): cstring {.exportc: "tyr_wasm_capabilities_json", cdecl.} =
  ensureRuntime()
  result = setResponse(capabilitiesJson())

proc tyrWasmBasicEncryptJson*(reqJson: cstring): cstring {.exportc: "tyr_wasm_basic_encrypt_json", cdecl.} =
  ensureRuntime()
  result = setResponse(basicEncryptJson(requestString(reqJson)))

proc tyrWasmBasicDecryptJson*(reqJson: cstring): cstring {.exportc: "tyr_wasm_basic_decrypt_json", cdecl.} =
  ensureRuntime()
  result = setResponse(basicDecryptJson(requestString(reqJson)))

proc tyrWasmBlake3HashJson*(reqJson: cstring): cstring {.exportc: "tyr_wasm_blake3_hash_json", cdecl.} =
  ensureRuntime()
  result = setResponse(blake3HashJson(requestString(reqJson)))

proc tyrWasmBlake3KeyedHashJson*(reqJson: cstring): cstring {.exportc: "tyr_wasm_blake3_keyed_hash_json", cdecl.} =
  ensureRuntime()
  result = setResponse(blake3KeyedHashJson(requestString(reqJson)))

proc tyrWasmGimliHashJson*(reqJson: cstring): cstring {.exportc: "tyr_wasm_gimli_hash_json", cdecl.} =
  ensureRuntime()
  result = setResponse(gimliHashJson(requestString(reqJson)))

proc tyrWasmSha3HashJson*(reqJson: cstring): cstring {.exportc: "tyr_wasm_sha3_hash_json", cdecl.} =
  ensureRuntime()
  result = setResponse(sha3HashJson(requestString(reqJson)))
