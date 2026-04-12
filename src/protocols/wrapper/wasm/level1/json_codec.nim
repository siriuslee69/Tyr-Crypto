## ------------------------------------------------
## Wasm JSON Codec <- base64 and JSON field helpers
## ------------------------------------------------

import std/[base64, json]

import ../../helpers/algorithms
import ../level0/types

proc bytesToString(bs: openArray[uint8]): string =
  result = newString(bs.len)
  for i in 0 ..< bs.len:
    result[i] = char(bs[i])

proc stringToBytes(s: string): seq[uint8] =
  result = newSeq[uint8](s.len)
  for i, ch in s:
    result[i] = uint8(ord(ch))

proc encodeBase64Bytes*(bs: openArray[uint8]): string =
  result = encode(bytesToString(bs))

proc decodeBase64Bytes*(s: string): seq[uint8] =
  result = stringToBytes(decode(s))

proc requireObject(reqJson: string): JsonNode =
  result = parseJson(reqJson)
  if result.kind != JObject:
    raise newException(ValueError, "wasm request must be a JSON object")

proc requireField(n: JsonNode, fieldName: string): JsonNode =
  if not n.hasKey(fieldName):
    raise newException(ValueError, "missing wasm field: " & fieldName)
  result = n[fieldName]

proc requireStringField(n: JsonNode, fieldName: string): string =
  var fieldNode = requireField(n, fieldName)
  if fieldNode.kind != JString:
    raise newException(ValueError, "wasm field " & fieldName & " must be a string")
  result = fieldNode.getStr()

proc decodeBase64Field(n: JsonNode, fieldName: string): seq[uint8] =
  result = decodeBase64Bytes(requireStringField(n, fieldName))

proc decodeOutLen(n: JsonNode, fieldName: string = "outLength"): uint16 =
  if not n.hasKey(fieldName):
    return 0'u16
  if n[fieldName].kind notin {JInt, JFloat}:
    raise newException(ValueError, "wasm field " & fieldName & " must be numeric")
  var value = n[fieldName].getInt()
  if value < 0 or value > int(high(uint16)):
    raise newException(ValueError, "wasm field " & fieldName & " is out of range")
  result = uint16(value)

proc decodeBasicEncryptRequest*(reqJson: string): WasmBasicEncryptRequest =
  var n = requireObject(reqJson)
  result.algo = parseBasicCipherAlgo(requireStringField(n, "algo"))
  result.key = decodeBase64Field(n, "key")
  result.nonce = decodeBase64Field(n, "nonce")
  result.message = decodeBase64Field(n, "message")

proc decodeBasicDecryptRequest*(reqJson: string): WasmBasicDecryptRequest =
  var n = requireObject(reqJson)
  result.algo = parseBasicCipherAlgo(requireStringField(n, "algo"))
  result.key = decodeBase64Field(n, "key")
  result.nonce = decodeBase64Field(n, "nonce")
  result.payload = decodeBase64Field(n, "payload")

proc decodeHashRequest*(reqJson: string): WasmHashRequest =
  var n = requireObject(reqJson)
  result.input = decodeBase64Field(n, "input")
  result.outLen = decodeOutLen(n)

proc decodeKeyedHashRequest*(reqJson: string): WasmKeyedHashRequest =
  var n = requireObject(reqJson)
  result.key = decodeBase64Field(n, "key")
  result.input = decodeBase64Field(n, "input")
  result.outLen = decodeOutLen(n)

proc buildErrorJson*(msg: string): string =
  result = $(%*{"ok": false, "error": msg})

proc buildBytesJson*(kind: string, value: openArray[uint8]): string =
  result = $(%*{
    "ok": true,
    "kind": kind,
    "bytes": encodeBase64Bytes(value)
  })

proc buildBasicCipherJson*(algo: StreamCipherAlgorithm, payload: openArray[uint8]): string =
  result = $(%*{
    "ok": true,
    "algo": algoName(algo),
    "payload": encodeBase64Bytes(payload)
  })

proc buildCapabilitiesJson*(abiVersion: int, caps: seq[WasmCapability]): string =
  var algorithmsNode = newJArray()
  for cap in caps:
    algorithmsNode.add(%*{
      "name": cap.name,
      "nonceBytes": cap.nonceBytes,
      "notes": cap.notes
    })
  result = $(%*{
    "ok": true,
    "abiVersion": abiVersion,
    "basicCiphers": algorithmsNode
  })
