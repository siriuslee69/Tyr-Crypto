import std/[base64, json, unittest]

import ../src/protocols/wrapper/wasm/level0/types
import ../src/protocols/wrapper/wasm/level2/json_api

proc wasmBytesToString(bs: openArray[uint8]): string =
  result = newString(bs.len)
  for i in 0 ..< bs.len:
    result[i] = char(bs[i])

proc wasmEncodeBytes(bs: openArray[uint8]): string =
  result = encode(wasmBytesToString(bs))

proc wasmDecodeBytes(s: string): seq[uint8] =
  let decoded = decode(s)
  result = newSeq[uint8](decoded.len)
  for i, ch in decoded:
    result[i] = uint8(ord(ch))

suite "wasm JSON bridge":
  test "capabilities surface is reported":
    let response = parseJson(capabilitiesJson())
    check response["ok"].getBool()
    check response["abiVersion"].getInt() == wasmAbiVersion
    check response["basicCiphers"].len > 0

  test "basic encrypt and decrypt roundtrip through JSON":
    var
      key = newSeq[uint8](32)
      nonce = newSeq[uint8](24)
      message = @[byte 1, 2, 3, 4, 5, 6]
      decryptRequest: JsonNode
      encryptResponse: JsonNode
      decryptResponse: JsonNode
    key[0] = 7
    nonce[0] = 9
    let encryptRequest = %*{
      "algo": "xchacha20",
      "key": wasmEncodeBytes(key),
      "nonce": wasmEncodeBytes(nonce),
      "message": wasmEncodeBytes(message)
    }
    encryptResponse = parseJson(basicEncryptJson($encryptRequest))
    check encryptResponse["ok"].getBool()
    decryptRequest = %*{
      "algo": "xchacha20",
      "key": wasmEncodeBytes(key),
      "nonce": wasmEncodeBytes(nonce),
      "payload": encryptResponse["payload"].getStr()
    }
    decryptResponse = parseJson(basicDecryptJson($decryptRequest))
    check decryptResponse["ok"].getBool()
    check wasmDecodeBytes(decryptResponse["payload"].getStr()) == message

  test "blake3 hash goes through JSON":
    let response = parseJson(blake3HashJson("""{"input":"YWJj","outLength":32}"""))
    check response["ok"].getBool()
    check response["kind"].getStr() == "blake3Hash"
    check wasmDecodeBytes(response["bytes"].getStr()).len == 32
