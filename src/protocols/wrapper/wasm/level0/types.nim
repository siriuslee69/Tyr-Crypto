## ------------------------------------------------
## Wasm Bridge Types <- JS/TS request/response data
## ------------------------------------------------

import ../../helpers/algorithms

const
  wasmAbiVersion* = 2
  symmetricKeyBytes* = 32

type
  WasmBasicEncryptRequest* = object
    algo*: StreamCipherAlgorithm
    key*: seq[uint8]
    nonce*: seq[uint8]
    message*: seq[uint8]

  WasmBasicDecryptRequest* = object
    algo*: StreamCipherAlgorithm
    key*: seq[uint8]
    nonce*: seq[uint8]
    payload*: seq[uint8]

  WasmHashRequest* = object
    input*: seq[uint8]
    outLen*: uint16

  WasmKeyedHashRequest* = object
    key*: seq[uint8]
    input*: seq[uint8]
    outLen*: uint16

  WasmCapability* = object
    name*: string
    nonceBytes*: int
    notes*: string

proc algoName*(a: StreamCipherAlgorithm): string =
  case a
  of scaXChaCha20:
    result = "xchacha20"
  of scaAesCtr:
    result = "aesCtr"
  of scaGimliStream:
    result = "gimliStream"

proc parseBasicCipherAlgo*(s: string): StreamCipherAlgorithm =
  case s
  of "xchacha20":
    result = scaXChaCha20
  of "aesCtr":
    result = scaAesCtr
  of "gimliStream":
    result = scaGimliStream
  else:
    raise newException(ValueError, "unsupported wasm basic cipher algorithm: " & s)

proc cipherNonceBytes*(a: StreamCipherAlgorithm): int =
  case a
  of scaXChaCha20, scaGimliStream:
    result = 24
  of scaAesCtr:
    result = 16

proc buildCapabilities*(): seq[WasmCapability] =
  for a in [scaXChaCha20, scaAesCtr, scaGimliStream]:
    result.add(WasmCapability(
      name: algoName(a),
      nonceBytes: cipherNonceBytes(a),
      notes: "Primitive basic-api cipher"
    ))
