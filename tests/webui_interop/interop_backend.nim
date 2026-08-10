## ----------------------------------------------------------------------
## WebUI Interop Backend <- native basic_api counterpart for browser wasm
## ----------------------------------------------------------------------

import std/[base64, json, strutils]

import ../../.iron/meta/metaPragmas
import ../../src/protocols/custom_crypto/[kyber, x25519]
import ../../src/protocols/wrapper/basic_api
import ../../src/protocols/wrapper/helpers/algorithms
import ./[test_catalog, test_jobs]

type
  InteropRequest* {.role: {preparedData}.} = object
    action*: string
    algo*: string
    key*: seq[uint8]
    nonce*: seq[uint8]
    payload*: seq[uint8]
    message*: seq[uint8]
    publicKey*: seq[uint8]
    secretKey*: seq[uint8]
    seed*: seq[uint8]
    id*: string
    path*: string
    output*: string
    passed*: bool
    durationMs*: int64

proc bytesToString(B: openArray[uint8]): string {.role: {helper}.} =
  ## Converts byte values to a base64-compatible binary string.
  var
    i: int = 0
  result = newString(B.len)
  while i < B.len:
    result[i] = char(B[i])
    i = i + 1

proc stringToBytes(s: string): seq[uint8] {.role: {helper}.} =
  ## Converts a decoded binary string to bytes.
  var
    i: int = 0
  result = newSeq[uint8](s.len)
  while i < s.len:
    result[i] = uint8(ord(s[i]))
    i = i + 1

proc encodeBytes*(B: openArray[uint8]): string {.role: {helper}.} =
  ## Encodes raw request and response materials for JSON transport.
  result = encode(bytesToString(B))

proc decodeBytes(n: JsonNode, field: string): seq[uint8] {.role: {helper}.} =
  ## Validates and decodes one required base64 JSON field.
  if not n.hasKey(field) or n[field].kind != JString:
    raise newException(ValueError, "missing interop field: " & field)
  result = stringToBytes(decode(n[field].getStr()))

proc decodeOptionalBytes(n: JsonNode, field: string): seq[uint8] {.role: {helper}.} =
  ## Decodes an optional base64 JSON field.
  if n.hasKey(field):
    result = decodeBytes(n, field)

proc parseStreamAlgo(s: string): StreamCipherAlgorithm {.role: {parser}.} =
  ## Maps the browser bridge names onto the typed basic_api enum.
  case s
  of "xchacha20":
    result = scaXChaCha20
  of "chacha20":
    result = scaChaCha20
  of "aesCtr":
    result = scaAesCtr
  of "gimliStream":
    result = scaGimliStream
  else:
    raise newException(ValueError, "unsupported stream algorithm: " & s)

proc parseRequest*(raw: string): InteropRequest {.role: {helper, parser}.} =
  ## Parses one untrusted WebUI request into a safe native request object.
  var n: JsonNode = parseJson(raw)
  if n.kind != JObject:
    raise newException(ValueError, "interop request must be a JSON object")
  if not n.hasKey("action") or n["action"].kind != JString:
    raise newException(ValueError, "interop request is missing an action")
  if not n.hasKey("algo") or n["algo"].kind != JString:
    raise newException(ValueError, "interop request is missing an algorithm")
  result.action = n["action"].getStr()
  result.algo = n["algo"].getStr()
  result.key = decodeOptionalBytes(n, "key")
  result.nonce = decodeOptionalBytes(n, "nonce")
  result.payload = decodeOptionalBytes(n, "payload")
  result.message = decodeOptionalBytes(n, "message")
  result.publicKey = decodeOptionalBytes(n, "publicKey")
  result.secretKey = decodeOptionalBytes(n, "secretKey")
  result.seed = decodeOptionalBytes(n, "seed")
  if n.hasKey("id") and n["id"].kind == JString:
    result.id = n["id"].getStr()
  if n.hasKey("path") and n["path"].kind == JString:
    result.path = n["path"].getStr()
  if n.hasKey("output") and n["output"].kind == JString:
    result.output = n["output"].getStr()
  if n.hasKey("passed") and n["passed"].kind == JBool:
    result.passed = n["passed"].getBool()
  if n.hasKey("durationMs") and n["durationMs"].kind == JInt:
    result.durationMs = n["durationMs"].getBiggestInt()

proc buildBytesResponse(kind, algo: string, B: openArray[uint8]): string {.role: {dataWriter}.} =
  ## Builds a successful native response with one encoded byte payload.
  result = $(%*{
    "ok": true,
    "kind": kind,
    "algo": algo,
    "bytes": encodeBytes(B)
  })

proc buildKemResponse(kind, algo: string, ciphertext, sharedSecret: openArray[uint8]): string {.role: {dataWriter}.} =
  ## Builds a KEM response with its public ciphertext and shared secret.
  result = $(%*{
    "ok": true,
    "kind": kind,
    "algo": algo,
    "ciphertext": encodeBytes(ciphertext),
    "sharedSecret": encodeBytes(sharedSecret)
  })

proc processSymmetric(R: InteropRequest): string {.role: {actor}.} =
  ## Decrypts a browser payload or encrypts a native payload with basic_api.
  var
    algo: StreamCipherAlgorithm = parseStreamAlgo(R.algo)
    output: seq[uint8] = @[]
  case R.action
  of "symDecrypt":
    output = symDec(algo, R.key, R.nonce, R.payload)
  of "symEncrypt":
    output = symEnc(algo, R.key, R.nonce, R.message)
  else:
    raise newException(ValueError, "unsupported symmetric action: " & R.action)
  result = buildBytesResponse(R.action, R.algo, output)

proc processKem(R: InteropRequest): string {.role: {actor}.} =
  ## Decapsulates browser KEM traffic or creates native KEM traffic.
  var
    sharedSecret: seq[uint8] = @[]
    ciphertext: seq[uint8] = @[]
    kp: X25519TyrKeypair
    kyberCipher: KyberTyrCipher
  case R.action
  of "kemDecaps":
    case R.algo
    of "x25519":
      sharedSecret = x25519TyrShared(R.secretKey, R.payload)
    of "kyber768":
      sharedSecret = kyberTyrDecaps(kyber768, R.secretKey, R.payload)
    of "kyber1024":
      sharedSecret = kyberTyrDecaps(kyber1024, R.secretKey, R.payload)
    else:
      raise newException(ValueError, "unsupported KEM algorithm: " & R.algo)
    result = buildBytesResponse(R.action, R.algo, sharedSecret)
  of "kemEncaps":
    case R.algo
    of "x25519":
      kp = if R.seed.len == 0: x25519TyrKeypair() else: x25519TyrKeypairFromSeed(R.seed)
      ciphertext = kp.publicKey
      sharedSecret = x25519TyrShared(kp.secretKey, R.publicKey)
    of "kyber768":
      kyberCipher = kyberTyrEncaps(kyber768, R.publicKey, R.seed)
      ciphertext = kyberCipher.ciphertext
      sharedSecret = kyberCipher.sharedSecret
    of "kyber1024":
      kyberCipher = kyberTyrEncaps(kyber1024, R.publicKey, R.seed)
      ciphertext = kyberCipher.ciphertext
      sharedSecret = kyberCipher.sharedSecret
    else:
      raise newException(ValueError, "unsupported KEM algorithm: " & R.algo)
    result = buildKemResponse(R.action, R.algo, ciphertext, sharedSecret)
  else:
    raise newException(ValueError, "unsupported KEM action: " & R.action)

proc processInteropRequest*(raw: string): string {.role: {orchestrator}.} =
  ## Routes a WebUI JSON request to the native crypto backend without exposing errors.
  var R: InteropRequest
  try:
    R = parseRequest(raw)
    if R.action == "catalog":
      when defined(tyrWebUiInteropSmoke):
        return catalogPayload(true)
      else:
        return catalogPayload(false)
    if R.action == "setResultsPath":
      return $(%*{"ok": true, "path": setResultsDirectory(R.path).replace('\\', '/')})
    if R.action == "browseResultsPath":
      return browseDirectoryPayload(R.path)
    if R.action == "chooseResultsPath":
      return $(%*{"ok": true, "path": chooseResultsDirectory().replace('\\', '/')})
    if R.action == "startCatalogJob":
      return $spawnerRequest(%*{
        "action": "start",
        "id": R.id,
        "resultsPath": resultsDirectory()
      })
    if R.action == "pollCatalogJobs":
      return $spawnerRequest(%*{"action": "poll"})
    if R.action == "stopCatalogJob":
      return $spawnerRequest(%*{"action": "stop", "id": R.id})
    if R.action == "stopAllCatalogJobs":
      return $spawnerRequest(%*{"action": "stopAll"})
    if R.action == "recordInteropResult":
      return recordInteropResult(R.passed, R.durationMs, R.output)
    if R.action == "echo":
      return buildBytesResponse(R.action, R.algo, R.message)
    if R.action.startsWith("sym"):
      return processSymmetric(R)
    result = processKem(R)
  except CatchableError as exc:
    result = $(%*{"ok": false, "error": exc.msg})
