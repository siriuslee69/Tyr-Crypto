## -------------------------------------------------------------
## Research Paper Downloader <- lockfile-driven PDF restorer
## -------------------------------------------------------------

import std/[httpclient, json, os, strutils]

type
  DownloadOptions* = object
    lockPath*: string
    includeTracked*: bool
    force*: bool

proc normalizeRepoPath(path: string): string =
  result = path.replace("/", $DirSep)

proc findRepoRoot(startDir: string): string =
  var
    dir: string = absolutePath(startDir)
    parent: string = ""
  while dir.len > 0:
    if fileExists(joinPath(dir, "tyr_crypto.nimble")):
      return dir
    parent = parentDir(dir)
    if parent == dir:
      break
    dir = parent
  raise newException(IOError, "could not find Tyr repo root from " & startDir)

const
  sha256Init: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]
  sha256K: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
    0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
    0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
    0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
    0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
    0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
    0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
    0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
    0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]
  hexDigits = "0123456789abcdef"

proc rotr(x: uint32, n: int): uint32 {.inline.} =
  result = (x shr n) or (x shl (32 - n))

proc sha256Hex(data: string): string =
  var
    msg: seq[byte] = newSeq[byte](data.len)
    bitLen: uint64 = uint64(data.len) * 8'u64
    H: array[8, uint32] = sha256Init
    W: array[64, uint32]
    off: int = 0
    i: int = 0
    j: int = 0
    s0, s1, ch, maj, temp1, temp2: uint32 = 0
    a, b, c, d, e, f, g, h: uint32 = 0
  i = 0
  while i < data.len:
    msg[i] = byte(ord(data[i]))
    i = i + 1
  msg.add(0x80'u8)
  while (msg.len mod 64) != 56:
    msg.add(0'u8)
  i = 7
  while i >= 0:
    msg.add(byte((bitLen shr (i * 8)) and 0xff'u64))
    i = i - 1
  off = 0
  while off < msg.len:
    i = 0
    while i < 16:
      j = off + i * 4
      W[i] = (uint32(msg[j]) shl 24) or (uint32(msg[j + 1]) shl 16) or
        (uint32(msg[j + 2]) shl 8) or uint32(msg[j + 3])
      i = i + 1
    i = 16
    while i < 64:
      s0 = rotr(W[i - 15], 7) xor rotr(W[i - 15], 18) xor (W[i - 15] shr 3)
      s1 = rotr(W[i - 2], 17) xor rotr(W[i - 2], 19) xor (W[i - 2] shr 10)
      W[i] = W[i - 16] + s0 + W[i - 7] + s1
      i = i + 1
    a = H[0]
    b = H[1]
    c = H[2]
    d = H[3]
    e = H[4]
    f = H[5]
    g = H[6]
    h = H[7]
    i = 0
    while i < 64:
      s1 = rotr(e, 6) xor rotr(e, 11) xor rotr(e, 25)
      ch = (e and f) xor ((not e) and g)
      temp1 = h + s1 + ch + sha256K[i] + W[i]
      s0 = rotr(a, 2) xor rotr(a, 13) xor rotr(a, 22)
      maj = (a and b) xor (a and c) xor (b and c)
      temp2 = s0 + maj
      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2
      i = i + 1
    H[0] = H[0] + a
    H[1] = H[1] + b
    H[2] = H[2] + c
    H[3] = H[3] + d
    H[4] = H[4] + e
    H[5] = H[5] + f
    H[6] = H[6] + g
    H[7] = H[7] + h
    off = off + 64
  result = newString(64)
  i = 0
  while i < 8:
    j = 0
    while j < 4:
      var byteValue = byte((H[i] shr ((3 - j) * 8)) and 0xff'u32)
      result[i * 8 + j * 2] = hexDigits[int(byteValue shr 4)]
      result[i * 8 + j * 2 + 1] = hexDigits[int(byteValue and 0x0f'u8)]
      j = j + 1
    i = i + 1

proc sha256HexForFile*(path: string): string =
  var
    data: string = readFile(path)
  result = sha256Hex(data)

proc fileMatchesSha256*(path, expected: string): bool =
  if not fileExists(path):
    return false
  result = sha256HexForFile(path) == expected.toLowerAscii()

proc parseDownloadOptions*(defaultLockPath: string): DownloadOptions =
  var
    i: int = 1
    arg: string = ""
  result.lockPath = defaultLockPath
  while i <= paramCount():
    arg = paramStr(i)
    if arg == "--":
      discard
    elif arg == "--includeTracked" or arg == "--include-tracked":
      result.includeTracked = true
    elif arg == "--force":
      result.force = true
    elif arg.startsWith("--lockPath:"):
      result.lockPath = arg.split(":", 1)[1]
    elif arg.startsWith("--lockPath="):
      result.lockPath = arg.split("=", 1)[1]
    elif arg == "--lockPath" and i < paramCount():
      i = i + 1
      result.lockPath = paramStr(i)
    else:
      raise newException(ValueError, "unknown argument: " & arg)
    i = i + 1

proc downloadFileChecked(client: HttpClient, url, target: string) =
  client.downloadFile(url, target)

proc restoreDocument(client: HttpClient, repoRoot: string, document: JsonNode,
    options: DownloadOptions) =
  var
    localPath: string = document["localPath"].getStr()
    pdfUrl: string = document["pdfUrl"].getStr()
    expected: string = document["sha256"].getStr().toLowerAscii()
    gitPolicy: string = document["gitPolicy"].getStr()
    target: string = joinPath(repoRoot, normalizeRepoPath(localPath))
    targetDir: string = parentDir(target)
    tmp: string = target & ".download"
    actual: string = ""
  if gitPolicy == "tracked" and not options.includeTracked:
    return
  createDir(targetDir)
  if not options.force and fileMatchesSha256(target, expected):
    echo "ok   " & localPath
    return
  if fileExists(tmp):
    removeFile(tmp)
  echo "get  " & localPath
  downloadFileChecked(client, pdfUrl, tmp)
  actual = sha256HexForFile(tmp)
  if actual != expected:
    removeFile(tmp)
    raise newException(ValueError, "sha256 mismatch for " & localPath &
      ": expected " & expected & ", got " & actual)
  if fileExists(target):
    removeFile(target)
  moveFile(tmp, target)

proc runResearchPaperDownloader*(defaultLockPath: string) =
  var
    options: DownloadOptions = parseDownloadOptions(defaultLockPath)
    lockPath: string = absolutePath(options.lockPath)
    repoRoot: string = findRepoRoot(parentDir(lockPath))
    manifest: JsonNode = parseFile(lockPath)
    client: HttpClient = newHttpClient()
    docs: JsonNode = manifest["documents"]
    i: int = 0
  while i < docs.len:
    restoreDocument(client, repoRoot, docs[i], options)
    i = i + 1
