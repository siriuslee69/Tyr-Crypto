## ---------------------------------------------------------------------
## | X-Wing <- draft-11 test vectors, roundtrip, and malformed input     |
## ---------------------------------------------------------------------
##
## `xwing_vectors.txt` is Appendix C of draft-connolly-cfrg-xwing-kem-11,
## copied byte for byte. Each vector fixes the secret key (seed) and the
## encapsulation randomness (eseed), so pk, ct and ss must match exactly.

import std/[os, strutils, unittest]

import runePragmas
import ../../src/tyr/kems
import ../../src/tyr/kems/dynamic as kemDyn

type
  XWingVector {.role: preparedData.} = object
    seed, pk, eseed, ct, ss: seq[byte]

proc hexBytes(s: string): seq[byte] {.role: parser.} =
  ## s: even-length hex text.
  var
    i: int = 0
  result = newSeq[byte](s.len div 2)
  while i < result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))
    i = i + 1

proc setField(V: var XWingVector, name, hex: string) {.role: parser.} =
  ## V/name/hex: the vector being filled, the field name, its hex value.
  case name
  of "seed": V.seed = hexBytes(hex)
  of "pk": V.pk = hexBytes(hex)
  of "eseed": V.eseed = hexBytes(hex)
  of "ct": V.ct = hexBytes(hex)
  of "ss": V.ss = hexBytes(hex)
  else: raise newException(ValueError, "unknown X-Wing vector field " & name)

proc loadVectors(): seq[XWingVector] {.role: dataFetcher.} =
  ## Read every vector from the file next to this test.
  var
    cur: XWingVector = default(XWingVector)
    parts: seq[string] = @[]
  for line in lines(currentSourcePath().parentDir / "xwing_vectors.txt"):
    if line.startsWith("#"):
      continue
    if line.strip().len == 0:
      if cur.seed.len > 0: result.add(cur)
      cur = default(XWingVector)
      continue
    parts = line.splitWhitespace()
    setField(cur, parts[0], parts[1])
  if cur.seed.len > 0: result.add(cur)

suite "x-wing":
  # {.testKind: tkRegression, covers: "xwingTyrKeypair, xwingTyrEncaps, xwingTyrDecaps".}
  test "all draft-11 Appendix C vectors match byte for byte":
    var
      V: seq[XWingVector] = loadVectors()
      kp: XWingTyrKeypair = default(XWingTyrKeypair)
      env: XWingTyrCipher = default(XWingTyrCipher)
    check V.len == 3
    for v in V:
      kp = xwingTyrKeypair(xwing768, v.seed)
      check kp.publicKey == v.pk
      env = xwingTyrEncaps(xwing768, v.pk, v.eseed)
      check env.ciphertext == v.ct
      check env.sharedSecret == v.ss
      check xwingTyrDecaps(xwing768, v.seed, v.ct) == v.ss

  # {.testKind: tkSmoke, covers: "xwingTyrKeypair, xwingTyrEncaps, xwingTyrDecaps".}
  test "random keypair roundtrip and sizes":
    var
      kp = xwingTyrKeypair()
      env = xwingTyrEncaps(xwing768, kp.publicKey)
    check kp.secretKey.len == xwingSecretKeyBytes
    check kp.publicKey.len == xwingPublicKeyBytes
    check env.ciphertext.len == xwingCiphertextBytes
    check xwingTyrDecaps(xwing768, kp.secretKey, env.ciphertext) == env.sharedSecret

  # {.testKind: tkEdgeCase, covers: "xwingTyrDecaps".}
  test "a tampered ML-KEM part gives a different secret, not an error":
    var
      kp = xwingTyrKeypair()
      env = xwingTyrEncaps(xwing768, kp.publicKey)
      bad: seq[byte] = env.ciphertext
    bad[0] = bad[0] xor 1'u8
    check xwingTyrDecaps(xwing768, kp.secretKey, bad) != env.sharedSecret

  # {.testKind: tkEdgeCase, covers: "xwingTyrEncaps, xwingTyrDecaps".}
  test "wrong lengths and a zero X25519 part are refused":
    var
      kp = xwingTyrKeypair()
      env = xwingTyrEncaps(xwing768, kp.publicKey)
      zeroX: seq[byte] = env.ciphertext
      i: int = 1088
    while i < zeroX.len:
      zeroX[i] = 0
      i = i + 1
    expect ValueError:
      discard xwingTyrEncaps(xwing768, kp.publicKey[0 ..< 1215])
    expect ValueError:
      discard xwingTyrDecaps(xwing768, kp.secretKey, env.ciphertext[0 ..< 1119])
    expect ValueError:
      discard xwingTyrDecaps(xwing768, kp.secretKey[0 ..< 31], env.ciphertext)
    expect ValueError:
      discard xwingTyrDecaps(xwing768, kp.secretKey, zeroX)

  # {.testKind: tkIntegration, covers: "keypair, encaps, decaps, keypairOf, encapsOf, decapsOf".}
  test "the typed and the runtime tier agree on X-Wing":
    var
      seed: seq[byte] = newSeq[byte](32)
      a: kemDyn.AnyKem = kemDyn.AnyKem(family: kfXWing, xwing: xwing768)
      kp: KemKeypair = default(KemKeypair)
      c: KemCiphertext = default(KemCiphertext)
    seed[0] = 7
    kp = keypair(xwing768, seed)
    check kp.family == kfXWing
    check kemDyn.keypairOf(a, seed).public == kp.public
    c = kemDyn.encapsOf(a, kp.public)
    check decaps(xwing768, kp.secret, c.ciphertext) == c.shared
    check familyName(kfXWing) == "xwing"
    check parseKemFamily("xwing") == kfXWing
