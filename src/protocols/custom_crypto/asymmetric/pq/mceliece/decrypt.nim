## Niederreiter decryption for the pure-Nim Classic McEliece backend.

import ./params
import ./util
import ./gf
import ./bm
import ./root
import ./synd
import ./benes

proc decodeErrorVector*(p: McElieceParams, skTail, ciphertext: openArray[byte]): tuple[ok: bool, okMask: uint16, errorVec: seq[byte]] =
  ## Decode a Niederreiter ciphertext into the bit-packed error vector using the secret-key tail.
  ## `skTail` layout: irreducible polynomial || control bits || secret s.
  var
    g = newSeq[GF](p.sysT + 1)
    L = newSeq[GF](p.sysN)
    r = newSeq[byte](1 shl p.gfBits div 8)
    s0: seq[GF] = @[]
    sCmp: seq[GF] = @[]
    locator: seq[GF] = @[]
    images: seq[GF] = @[]
    check: GF = 0
    w: int = 0
    t: GF = 0
    condOffset = p.irrBytes
  defer:
    clearSensitiveWords(g)
    clearSensitiveWords(L)
    clearSensitiveWords(r)
    clearSensitiveWords(s0)
    clearSensitiveWords(sCmp)
    clearSensitiveWords(locator)
    clearSensitiveWords(images)
  if skTail.len < p.irrBytes + p.condBytes + (p.sysN div 8):
    raise newException(ValueError, "invalid McEliece secret key tail length")
  if ciphertext.len != p.syndBytes:
    raise newException(ValueError, "invalid McEliece ciphertext length")

  for i in 0 ..< p.syndBytes:
    r[i] = ciphertext[i]
  var fillIdx = p.syndBytes
  while fillIdx < r.len:
    r[fillIdx] = 0
    fillIdx = fillIdx + 1

  for i in 0 ..< p.sysT:
    g[i] = loadGF(skTail.toOpenArray(i * 2, i * 2 + 1))
  g[p.sysT] = 1
  supportGen(L, skTail.toOpenArray(condOffset, condOffset + p.condBytes - 1), p.gfBits, p.sysN)
  synd(p, g, L, r, s0)
  berlekampMassey(p, s0, locator)
  rootEval(p, locator, L, images)

  result.errorVec = newSeq[byte](p.sysN div 8)
  for i in 0 ..< p.sysN:
    t = gfIsZero(images[i]) and 1'u16
    result.errorVec[i div 8] = result.errorVec[i div 8] or byte(t shl (i mod 8))
    w = w + int(t)
  synd(p, g, L, result.errorVec, sCmp)
  check = GF(uint16(w xor p.sysT))
  for i in 0 ..< s0.len:
    check = check or (s0[i] xor sCmp[i])
  result.okMask = ctMaskZero(check)
  result.ok = result.okMask == 0xFFFF'u16
