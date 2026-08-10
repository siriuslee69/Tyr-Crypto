## -----------------------------------------------------------------------
## X.509 Verify <- pinned Ed25519 trust, time, usage, and SAN identity policy
## -----------------------------------------------------------------------

import std/[net, strutils]
import metaPragmas
import ../custom_crypto/ed25519
import ./x509

type
  X509VerifyResult* = object
    ok*: bool
    err*: string

proc validDnsLabel(s: string): bool {.role: {parser}.} =
  var i: int = 0
  if s.len == 0 or s.len > 63 or s[0] == '-' or s[^1] == '-':
    return false
  while i < s.len:
    if not ((s[i] >= 'a' and s[i] <= 'z') or
        (s[i] >= '0' and s[i] <= '9') or s[i] == '-'):
      return false
    i = i + 1
  result = true

proc validAsciiDnsName(s: string): bool {.role: {parser}.} =
  var
    P: seq[string] = s.split('.')
    i: int = 0
  if s.len == 0 or s.len > 253 or s[0] == '.' or s[^1] == '.':
    return false
  while i < P.len:
    if not validDnsLabel(P[i]):
      return false
    i = i + 1
  result = true

proc matchDnsPattern*(pattern, host: string): bool {.role: {actor}.} =
  ## pattern/host: lowercase ASCII SAN pattern and requested DNS host.
  var
    p: string = pattern.strip().toLowerAscii()
    h: string = host.strip().toLowerAscii()
    suffix: string = ""
    firstDot: int = -1
  if p.startsWith("*."):
    suffix = p[2 .. ^1]
    if suffix.find('.') < 0 or not validAsciiDnsName(suffix) or
        not validAsciiDnsName(h):
      return false
    firstDot = h.find('.')
    if firstDot <= 0:
      return false
    return h[firstDot + 1 .. ^1] == suffix
  if p.find('*') >= 0 or not validAsciiDnsName(p) or not validAsciiDnsName(h):
    return false
  result = p == h

proc verifyCertificateIdentity*(C: X509Certificate, host: string):
    X509VerifyResult {.role: {actor}.} =
  ## C/host: parsed certificate and expected ASCII DNS identity.
  var
    i, j: int = 0
    ip: IpAddress
    ipBytes: seq[byte] = @[]
    normalized: string = host.strip()
  if host.len == 0:
    result.err = "expected server hostname is empty"
    return
  if normalized.len >= 2 and normalized[0] == '[' and normalized[^1] == ']':
    normalized = normalized[1 .. ^2]
  if isIpAddress(normalized):
    try:
      ip = parseIpAddress(normalized)
    except ValueError:
      result.err = "expected server IP address is invalid"
      return
    case ip.family
    of IpAddressFamily.IPv4:
      ipBytes = newSeq[byte](4)
      while j < 4:
        ipBytes[j] = ip.address_v4[j]
        j = j + 1
    of IpAddressFamily.IPv6:
      ipBytes = newSeq[byte](16)
      while j < 16:
        ipBytes[j] = ip.address_v6[j]
        j = j + 1
    while i < C.ipAddresses.len:
      if C.ipAddresses[i] == ipBytes:
        result.ok = true
        return
      i = i + 1
    result.err = "certificate IP Subject Alternative Name does not match"
    return
  if C.dnsNames.len == 0:
    result.err = "certificate has no DNS Subject Alternative Name"
    return
  while i < C.dnsNames.len:
    if matchDnsPattern(C.dnsNames[i], normalized):
      result.ok = true
      return
    i = i + 1
  result.err = "certificate DNS Subject Alternative Name does not match"

proc verifyPinnedEd25519ServerCertificate*(leaf, root: X509Certificate,
    nowUnix: int64, host: string = ""): X509VerifyResult {.role: {actor}.} =
  ## leaf/root/nowUnix/host: controlled pinned-root server-auth policy inputs.
  if nowUnix < leaf.notBeforeUnix or nowUnix > leaf.notAfterUnix:
    result.err = "leaf certificate is outside its validity period"
    return
  if nowUnix < root.notBeforeUnix or nowUnix > root.notAfterUnix:
    result.err = "root certificate is outside its validity period"
    return
  if not root.hasBasicConstraints or not root.isCa:
    result.err = "pinned root is not an X.509 CA"
    return
  if root.issuerDer != root.subjectDer:
    result.err = "pinned root is not self-issued"
    return
  if root.hasKeyUsage and not root.canKeyCertSign:
    result.err = "pinned root does not permit certificate signing"
    return
  if not ed25519TyrVerify(root.tbsCertificate, root.signature,
      root.publicKey):
    result.err = "pinned root Ed25519 signature is invalid"
    return
  if leaf.issuerDer != root.subjectDer:
    result.err = "leaf issuer does not match pinned root subject"
    return
  if leaf.hasKeyUsage and not leaf.canDigitalSignature:
    result.err = "leaf certificate does not permit digital signatures"
    return
  if leaf.hasExtendedKeyUsage and not leaf.hasServerAuth:
    result.err = "leaf certificate does not permit server authentication"
    return
  if not ed25519TyrVerify(leaf.tbsCertificate, leaf.signature, root.publicKey):
    result.err = "leaf certificate Ed25519 signature is invalid"
    return
  if host.len > 0:
    result = verifyCertificateIdentity(leaf, host)
    return
  result.ok = true
