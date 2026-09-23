proc verifyPinnedServerCertificate*(leaf, root: X509Certificate,
    nowUnix: int64, host: string = ""): tuple[ok: bool, err: string] {.
    role: {actor}.} =
  ## leaf/root/nowUnix/host: pinned-root server-auth policy inputs.
  ## The algorithm-agnostic counterpart of
  ## `verifyPinnedEd25519ServerCertificate`, used when the pinned root or the
  ## leaf carries an RSA or ECDSA key instead of Ed25519.
  var
    sig: tuple[ok: bool, err: string] = default(tuple[ok: bool, err: string])
    identity: X509VerifyResult = default(X509VerifyResult)
  if nowUnix < leaf.notBeforeUnix or nowUnix > leaf.notAfterUnix:
    return (ok: false, err: "leaf certificate is outside its validity period")
  if nowUnix < root.notBeforeUnix or nowUnix > root.notAfterUnix:
    return (ok: false, err: "pinned root is outside its validity period")
  if not root.hasBasicConstraints or not root.isCa:
    return (ok: false, err: "pinned root is not an X.509 CA")
  if root.issuerDer != root.subjectDer:
    return (ok: false, err: "pinned root is not self-issued")
  if root.hasKeyUsage and not root.canKeyCertSign:
    return (ok: false, err: "pinned root does not permit certificate signing")
  sig = verifySignatureWithIssuer(root, root)
  if not sig.ok:
    return (ok: false, err: "pinned root self-signature is invalid: " & sig.err)
  if leaf.issuerDer != root.subjectDer:
    return (ok: false, err: "leaf issuer does not match pinned root subject")
  if leaf.hasKeyUsage and not leaf.canDigitalSignature:
    return (ok: false,
      err: "leaf certificate does not permit digital signatures")
  if leaf.hasExtendedKeyUsage and not leaf.hasServerAuth:
    return (ok: false,
      err: "leaf certificate does not permit server authentication")
  sig = verifySignatureWithIssuer(leaf, root)
  if not sig.ok:
    return (ok: false, err: sig.err)
  if host.len > 0:
    identity = verifyCertificateIdentity(leaf, host)
    if not identity.ok:
      return (ok: false, err: identity.err)
  result = (ok: true, err: "")

proc findIssuer(subject: X509Certificate, pool: seq[X509Certificate],
    used: seq[int]): int {.role: {dataFetcher}.} =
  ## subject/pool/used: certificate needing an issuer, candidates, and the
  ## indices already on the path (which prevents cycles).
  var i: int = 0
  result = -1
  while i < pool.len:
    if i notin used and pool[i].subjectDer == subject.issuerDer:
      return i
    i = i + 1
