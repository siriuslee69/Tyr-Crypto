proc verifyCertificateChain*(leaf: X509Certificate,
    intermediates: seq[X509Certificate], trust: TrustStore, nowUnix: int64,
    host: string = ""): ChainVerifyResult {.role: {orchestrator}.} =
  ## leaf/intermediates/trust/nowUnix/host: the certificate to validate, any
  ## untrusted chain certificates the peer supplied, the trust anchors, the
  ## current time, and an optional hostname to match against the leaf.
  ##
  ## Walks from the leaf upward, checking validity, CA status, key usage and
  ## the signature at each hop, and succeeds only when a trust anchor signs
  ## the final certificate.
  var
    current: X509Certificate = leaf
    used: seq[int] = @[]
    depth, idx, i: int = 0
    sig: tuple[ok: bool, err: string] = default(tuple[ok: bool, err: string])
    identity: X509VerifyResult = default(X509VerifyResult)
  if trust.roots.len == 0:
    result.err = "trust store is empty"
    return
  if nowUnix < leaf.notBeforeUnix or nowUnix > leaf.notAfterUnix:
    result.err = "leaf certificate is outside its validity period"
    return
  if leaf.hasKeyUsage and not leaf.canDigitalSignature:
    result.err = "leaf certificate does not permit digital signatures"
    return
  if leaf.hasExtendedKeyUsage and not leaf.hasServerAuth:
    result.err = "leaf certificate does not permit server authentication"
    return
  if host.len > 0:
    identity = verifyCertificateIdentity(leaf, host)
    if not identity.ok:
      result.err = identity.err
      return
  while depth < maxChainDepth:
    # A trust anchor that issued the current certificate ends the walk.
    i = 0
    while i < trust.roots.len:
      if trust.roots[i].subjectDer == current.issuerDer:
        if nowUnix < trust.roots[i].notBeforeUnix or
            nowUnix > trust.roots[i].notAfterUnix:
          result.err = "trust anchor is outside its validity period"
          return
        sig = verifySignatureWithIssuer(current, trust.roots[i])
        if not sig.ok:
          result.err = sig.err
          return
        result.depth = depth + 1
        result.ok = true
        return
      i = i + 1
    # Otherwise continue through the supplied intermediates.
    idx = findIssuer(current, intermediates, used)
    if idx < 0:
      result.err = "no issuer found for certificate at depth " & $depth
      return
    if nowUnix < intermediates[idx].notBeforeUnix or
        nowUnix > intermediates[idx].notAfterUnix:
      result.err = "intermediate certificate is outside its validity period"
      return
    if not intermediates[idx].hasBasicConstraints or not intermediates[idx].isCa:
      result.err = "intermediate certificate is not a CA"
      return
    if intermediates[idx].hasKeyUsage and not intermediates[idx].canKeyCertSign:
      result.err = "intermediate certificate does not permit certificate signing"
      return
    ## pathLenConstraint counts the CA certificates allowed BELOW this one,
    ## not counting the leaf. `depth` is how many hops the walk has already
    ## taken, so at depth 0 the certificate being signed is the leaf and no
    ## CA sits below; at depth 1 exactly one does, and so on. An intermediate
    ## marked pathlen:0 that signed another CA is a certificate being used
    ## for more than it was issued for.
    if intermediates[idx].hasPathLen and depth > intermediates[idx].pathLen:
      result.err = "intermediate certificate exceeds its path length constraint"
      return
    sig = verifySignatureWithIssuer(current, intermediates[idx])
    if not sig.ok:
      result.err = sig.err
      return
    used.add(idx)
    current = intermediates[idx]
    depth = depth + 1
  result.err = "certificate chain exceeds the maximum depth"
