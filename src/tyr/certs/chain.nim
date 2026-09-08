## ---------------------------------------------------------------------
## X.509 Chain <- multi-algorithm signature checks and WebPKI path building
## ---------------------------------------------------------------------
##
## Extends the pinned Ed25519 policy in `verify.nim` to the algorithms real
## certificate authorities actually issue: RSA PKCS#1 v1.5 and RSASSA-PSS
## with SHA-256/384/512, and ECDSA P-256 with SHA-256/384.
##
## Deliberate limits, enforced rather than assumed:
##  * P-384 and P-521 keys are refused; only prime256v1 is implemented.
##  * Revocation (CRL and OCSP) is out of scope and is not consulted.
##  * Name constraints are not evaluated, so a trusted CA is trusted for
##    every name. Keep the trust store narrow.


import tyrPragmas
import ./[oid, x509, verify]
import ./rsa
import ../signatures/ecdsa_p256
import ../hashes/sha512
import ../hashes/sha256
import ../signatures/ed25519

type
  ChainVerifyResult* {.role: {truthState}.} = object
    ok*: bool
    err*: string
    depth*: int ## number of issuers walked from the leaf to the trust anchor

  TrustStore* {.role: {truthState}.} = object
    roots*: seq[X509Certificate]

const
  maxChainDepth* = 8 ## bounds path building against adversarial bundles

proc initTrustStore*(): TrustStore {.role: {helper}.} =
  ## Return an empty trust store.
  result.roots = @[]

proc addTrustedRoot*(T: var TrustStore, C: X509Certificate): string {.
    role: {actor}.} =
  ## T/C: trust store and a candidate self-issued CA certificate.
  ## Returns an error string when the certificate cannot serve as an anchor.
  if not C.hasBasicConstraints or not C.isCa:
    return "trust anchor is not an X.509 CA"
  if C.issuerDer != C.subjectDer:
    return "trust anchor is not self-issued"
  if C.hasKeyUsage and not C.canKeyCertSign:
    return "trust anchor does not permit certificate signing"
  T.roots.add(C)
  result = ""

proc rsaHashForOid(sigOid: string): tuple[ok: bool, hash: RsaHash] {.
    role: {helper}.} =
  ## sigOid: certificate signature algorithm OID.
  case sigOid
  of oidSha256WithRsa:
    result = (ok: true, hash: rhSha256)
  of oidSha384WithRsa:
    result = (ok: true, hash: rhSha384)
  of oidSha512WithRsa:
    result = (ok: true, hash: rhSha512)
  of oidRsassaPss:
    # Without decoding the PSS parameter block the only safe assumption is
    # the ubiquitous SHA-256/MGF1-SHA-256/salt-32 profile.
    result = (ok: true, hash: rhSha256)
  else:
    result = (ok: false, hash: rhSha256)

proc ecdsaDigestForOid(sigOid: string, msg: openArray[byte]): tuple[
    ok: bool, digest: seq[byte]] {.role: {math}.} =
  ## sigOid/msg: signature algorithm OID and the signed TBS bytes.
  case sigOid
  of oidEcdsaWithSha256:
    result = (ok: true, digest: @(sha256Hash(msg)))
  of oidEcdsaWithSha384:
    result = (ok: true, digest: @(sha384Hash(msg)))
  else:
    result = (ok: false, digest: @[])

proc verifySignatureWithIssuer*(subject, issuer: X509Certificate): tuple[
    ok: bool, err: string] {.role: {actor}.} =
  ## subject/issuer: certificate to check and the certificate that signed it.
  ## Dispatches on the issuer's key algorithm and the subject's signature
  ## algorithm, refusing any combination that is not explicitly supported.
  var
    rsaKey: RsaPublicKeyResult
    ecKey: P256PublicKeyResult
    hash: tuple[ok: bool, hash: RsaHash]
    digest: tuple[ok: bool, digest: seq[byte]]
    parsedSig: tuple[ok: bool, sig: EcdsaSignature, err: string]
  case issuer.publicKeyAlgorithm
  of oidEd25519:
    if subject.signatureAlgorithm != oidEd25519:
      return (ok: false, err: "Ed25519 issuer cannot sign " &
        subject.signatureAlgorithm)
    if not ed25519TyrVerify(subject.tbsCertificate, subject.signature,
        issuer.publicKey):
      return (ok: false, err: "Ed25519 certificate signature is invalid")
    result = (ok: true, err: "")
  of oidRsaEncryption:
    hash = rsaHashForOid(subject.signatureAlgorithm)
    if not hash.ok:
      return (ok: false, err: "RSA issuer cannot sign " &
        subject.signatureAlgorithm)
    rsaKey = parseRsaSpki(issuer.publicKeySpki)
    if not rsaKey.ok:
      return (ok: false, err: "issuer RSA key is unusable: " & rsaKey.err)
    if subject.signatureAlgorithm == oidRsassaPss:
      if not rsaVerifyPssSha256(rsaKey.key, subject.tbsCertificate,
          subject.signature):
        return (ok: false, err: "RSASSA-PSS certificate signature is invalid")
    elif not rsaVerifyPkcs1v15(rsaKey.key, hash.hash, subject.tbsCertificate,
        subject.signature):
      return (ok: false, err: "RSA certificate signature is invalid")
    result = (ok: true, err: "")
  of oidEcPublicKey:
    digest = ecdsaDigestForOid(subject.signatureAlgorithm,
      subject.tbsCertificate)
    if not digest.ok:
      return (ok: false, err: "EC issuer cannot sign " &
        subject.signatureAlgorithm)
    ecKey = parseP256Spki(issuer.publicKeySpki)
    if not ecKey.ok:
      return (ok: false, err: "issuer EC key is unusable: " & ecKey.err)
    parsedSig = parseEcdsaSignatureDer(subject.signature)
    if not parsedSig.ok:
      return (ok: false, err: "ECDSA signature encoding is invalid: " &
        parsedSig.err)
    if not ecdsaVerifyP256WithDigest(ecKey.point, digest.digest, parsedSig.sig):
      return (ok: false, err: "ECDSA certificate signature is invalid")
    result = (ok: true, err: "")
  else:
    result = (ok: false, err: "issuer key algorithm is unsupported: " &
      issuer.publicKeyAlgorithm)

proc verifyPinnedServerCertificate*(leaf, root: X509Certificate,
    nowUnix: int64, host: string = ""): tuple[ok: bool, err: string] {.
    role: {actor}.} =
  ## leaf/root/nowUnix/host: pinned-root server-auth policy inputs.
  ## The algorithm-agnostic counterpart of
  ## `verifyPinnedEd25519ServerCertificate`, used when the pinned root or the
  ## leaf carries an RSA or ECDSA key instead of Ed25519.
  var
    sig: tuple[ok: bool, err: string]
    identity: X509VerifyResult
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
    sig: tuple[ok: bool, err: string]
    identity: X509VerifyResult
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
