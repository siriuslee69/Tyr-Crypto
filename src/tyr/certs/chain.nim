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


import runePragmas
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
    rsaKey: RsaPublicKeyResult = default(RsaPublicKeyResult)
    ecKey: P256PublicKeyResult = default(P256PublicKeyResult)
    hash: tuple[ok: bool, hash: RsaHash] = default(tuple[ok: bool, hash: RsaHash])
    digest: tuple[ok: bool, digest: seq[byte]] = default(
      tuple[ok: bool, digest: seq[byte]])
    parsedSig: tuple[ok: bool, sig: EcdsaSignature, err: string] = default(
      tuple[ok: bool, sig: EcdsaSignature, err: string])
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


include "chain_path_checks.nim"
include "chain_path_building.nim"
