## ---------------------------------------------------------------------
## | HQC Params <- every fixed number the three HQC parameter sets use  |
## ---------------------------------------------------------------------
##
## HQC in one picture
## ------------------
## HQC hides a short message inside a very long, deliberately noisy
## bit string. Only somebody holding the secret can strip the noise off:
##
##   message m  ->  [ error-correcting code ]  ->  codeword
##   codeword   +   noise (a few thousand flipped bits)  ->  ciphertext
##   ciphertext -   noise removed by the secret  ->  codeword  ->  m
##
## Everything below is a length or a count used by that machinery.
##
## Reference: [HQC-20250822] Hamming Quasi-Cyclic specification of
## 2025-08-22, parameter tables; matched against the reference C
## implementation shipped with liboqs (`src/kem/hqc/pqc-hqc_hqc-*_ref`).

type
  ## The three published HQC parameter sets. The digit is the NIST
  ## security category, not a bit length.
  HqcVariant* = enum
    hqc1,   ## category 1, comparable to AES-128
    hqc3,   ## category 3, comparable to AES-192
    hqc5    ## category 5, comparable to AES-256

  ## Every fixed number for one parameter set, in one record.
  ##
  ##   n        length of the big vectors, IN BITS
  ##   n1       length of the Reed-Solomon codeword, IN BYTES
  ##   n2       length of one duplicated Reed-Muller block, IN BITS
  ##   n1n2     n1 * n2, the concatenated codeword length IN BITS
  ##   omega    how many 1-bits the secret vectors x and y carry
  ##   omegaR   how many 1-bits the encryption vectors r1 and r2 carry
  ##   omegaE   how many 1-bits the encryption error vector e carries
  HqcParams* = object
    name*: string
    n*: int
    n1*: int
    n2*: int
    n1n2*: int
    omega*: int
    omegaE*: int
    omegaR*: int
    messageBytes*: int        ## PARAM_K == PARAM_SECURITY_BYTES
    delta*: int               ## Reed-Solomon error-correcting capacity
    genPolyLen*: int          ## PARAM_G, coefficients in the RS generator
    fftExp*: int              ## PARAM_FFT, the additive FFT works on 2^fftExp points
    barrettMu*: uint64        ## floor(2^32 / n), for reduction without division
    rejectThreshold*: uint32  ## 24-bit samples at or above this are thrown away
    vecNWords*: int           ## 64-bit words needed to hold n bits
    vecNBytes*: int           ## bytes needed to hold n bits
    vecN1n2Words*: int        ## 64-bit words needed to hold n1n2 bits
    vecN1n2Bytes*: int        ## bytes needed to hold n1n2 bits
    multiplicity*: int        ## how many times each 128-bit RM word repeats
    publicKeyBytes*: int
    secretKeyBytes*: int
    ciphertextBytes*: int
    sharedSecretBytes*: int
    keypairRandomBytes*: int  ## bytes of randomness one keypair consumes
    encapsRandomBytes*: int   ## bytes of randomness one encapsulation consumes

const
  hqcSeedBytes* = 32
    ## Every seed HQC hands to a SHAKE-256 stream is this long.
  hqcSaltBytes* = 16
    ## Fresh per-encapsulation salt, sent in the clear inside the ciphertext.
  hqcSharedSecretBytes* = 32
    ## Every parameter set agrees on a 32-byte shared secret.
  hqcGfM* = 8
    ## The Reed-Solomon code lives in GF(2^8): one field element is one byte.
  hqcGfPoly* = 0x11D
    ## x^8 + x^4 + x^3 + x^2 + 1, the polynomial that defines GF(2^8).
  hqcGfMulOrder* = 255
    ## 2^8 - 1. Every non-zero field element is alpha^k for some k below this.

  ## Ceilings used to size stack buffers so no code path has to allocate.
  hqcMaxN1* = 90              ## largest n1 (HQC-5)
  hqcMaxDelta* = 29           ## largest delta (HQC-5)
  hqcMaxOmegaR* = 149         ## largest omegaR (HQC-5)
  hqcMaxGenPolyLen* = 59      ## largest genPolyLen (HQC-5)
  hqcMaxMessageBytes* = 32    ## largest messageBytes (HQC-5)
  hqcMaxFftExp* = 5           ## largest fftExp (HQC-3 and HQC-5)

## ╭⟢ Reed-Solomon generator polynomials
##
## One list per parameter set, lowest-degree coefficient first. These are
## the coefficients of g(x) = (x - alpha^1)(x - alpha^2)...(x - alpha^2delta)
## already multiplied out, so nothing has to recompute them at run time.
## They are copied verbatim from `RS_POLY_COEFS` in the reference
## implementation's `parameters.h`.

const
  hqc1GenPoly*: array[31, uint16] = [
    89'u16, 69, 153, 116, 176, 117, 111, 75, 73, 233,
    242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1]

  hqc3GenPoly*: array[33, uint16] = [
    45'u16, 216, 239, 24, 253, 104, 27, 40, 107, 50,
    163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
    238, 164, 82, 43, 15, 232, 246, 142, 50, 189,
    29, 232, 1]

  hqc5GenPoly*: array[59, uint16] = [
    49'u16, 167, 49, 39, 200, 121, 124, 91, 240, 63,
    148, 71, 150, 123, 87, 101, 32, 215, 159, 71,
    201, 115, 97, 210, 186, 183, 141, 217, 123, 12,
    31, 243, 180, 219, 152, 239, 99, 141, 4, 246,
    191, 144, 8, 232, 47, 27, 141, 178, 130, 64,
    124, 47, 39, 188, 216, 48, 199, 187, 1]

## Reference: [HQC-20250822] parameter tables; derived sizes for `buildHqcParams`; pitfall: every length below is load-bearing, so change one only together with the specification it came from.
proc buildHqcParams(name: string, n, n1, n2, n1n2, omega, omegaE, omegaR,
    messageBytes, delta, genPolyLen, fftExp: int, barrettMu: uint64,
    rejectThreshold: uint32): HqcParams {.raises: [].} =
  ## name..rejectThreshold: the numbers the specification prints; the rest
  ## of the record is worked out from them so no size can drift apart.
  result.name = name
  result.n = n
  result.n1 = n1
  result.n2 = n2
  result.n1n2 = n1n2
  result.omega = omega
  result.omegaE = omegaE
  result.omegaR = omegaR
  result.messageBytes = messageBytes
  result.delta = delta
  result.genPolyLen = genPolyLen
  result.fftExp = fftExp
  result.barrettMu = barrettMu
  result.rejectThreshold = rejectThreshold
  result.vecNWords = (n + 63) div 64
  result.vecNBytes = (n + 7) div 8
  result.vecN1n2Words = (n1n2 + 63) div 64
  result.vecN1n2Bytes = (n1n2 + 7) div 8
  result.multiplicity = (n2 + 127) div 128
  result.sharedSecretBytes = hqcSharedSecretBytes
  ## public key  = seed_ek (32) || s (n bits)
  result.publicKeyBytes = hqcSeedBytes + result.vecNBytes
  ## secret key  = public key || seed_dk (32) || sigma || seed_kem (32)
  result.secretKeyBytes = result.publicKeyBytes + hqcSeedBytes +
    messageBytes + hqcSeedBytes
  ## ciphertext  = u (n bits) || v (n1n2 bits) || salt (16)
  result.ciphertextBytes = result.vecNBytes + result.vecN1n2Bytes + hqcSaltBytes
  ## key generation draws one 32-byte seed; everything else grows from it.
  result.keypairRandomBytes = hqcSeedBytes
  ## encapsulation draws the message and then the salt, in that order.
  result.encapsRandomBytes = messageBytes + hqcSaltBytes

const hqcParamsTable*: array[HqcVariant, HqcParams] = [
  hqc1: buildHqcParams("hqc-1", 17669, 46, 384, 17664, 66, 75, 75,
    16, 15, 31, 4, 243079'u64, 16767881'u32),
  hqc3: buildHqcParams("hqc-3", 35851, 56, 640, 35840, 100, 114, 114,
    24, 16, 33, 5, 119800'u64, 16742417'u32),
  hqc5: buildHqcParams("hqc-5", 57637, 90, 640, 57600, 131, 149, 149,
    32, 29, 59, 5, 74517'u64, 16772367'u32)
]

## Reference: [HQC-20250822] parameter tables; parameter-set lookup for `params`; pitfall: preserve the published lengths exactly.
proc params*(v: HqcVariant): HqcParams {.inline, raises: [].} =
  ## v: which parameter set.
  ## Return the fixed number bundle for one HQC parameter set.
  result = hqcParamsTable[v]

## Reference: [HQC-20250822] Reed-Solomon generator polynomial tables; generator lookup for `genPoly`; pitfall: coefficients are ordered lowest degree first.
proc genPoly*(v: HqcVariant): seq[uint16] {.raises: [].} =
  ## v: which parameter set.
  ## Return the Reed-Solomon generator polynomial, lowest degree first.
  case v
  of hqc1: result = @hqc1GenPoly
  of hqc3: result = @hqc3GenPoly
  of hqc5: result = @hqc5GenPoly

## Reference: [HQC-20250822] parameter tables; stable text naming for `variantName`; pitfall: these names are stored in configs, so they must not drift.
proc variantName*(v: HqcVariant): string {.raises: [].} =
  ## v: which parameter set.
  ## Short stable text name, safe to store in a config or a log line.
  result = hqcParamsTable[v].name

## Reference: [HQC-20250822] parameter tables; stable text naming for `parseHqcVariant`; pitfall: an unknown name must never silently select a different parameter set.
proc parseHqcVariant*(s: string): HqcVariant {.raises: [ValueError].} =
  ## s: a name produced by `variantName`.
  ## Turn stored text back into a parameter set. Raises on anything unknown.
  case s
  of "hqc-1", "hqc1": result = hqc1
  of "hqc-3", "hqc3": result = hqc3
  of "hqc-5", "hqc5": result = hqc5
  else: raise newException(ValueError, "unknown HQC variant: " & s)
