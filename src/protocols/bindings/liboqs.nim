import ../common

const
  oqsLibCandidates* = when defined(windows):
                        ["oqs.dll", "liboqs.dll"]
                      elif defined(macosx):
                        ["liboqs.dylib"]
                      else:
                        ["liboqs.so", "liboqs.so.4", "liboqs.so.5"]

type
  OqsStatus* = distinct cint
  OqsRandombytesCallback* = proc (random_array: ptr uint8,
    bytes_to_read: csize_t) {.cdecl.}
  OqsNistDrbgState* = object
    key*: array[32, uint8]
    v*: array[16, uint8]
    reseed_counter*: cint

proc `==`*(a, b: OqsStatus): bool =
  cint(a) == cint(b)

proc `!=`*(a, b: OqsStatus): bool =
  cint(a) != cint(b)

const
  oqsSuccess* = OqsStatus(0)
  oqsError* = OqsStatus(-1)

when defined(hasLibOqs):
  import std/[dynlib, os, strutils]
  import ../builders/liboqs_builder

  const moduleDir = splitFile(currentSourcePath()).dir

  proc repoRoot(): string =
    absolutePath(joinPath(moduleDir, "..", "..", ".."))

  proc defaultSourceDir(): string =
    let envSource = getEnv("LIBOQS_SOURCE").strip()
    if envSource.len > 0:
      return envSource
    let submoduleDir = joinPath(repoRoot(), "submodules", "liboqs")
    if dirExists(submoduleDir):
      return submoduleDir
    joinPath(parentDir(repoRoot()), "liboqs")

  proc defaultBuildRoot(): string =
    let envBuild = getEnv("LIBOQS_BUILD_ROOT").strip()
    if envBuild.len > 0:
      return envBuild
    joinPath(repoRoot(), "build", "liboqs")

  proc appendLibMatches(candidates: var seq[string], dirPath: string) =
    if dirExists(dirPath):
      let patterns = when defined(windows):
                       @["oqs.dll", "liboqs.dll"]
                     elif defined(macosx):
                       @["liboqs.dylib"]
                     else:
                       @["liboqs.so*"]
      for pattern in patterns:
        for candidate in walkPattern(joinPath(dirPath, pattern)):
          if fileExists(candidate) or symlinkExists(candidate):
            candidates.add(candidate)

  proc defaultLibCandidates(): seq[string] =
    var candidates: seq[string] = @[]
    let envLibDirs = getEnv("LIBOQS_LIB_DIRS").strip()
    if envLibDirs.len > 0:
      for dir in envLibDirs.split({';', ':'}):
        let trimmed = dir.strip()
        if trimmed.len > 0:
          appendLibMatches(candidates, trimmed)
    var sourceDir = defaultSourceDir()
    let buildRoot = defaultBuildRoot()
    appendLibMatches(candidates, joinPath(absolutePath(sourceDir), "build", "lib"))
    appendLibMatches(candidates, joinPath(absolutePath(sourceDir), "build", "bin"))
    appendLibMatches(candidates, joinPath(absolutePath(sourceDir), "build", "lib64"))
    appendLibMatches(candidates, joinPath(absolutePath(sourceDir), "build", "install", "lib"))
    appendLibMatches(candidates, joinPath(absolutePath(sourceDir), "build", "install", "lib64"))
    appendLibMatches(candidates, joinPath(moduleDir, "..", "..", "build", "liboqs", "install", "lib"))
    appendLibMatches(candidates, joinPath(moduleDir, "..", "..", "build", "liboqs", "install", "lib64"))
    appendLibMatches(candidates, joinPath(buildRoot, "install", "lib"))
    appendLibMatches(candidates, joinPath(buildRoot, "install", "bin"))
    appendLibMatches(candidates, joinPath(buildRoot, "build", "lib"))
    appendLibMatches(candidates, joinPath(buildRoot, "build", "bin"))
    candidates

  type
    OqsKem* = object
      method_name*: cstring
      alg_version*: cstring
      claimed_nist_level*: cint
      is_ind_cca*: cint
      length_public_key*: csize_t
      length_secret_key*: csize_t
      length_ciphertext*: csize_t
      length_shared_secret*: csize_t
      length_keypair_seed*: csize_t
      length_encaps_seed*: csize_t

    OqsSig* = object
      method_name*: cstring
      alg_version*: cstring
      claimed_nist_level*: cint
      is_euf_cma*: cint
      length_public_key*: csize_t
      length_secret_key*: csize_t
      length_signature*: csize_t

    KemNewProc = proc (algId: cstring): ptr OqsKem {.cdecl.}
    KemFreeProc = proc (kem: ptr OqsKem) {.cdecl.}
    KemKeypairDerandProc = proc (kem: ptr OqsKem, public_key, secret_key: ptr uint8,
      seed: ptr uint8): OqsStatus {.cdecl.}
    KemKeypairProc = proc (kem: ptr OqsKem, public_key, secret_key: ptr uint8): OqsStatus {.cdecl.}
    KemEncapsDerandProc = proc (kem: ptr OqsKem, ciphertext, shared_secret: ptr uint8,
      public_key, seed: ptr uint8): OqsStatus {.cdecl.}
    KemEncapsProc = proc (kem: ptr OqsKem, ciphertext, shared_secret: ptr uint8, public_key: ptr uint8): OqsStatus {.cdecl.}
    KemDecapsProc = proc (kem: ptr OqsKem, shared_secret: ptr uint8, ciphertext: ptr uint8, secret_key: ptr uint8): OqsStatus {.cdecl.}

    SigNewProc = proc (algId: cstring): ptr OqsSig {.cdecl.}
    SigFreeProc = proc (sig: ptr OqsSig) {.cdecl.}
    SigKeypairProc = proc (sig: ptr OqsSig, public_key, secret_key: ptr uint8): OqsStatus {.cdecl.}
    SigSignProc = proc (sig: ptr OqsSig, signature: ptr uint8, sigLenOut: ptr csize_t, msg: ptr uint8, msgLen: csize_t, secret_key: ptr uint8): OqsStatus {.cdecl.}
    SigVerifyProc = proc (sig: ptr OqsSig, msg: ptr uint8, msgLen: csize_t, signature: ptr uint8, sigLen: csize_t, public_key: ptr uint8): OqsStatus {.cdecl.}
    RandombytesSwitchProc = proc (algorithm: cstring): OqsStatus {.cdecl.}
    RandombytesCustomProc = proc (algorithm_ptr: OqsRandombytesCallback) {.cdecl.}
    RandombytesNistInitProc = proc (entropy_input, personalization_string: ptr uint8) {.cdecl.}
    RandombytesNistProc = proc (random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.}
    RandombytesNistGetStateProc = proc (out_state: pointer) {.cdecl.}
    RandombytesNistSetStateProc = proc (in_state: pointer) {.cdecl.}

  var
    oqsHandle: LibHandle
    oqsKemNew: KemNewProc
    oqsKemFree: KemFreeProc
    oqsKemKeypairDerand: KemKeypairDerandProc
    oqsKemKeypair: KemKeypairProc
    oqsKemEncapsDerand: KemEncapsDerandProc
    oqsKemEncaps: KemEncapsProc
    oqsKemDecaps: KemDecapsProc
    oqsSigNew: SigNewProc
    oqsSigFree: SigFreeProc
    oqsSigKeypair: SigKeypairProc
    oqsSigSign: SigSignProc
    oqsSigVerify: SigVerifyProc
    oqsRandombytesSwitch: RandombytesSwitchProc
    oqsRandombytesCustom: RandombytesCustomProc
    oqsRandombytesNistInit: RandombytesNistInitProc
    oqsRandombytesNist: RandombytesNistProc
    oqsRandombytesNistGetState: RandombytesNistGetStateProc
    oqsRandombytesNistSetState: RandombytesNistSetStateProc
    extraLibCandidates: seq[string] = defaultLibCandidates()
    builderAttempted: bool = false

  proc unloadOqs() =
    if oqsHandle != nil:
      unloadLib(oqsHandle)
      oqsHandle = nil
    builderAttempted = false

  proc loadSymbol[T](symName: string, target: var T): bool =
    let addrSym = symAddr(oqsHandle, symName)
    if addrSym.isNil:
      unloadOqs()
      return false
    target = cast[T](addrSym)
    true

  proc loadOqsSymbols(): bool =
    if oqsHandle != nil:
      return true
    if oqsHandle == nil:
      for candidate in extraLibCandidates:
        oqsHandle = loadLib(candidate)
        if oqsHandle != nil:
          break
    if oqsHandle == nil:
      for candidate in oqsLibCandidates:
        oqsHandle = loadLib(candidate)
        if oqsHandle != nil:
          break
    if oqsHandle == nil:
      if not builderAttempted:
        builderAttempted = true
        let defaultSource = defaultSourceDir()
        let buildRoot = defaultBuildRoot()
        if promptAndBuildLibOqs(extraLibCandidates, defaultSource, buildRoot):
          return loadOqsSymbols()
      return false
    if not loadSymbol("OQS_KEM_new", oqsKemNew): return false
    if not loadSymbol("OQS_KEM_free", oqsKemFree): return false
    if not loadSymbol("OQS_KEM_keypair_derand", oqsKemKeypairDerand): return false
    if not loadSymbol("OQS_KEM_keypair", oqsKemKeypair): return false
    if not loadSymbol("OQS_KEM_encaps_derand", oqsKemEncapsDerand): return false
    if not loadSymbol("OQS_KEM_encaps", oqsKemEncaps): return false
    if not loadSymbol("OQS_KEM_decaps", oqsKemDecaps): return false
    if not loadSymbol("OQS_SIG_new", oqsSigNew): return false
    if not loadSymbol("OQS_SIG_free", oqsSigFree): return false
    if not loadSymbol("OQS_SIG_keypair", oqsSigKeypair): return false
    if not loadSymbol("OQS_SIG_sign", oqsSigSign): return false
    if not loadSymbol("OQS_SIG_verify", oqsSigVerify): return false
    if not loadSymbol("OQS_randombytes_switch_algorithm", oqsRandombytesSwitch): return false
    if not loadSymbol("OQS_randombytes_custom_algorithm", oqsRandombytesCustom): return false
    let initSym = symAddr(oqsHandle, "OQS_randombytes_nist_kat_init_256bit")
    if not initSym.isNil:
      oqsRandombytesNistInit = cast[RandombytesNistInitProc](initSym)
    let nistSym = symAddr(oqsHandle, "OQS_randombytes_nist_kat")
    if not nistSym.isNil:
      oqsRandombytesNist = cast[RandombytesNistProc](nistSym)
    let getStateSym = symAddr(oqsHandle, "OQS_randombytes_nist_kat_get_state")
    if not getStateSym.isNil:
      oqsRandombytesNistGetState = cast[RandombytesNistGetStateProc](getStateSym)
    let setStateSym = symAddr(oqsHandle, "OQS_randombytes_nist_kat_set_state")
    if not setStateSym.isNil:
      oqsRandombytesNistSetState = cast[RandombytesNistSetStateProc](setStateSym)
    true

  proc ensureLibOqsLoaded*(): bool =
    loadOqsSymbols()

  proc requireLibOqs() =
    if not loadOqsSymbols():
      raiseUnavailable("liboqs", "hasLibOqs")

  proc OQS_KEM_new*(algId: cstring): ptr OqsKem =
    requireLibOqs()
    oqsKemNew(algId)

  proc OQS_KEM_free*(kem: ptr OqsKem) =
    requireLibOqs()
    oqsKemFree(kem)

  proc OQS_KEM_keypair_derand*(kem: ptr OqsKem, public_key, secret_key: ptr uint8,
      seed: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsKemKeypairDerand(kem, public_key, secret_key, seed)

  proc OQS_KEM_keypair*(kem: ptr OqsKem, public_key, secret_key: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsKemKeypair(kem, public_key, secret_key)

  proc OQS_KEM_encaps_derand*(kem: ptr OqsKem, ciphertext, shared_secret: ptr uint8,
      public_key, seed: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsKemEncapsDerand(kem, ciphertext, shared_secret, public_key, seed)

  proc OQS_KEM_encaps*(kem: ptr OqsKem, ciphertext, shared_secret: ptr uint8, public_key: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsKemEncaps(kem, ciphertext, shared_secret, public_key)

  proc OQS_KEM_decaps*(kem: ptr OqsKem, shared_secret: ptr uint8, ciphertext: ptr uint8, secret_key: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsKemDecaps(kem, shared_secret, ciphertext, secret_key)

  proc OQS_SIG_new*(algId: cstring): ptr OqsSig =
    requireLibOqs()
    oqsSigNew(algId)

  proc OQS_SIG_free*(sig: ptr OqsSig) =
    requireLibOqs()
    oqsSigFree(sig)

  proc OQS_SIG_keypair*(sig: ptr OqsSig, public_key, secret_key: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsSigKeypair(sig, public_key, secret_key)

  proc OQS_SIG_sign*(sig: ptr OqsSig, signature: ptr uint8, sigLenOut: ptr csize_t, msg: ptr uint8, msgLen: csize_t, secret_key: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsSigSign(sig, signature, sigLenOut, msg, msgLen, secret_key)

  proc OQS_SIG_verify*(sig: ptr OqsSig, msg: ptr uint8, msgLen: csize_t, signature: ptr uint8, sigLen: csize_t, public_key: ptr uint8): OqsStatus =
    requireLibOqs()
    oqsSigVerify(sig, msg, msgLen, signature, sigLen, public_key)

  proc OQS_randombytes_switch_algorithm*(algorithm: cstring): OqsStatus =
    requireLibOqs()
    oqsRandombytesSwitch(algorithm)

  proc OQS_randombytes_custom_algorithm*(algorithm_ptr: OqsRandombytesCallback) =
    requireLibOqs()
    oqsRandombytesCustom(algorithm_ptr)

  proc hasOqsNistKatDrbg*(): bool =
    requireLibOqs()
    result = oqsRandombytesNistInit != nil and oqsRandombytesNist != nil and
      oqsRandombytesNistGetState != nil and oqsRandombytesNistSetState != nil

  proc OQS_randombytes_nist_kat_init_256bit*(entropy_input, personalization_string: ptr uint8) =
    requireLibOqs()
    if oqsRandombytesNistInit == nil:
      raiseOperation("liboqs", "OQS_randombytes_nist_kat_init_256bit unavailable")
    oqsRandombytesNistInit(entropy_input, personalization_string)

  proc OQS_randombytes_nist_kat*(random_array: ptr uint8, bytes_to_read: csize_t) =
    requireLibOqs()
    if oqsRandombytesNist == nil:
      raiseOperation("liboqs", "OQS_randombytes_nist_kat unavailable")
    oqsRandombytesNist(random_array, bytes_to_read)

  proc OQS_randombytes_nist_kat_get_state*(out_state: pointer) =
    requireLibOqs()
    if oqsRandombytesNistGetState == nil:
      raiseOperation("liboqs", "OQS_randombytes_nist_kat_get_state unavailable")
    oqsRandombytesNistGetState(out_state)

  proc OQS_randombytes_nist_kat_set_state*(in_state: pointer) =
    requireLibOqs()
    if oqsRandombytesNistSetState == nil:
      raiseOperation("liboqs", "OQS_randombytes_nist_kat_set_state unavailable")
    oqsRandombytesNistSetState(in_state)

else:
  type
    OqsKem* = object
    OqsSig* = object

  proc ensureLibOqsLoaded*(): bool =
    false

  proc OQS_KEM_new*(algId: cstring): ptr OqsKem =
    discard algId
    raiseUnavailable("liboqs", "hasLibOqs")
    return nil

  proc OQS_KEM_free*(kem: ptr OqsKem) =
    discard kem
    raiseUnavailable("liboqs", "hasLibOqs")

  proc OQS_KEM_keypair_derand*(kem: ptr OqsKem, public_key, secret_key: ptr uint8,
      seed: ptr uint8): OqsStatus =
    discard kem
    discard public_key
    discard secret_key
    discard seed
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_KEM_keypair*(kem: ptr OqsKem, public_key, secret_key: ptr uint8): OqsStatus =
    discard kem
    discard public_key
    discard secret_key
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_KEM_encaps_derand*(kem: ptr OqsKem, ciphertext, shared_secret: ptr uint8,
      public_key, seed: ptr uint8): OqsStatus =
    discard kem
    discard ciphertext
    discard shared_secret
    discard public_key
    discard seed
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_KEM_encaps*(kem: ptr OqsKem, ciphertext, shared_secret: ptr uint8, public_key: ptr uint8): OqsStatus =
    discard kem
    discard ciphertext
    discard shared_secret
    discard public_key
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_KEM_decaps*(kem: ptr OqsKem, shared_secret: ptr uint8, ciphertext: ptr uint8, secret_key: ptr uint8): OqsStatus =
    discard kem
    discard shared_secret
    discard ciphertext
    discard secret_key
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_SIG_new*(algId: cstring): ptr OqsSig =
    discard algId
    raiseUnavailable("liboqs", "hasLibOqs")
    return nil

  proc OQS_SIG_free*(sig: ptr OqsSig) =
    discard sig
    raiseUnavailable("liboqs", "hasLibOqs")

  proc OQS_SIG_keypair*(sig: ptr OqsSig, public_key, secret_key: ptr uint8): OqsStatus =
    discard sig
    discard public_key
    discard secret_key
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_SIG_sign*(sig: ptr OqsSig, signature: ptr uint8, sigLenOut: ptr csize_t, msg: ptr uint8, msgLen: csize_t, secret_key: ptr uint8): OqsStatus =
    discard sig
    discard signature
    discard sigLenOut
    discard msg
    discard msgLen
    discard secret_key
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_SIG_verify*(sig: ptr OqsSig, msg: ptr uint8, msgLen: csize_t, signature: ptr uint8, sigLen: csize_t, public_key: ptr uint8): OqsStatus =
    discard sig
    discard msg
    discard msgLen
    discard signature
    discard sigLen
    discard public_key
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_randombytes_switch_algorithm*(algorithm: cstring): OqsStatus =
    discard algorithm
    raiseUnavailable("liboqs", "hasLibOqs")
    return oqsError

  proc OQS_randombytes_custom_algorithm*(algorithm_ptr: OqsRandombytesCallback) =
    raiseUnavailable("liboqs", "hasLibOqs")

  proc hasOqsNistKatDrbg*(): bool =
    false

  proc OQS_randombytes_nist_kat_init_256bit*(entropy_input, personalization_string: ptr uint8) =
    discard entropy_input
    discard personalization_string
    raiseUnavailable("liboqs", "hasLibOqs")

  proc OQS_randombytes_nist_kat*(random_array: ptr uint8, bytes_to_read: csize_t) =
    discard random_array
    discard bytes_to_read
    raiseUnavailable("liboqs", "hasLibOqs")

  proc OQS_randombytes_nist_kat_get_state*(out_state: pointer) =
    discard out_state
    raiseUnavailable("liboqs", "hasLibOqs")

  proc OQS_randombytes_nist_kat_set_state*(in_state: pointer) =
    discard in_state
    raiseUnavailable("liboqs", "hasLibOqs")

const
  ## Algorithm identifiers used across the project.
  oqsRandAlgSystem* = "system"
  oqsAlgKyber768* = "Kyber768"
  oqsAlgKyber1024* = "Kyber1024"
  oqsAlgKyber768_90s* = "Kyber768-90s"
  oqsAlgFrodoKEM976* = "FrodoKEM-976-AES"
  oqsAlgClassicMcEliece6688128* = "Classic-McEliece-6688128"
  oqsAlgClassicMcEliece6688128f* = "Classic-McEliece-6688128f"
  oqsAlgClassicMcEliece6960119* = "Classic-McEliece-6960119"
  oqsAlgClassicMcEliece6960119f* = "Classic-McEliece-6960119f"
  oqsAlgClassicMcEliece8192128* = "Classic-McEliece-8192128"
  oqsAlgClassicMcEliece8192128f* = "Classic-McEliece-8192128f"
  oqsAlgBike0* = "BIKE-L1" ## current lowest bound backend for bike0
  oqsAlgBIKEL1* = oqsAlgBike0
  oqsAlgNtruPrime0* = "sntrup761" ## current lowest bound backend for ntruprime0
  oqsAlgNtruPrimeSntrup761* = oqsAlgNtruPrime0

  oqsSigDilithium0* = "ML-DSA-44" ## original Dilithium2 / standardized ML-DSA-44
  oqsSigDilithium1* = "ML-DSA-65" ## original Dilithium3 / standardized ML-DSA-65
  oqsSigDilithium2* = "ML-DSA-87" ## original Dilithium5 / standardized ML-DSA-87
  oqsSigDilithium3* = oqsSigDilithium1
  oqsSigDilithium5* = oqsSigDilithium2
  oqsSigFalcon512* = "Falcon-512"
  oqsSigFalcon1024* = "Falcon-1024"
  oqsSigSphincsShake128fSimple* = "SPHINCS+-SHAKE-128f-simple"
  oqsSigSphincsHaraka128fSimple* = "SPHINCS+-SHAKE-128f-simple" ## current local backend binding for the kept 128f simple surface

proc requireSuccess*(status: OqsStatus, action: string) =
  if status != oqsSuccess:
    raiseOperation("liboqs", action & " failed")
