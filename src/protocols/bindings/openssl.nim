import ../common

const
  opensslLibNames* = when defined(windows):
                       @["libcrypto-3-x64.dll"]
                     elif defined(macosx):
                       @["libcrypto.3.dylib", "libcrypto.dylib"]
                     else:
                       @["libcrypto.so.3", "libcrypto.so"]
  opensslLib* = when defined(windows):
                  "libcrypto-3-x64.dll"
                elif defined(macosx):
                  "libcrypto.3.dylib"
                else:
                  "libcrypto.so(|.3)"

const
  EVP_PKEY_ED448* = 1087

type
  OsslStatus* = distinct cint

const
  osslSuccess* = OsslStatus(1)
  osslFailure* = OsslStatus(0)

when defined(hasOpenSSL3):
  import std/[dynlib, os, strutils]
  import ../builders/openssl_builder

  const
    moduleDir = splitFile(currentSourcePath()).dir

  type
    EVP_PKEY* = object
    EVP_MD_CTX* = object
    EVP_PKEY_CTX* = object
    BIO* = object
    X509* = object
    X509_STORE* = object
    X509_STORE_CTX* = object
    OPENSSL_STACK* = object

    OpenSslVersionNumProc = proc (): culong {.cdecl.}
    EvpPkeyNewRawPrivateKeyProc = proc (typ: cint, engine: pointer, priv: ptr uint8, len: csize_t): ptr EVP_PKEY {.cdecl.}
    EvpPkeyNewRawPublicKeyProc = proc (typ: cint, engine: pointer, pub: ptr uint8, len: csize_t): ptr EVP_PKEY {.cdecl.}
    EvpPkeyGetRawPublicKeyProc = proc (pkey: ptr EVP_PKEY, pub: ptr uint8, len: ptr csize_t): cint {.cdecl.}
    EvpPkeyFreeProc = proc (pkey: ptr EVP_PKEY) {.cdecl.}
    EvpMdCtxNewProc = proc (): ptr EVP_MD_CTX {.cdecl.}
    EvpMdCtxFreeProc = proc (ctx: ptr EVP_MD_CTX) {.cdecl.}
    EvpDigestSignInitExProc = proc (ctx: ptr EVP_MD_CTX,
      pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, libctx: pointer,
      propq: cstring, pkey: ptr EVP_PKEY, params: pointer): cint {.cdecl.}
    EvpDigestSignProc = proc (ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: ptr csize_t, data: ptr uint8, datalen: csize_t): cint {.cdecl.}
    EvpDigestVerifyInitExProc = proc (ctx: ptr EVP_MD_CTX,
      pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, libctx: pointer,
      propq: cstring, pkey: ptr EVP_PKEY, params: pointer): cint {.cdecl.}
    EvpDigestVerifyProc = proc (ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: csize_t, data: ptr uint8, datalen: csize_t): cint {.cdecl.}
    EvpPkeyCtxFreeProc = proc (ctx: ptr EVP_PKEY_CTX) {.cdecl.}
    BioNewMemBufProc = proc (buf: pointer, len: cint): ptr BIO {.cdecl.}
    BioFreeProc = proc (bio: ptr BIO): cint {.cdecl.}
    PemReadBioPubkeyProc = proc (bio: ptr BIO, key: ptr ptr EVP_PKEY, cb: pointer, u: pointer): ptr EVP_PKEY {.cdecl.}
    D2iPubkeyProc = proc (key: ptr ptr EVP_PKEY, data: ptr ptr uint8, len: clong): ptr EVP_PKEY {.cdecl.}
    I2dPubkeyProc = proc (key: ptr EVP_PKEY, data: ptr ptr uint8): cint {.cdecl.}
    PemReadBioX509Proc = proc (bio: ptr BIO, cert: ptr ptr X509, cb: pointer, u: pointer): ptr X509 {.cdecl.}
    D2iX509Proc = proc (cert: ptr ptr X509, data: ptr ptr uint8, len: clong): ptr X509 {.cdecl.}
    X509FreeProc = proc (cert: ptr X509) {.cdecl.}
    X509GetPubkeyProc = proc (cert: ptr X509): ptr EVP_PKEY {.cdecl.}
    X509StoreNewProc = proc (): ptr X509_STORE {.cdecl.}
    X509StoreFreeProc = proc (store: ptr X509_STORE) {.cdecl.}
    X509StoreAddCertProc = proc (store: ptr X509_STORE, cert: ptr X509): cint {.cdecl.}
    X509StoreSetDefaultPathsProc = proc (store: ptr X509_STORE): cint {.cdecl.}
    X509StoreCtxNewProc = proc (): ptr X509_STORE_CTX {.cdecl.}
    X509StoreCtxFreeProc = proc (ctx: ptr X509_STORE_CTX) {.cdecl.}
    X509StoreCtxInitProc = proc (ctx: ptr X509_STORE_CTX, store: ptr X509_STORE, cert: ptr X509, chain: ptr OPENSSL_STACK): cint {.cdecl.}
    X509VerifyCertProc = proc (ctx: ptr X509_STORE_CTX): cint {.cdecl.}
    X509StoreCtxGetErrorProc = proc (ctx: ptr X509_STORE_CTX): cint {.cdecl.}
    X509VerifyCertErrorStringProc = proc (err: clong): cstring {.cdecl.}
    OpenSslSkNewNullProc = proc (): ptr OPENSSL_STACK {.cdecl.}
    OpenSslSkPushProc = proc (stack: ptr OPENSSL_STACK, data: pointer): cint {.cdecl.}
    OpenSslSkFreeProc = proc (stack: ptr OPENSSL_STACK) {.cdecl.}

  var
    opensslHandle: LibHandle
    osslVersionNum: OpenSslVersionNumProc
    osslNewRawPriv: EvpPkeyNewRawPrivateKeyProc
    osslNewRawPub: EvpPkeyNewRawPublicKeyProc
    osslGetRawPub: EvpPkeyGetRawPublicKeyProc
    osslPkeyFree: EvpPkeyFreeProc
    osslMdCtxNew: EvpMdCtxNewProc
    osslMdCtxFree: EvpMdCtxFreeProc
    osslDigestSignInit: EvpDigestSignInitExProc
    osslDigestSign: EvpDigestSignProc
    osslDigestVerifyInit: EvpDigestVerifyInitExProc
    osslDigestVerify: EvpDigestVerifyProc
    osslPkeyCtxFree: EvpPkeyCtxFreeProc
    osslBioNewMemBuf: BioNewMemBufProc
    osslBioFree: BioFreeProc
    osslPemReadBioPubkey: PemReadBioPubkeyProc
    osslD2iPubkey: D2iPubkeyProc
    osslI2dPubkey: I2dPubkeyProc
    osslPemReadBioX509: PemReadBioX509Proc
    osslD2iX509: D2iX509Proc
    osslX509Free: X509FreeProc
    osslX509GetPubkey: X509GetPubkeyProc
    osslX509StoreNew: X509StoreNewProc
    osslX509StoreFree: X509StoreFreeProc
    osslX509StoreAddCert: X509StoreAddCertProc
    osslX509StoreSetDefaultPaths: X509StoreSetDefaultPathsProc
    osslX509StoreCtxNew: X509StoreCtxNewProc
    osslX509StoreCtxFree: X509StoreCtxFreeProc
    osslX509StoreCtxInit: X509StoreCtxInitProc
    osslX509VerifyCert: X509VerifyCertProc
    osslX509StoreCtxGetError: X509StoreCtxGetErrorProc
    osslX509VerifyCertErrorString: X509VerifyCertErrorStringProc
    osslSkNewNull: OpenSslSkNewNullProc
    osslSkPush: OpenSslSkPushProc
    osslSkFree: OpenSslSkFreeProc
    extraLibCandidates: seq[string] = @[]
    builderAttempted: bool = false

  proc appendLibCandidates(candidates: var seq[string], dirPath: string) =
    for name in opensslLibNames:
      let candidate = joinPath(dirPath, name)
      if fileExists(candidate) or symlinkExists(candidate):
        candidates.add(candidate)

  proc envLibCandidates(): seq[string] =
    let envLibDirs = getEnv("OPENSSL_LIB_DIRS").strip()
    if envLibDirs.len == 0:
      return @[]
    var candidates: seq[string] = @[]
    for dir in envLibDirs.split({';', ':'}):
      let trimmed = dir.strip()
      if trimmed.len > 0:
        appendLibCandidates(candidates, trimmed)
    candidates

  proc defaultSourceDir(): string =
    let envSource = getEnv("OPENSSL_SOURCE").strip()
    if envSource.len > 0:
      return envSource
    let submoduleDir = joinPath(absolutePath(joinPath(moduleDir, "..", "..", "..")),
      "submodules", "openssl")
    if dirExists(submoduleDir):
      return submoduleDir
    joinPath(parentDir(absolutePath(joinPath(moduleDir, "..", "..", ".."))), "openssl")

  proc defaultLibCandidates(): seq[string] =
    var candidates = envLibCandidates()
    let
      absSource = absolutePath(defaultSourceDir())
    appendLibCandidates(candidates, joinPath(absSource, "build", "install", "lib"))
    candidates

  proc unloadOpenSsl() =
    if opensslHandle != nil:
      unloadLib(opensslHandle)
      opensslHandle = nil
    builderAttempted = false

  proc loadSymbol[T](symName: string, target: var T): bool =
    let addrSym = symAddr(opensslHandle, symName)
    if addrSym.isNil:
      unloadOpenSsl()
      return false
    target = cast[T](addrSym)
    true

  proc tryLoadFrom(candidates: seq[string]): LibHandle =
    for candidate in candidates:
      let handle = loadLib(candidate)
      if handle != nil:
        return handle
    nil

  proc promptBuildAndReload(): bool =
    if builderAttempted:
      return false
    builderAttempted = true
    let sourceDir = defaultSourceDir()
    let buildRoot = joinPath(absolutePath(joinPath(moduleDir, "..", "..", "..")),
      "build", "openssl")
    if promptAndBuildOpenSsl(extraLibCandidates, sourceDir, buildRoot):
      return true
    false

  proc ensureOpenSslHandle(): bool =
    if opensslHandle != nil:
      return true
    if extraLibCandidates.len == 0:
      extraLibCandidates = defaultLibCandidates()
    opensslHandle = tryLoadFrom(extraLibCandidates)
    if opensslHandle != nil:
      return true
    opensslHandle = tryLoadFrom(opensslLibNames)
    if opensslHandle != nil:
      return true
    if promptBuildAndReload():
      return ensureOpenSslHandle()
    false

  proc loadOpenSslSymbols(): bool =
    if not ensureOpenSslHandle():
      return false
    if not loadSymbol("OpenSSL_version_num", osslVersionNum): return false
    if not loadSymbol("EVP_PKEY_new_raw_private_key", osslNewRawPriv): return false
    if not loadSymbol("EVP_PKEY_new_raw_public_key", osslNewRawPub): return false
    if not loadSymbol("EVP_PKEY_get_raw_public_key", osslGetRawPub): return false
    if not loadSymbol("EVP_PKEY_free", osslPkeyFree): return false
    if not loadSymbol("EVP_MD_CTX_new", osslMdCtxNew): return false
    if not loadSymbol("EVP_MD_CTX_free", osslMdCtxFree): return false
    if not loadSymbol("EVP_DigestSignInit_ex", osslDigestSignInit): return false
    if not loadSymbol("EVP_DigestSign", osslDigestSign): return false
    if not loadSymbol("EVP_DigestVerifyInit_ex", osslDigestVerifyInit): return false
    if not loadSymbol("EVP_DigestVerify", osslDigestVerify): return false
    if not loadSymbol("EVP_PKEY_CTX_free", osslPkeyCtxFree): return false
    if not loadSymbol("BIO_new_mem_buf", osslBioNewMemBuf): return false
    if not loadSymbol("BIO_free", osslBioFree): return false
    if not loadSymbol("PEM_read_bio_PUBKEY", osslPemReadBioPubkey): return false
    if not loadSymbol("d2i_PUBKEY", osslD2iPubkey): return false
    if not loadSymbol("i2d_PUBKEY", osslI2dPubkey): return false
    if not loadSymbol("PEM_read_bio_X509", osslPemReadBioX509): return false
    if not loadSymbol("d2i_X509", osslD2iX509): return false
    if not loadSymbol("X509_free", osslX509Free): return false
    if not loadSymbol("X509_get_pubkey", osslX509GetPubkey): return false
    if not loadSymbol("X509_STORE_new", osslX509StoreNew): return false
    if not loadSymbol("X509_STORE_free", osslX509StoreFree): return false
    if not loadSymbol("X509_STORE_add_cert", osslX509StoreAddCert): return false
    if not loadSymbol("X509_STORE_set_default_paths", osslX509StoreSetDefaultPaths): return false
    if not loadSymbol("X509_STORE_CTX_new", osslX509StoreCtxNew): return false
    if not loadSymbol("X509_STORE_CTX_free", osslX509StoreCtxFree): return false
    if not loadSymbol("X509_STORE_CTX_init", osslX509StoreCtxInit): return false
    if not loadSymbol("X509_verify_cert", osslX509VerifyCert): return false
    if not loadSymbol("X509_STORE_CTX_get_error", osslX509StoreCtxGetError): return false
    if not loadSymbol("X509_verify_cert_error_string", osslX509VerifyCertErrorString): return false
    if not loadSymbol("OPENSSL_sk_new_null", osslSkNewNull): return false
    if not loadSymbol("OPENSSL_sk_push", osslSkPush): return false
    if not loadSymbol("OPENSSL_sk_free", osslSkFree): return false
    true

  proc ensureOpenSslLoaded*(): bool =
    loadOpenSslSymbols()

  proc requireOpenSsl() =
    if not loadOpenSslSymbols():
      raiseUnavailable("OpenSSL", "hasOpenSSL3")

  proc OpenSSL_version_num*(): culong =
    requireOpenSsl()
    osslVersionNum()

  proc EVP_PKEY_new_raw_private_key*(typ: cint, engine: pointer, priv: ptr uint8, len: csize_t): ptr EVP_PKEY =
    requireOpenSsl()
    osslNewRawPriv(typ, engine, priv, len)

  proc EVP_PKEY_new_raw_public_key*(typ: cint, engine: pointer, pub: ptr uint8, len: csize_t): ptr EVP_PKEY =
    requireOpenSsl()
    osslNewRawPub(typ, engine, pub, len)

  proc EVP_PKEY_get_raw_public_key*(pkey: ptr EVP_PKEY, pub: ptr uint8, len: ptr csize_t): cint =
    requireOpenSsl()
    osslGetRawPub(pkey, pub, len)

  proc EVP_PKEY_free*(pkey: ptr EVP_PKEY) =
    requireOpenSsl()
    osslPkeyFree(pkey)

  proc EVP_MD_CTX_new*(): ptr EVP_MD_CTX =
    requireOpenSsl()
    osslMdCtxNew()

  proc EVP_MD_CTX_free*(ctx: ptr EVP_MD_CTX) =
    requireOpenSsl()
    osslMdCtxFree(ctx)

  proc EVP_DigestSignInit_ex*(ctx: ptr EVP_MD_CTX, pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, propq: cstring, pkey: ptr EVP_PKEY): cint =
    requireOpenSsl()
    osslDigestSignInit(ctx, pctx, mdname, nil, propq, pkey, nil)

  proc EVP_DigestSign*(ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: ptr csize_t, data: ptr uint8, datalen: csize_t): cint =
    requireOpenSsl()
    osslDigestSign(ctx, sig, siglen, data, datalen)

  proc EVP_DigestVerifyInit_ex*(ctx: ptr EVP_MD_CTX, pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, propq: cstring, pkey: ptr EVP_PKEY): cint =
    requireOpenSsl()
    osslDigestVerifyInit(ctx, pctx, mdname, nil, propq, pkey, nil)

  proc EVP_DigestVerify*(ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: csize_t, data: ptr uint8, datalen: csize_t): cint =
    requireOpenSsl()
    osslDigestVerify(ctx, sig, siglen, data, datalen)

  proc EVP_PKEY_CTX_free*(ctx: ptr EVP_PKEY_CTX) =
    requireOpenSsl()
    osslPkeyCtxFree(ctx)

  proc BIO_new_mem_buf*(buf: pointer, len: cint): ptr BIO =
    requireOpenSsl()
    osslBioNewMemBuf(buf, len)

  proc BIO_free*(bio: ptr BIO): cint =
    requireOpenSsl()
    osslBioFree(bio)

  proc PEM_read_bio_PUBKEY*(bio: ptr BIO, key: ptr ptr EVP_PKEY, cb: pointer, u: pointer): ptr EVP_PKEY =
    requireOpenSsl()
    osslPemReadBioPubkey(bio, key, cb, u)

  proc d2i_PUBKEY*(key: ptr ptr EVP_PKEY, data: ptr ptr uint8, len: clong): ptr EVP_PKEY =
    requireOpenSsl()
    osslD2iPubkey(key, data, len)

  proc i2d_PUBKEY*(key: ptr EVP_PKEY, data: ptr ptr uint8): cint =
    requireOpenSsl()
    osslI2dPubkey(key, data)

  proc PEM_read_bio_X509*(bio: ptr BIO, cert: ptr ptr X509, cb: pointer, u: pointer): ptr X509 =
    requireOpenSsl()
    osslPemReadBioX509(bio, cert, cb, u)

  proc d2i_X509*(cert: ptr ptr X509, data: ptr ptr uint8, len: clong): ptr X509 =
    requireOpenSsl()
    osslD2iX509(cert, data, len)

  proc X509_free*(cert: ptr X509) =
    requireOpenSsl()
    osslX509Free(cert)

  proc X509_get_pubkey*(cert: ptr X509): ptr EVP_PKEY =
    requireOpenSsl()
    osslX509GetPubkey(cert)

  proc X509_STORE_new*(): ptr X509_STORE =
    requireOpenSsl()
    osslX509StoreNew()

  proc X509_STORE_free*(store: ptr X509_STORE) =
    requireOpenSsl()
    osslX509StoreFree(store)

  proc X509_STORE_add_cert*(store: ptr X509_STORE, cert: ptr X509): cint =
    requireOpenSsl()
    osslX509StoreAddCert(store, cert)

  proc X509_STORE_set_default_paths*(store: ptr X509_STORE): cint =
    requireOpenSsl()
    osslX509StoreSetDefaultPaths(store)

  proc X509_STORE_CTX_new*(): ptr X509_STORE_CTX =
    requireOpenSsl()
    osslX509StoreCtxNew()

  proc X509_STORE_CTX_free*(ctx: ptr X509_STORE_CTX) =
    requireOpenSsl()
    osslX509StoreCtxFree(ctx)

  proc X509_STORE_CTX_init*(ctx: ptr X509_STORE_CTX, store: ptr X509_STORE,
      cert: ptr X509, chain: ptr OPENSSL_STACK): cint =
    requireOpenSsl()
    osslX509StoreCtxInit(ctx, store, cert, chain)

  proc X509_verify_cert*(ctx: ptr X509_STORE_CTX): cint =
    requireOpenSsl()
    osslX509VerifyCert(ctx)

  proc X509_STORE_CTX_get_error*(ctx: ptr X509_STORE_CTX): cint =
    requireOpenSsl()
    osslX509StoreCtxGetError(ctx)

  proc X509_verify_cert_error_string*(err: clong): cstring =
    requireOpenSsl()
    osslX509VerifyCertErrorString(err)

  proc OPENSSL_sk_new_null*(): ptr OPENSSL_STACK =
    requireOpenSsl()
    osslSkNewNull()

  proc OPENSSL_sk_push*(stack: ptr OPENSSL_STACK, data: pointer): cint =
    requireOpenSsl()
    osslSkPush(stack, data)

  proc OPENSSL_sk_free*(stack: ptr OPENSSL_STACK) =
    requireOpenSsl()
    osslSkFree(stack)

else:
  proc ensureOpenSslLoaded*(): bool =
    false

  type
    EVP_PKEY* = object
    EVP_MD_CTX* = object
    EVP_PKEY_CTX* = object
    BIO* = object
    X509* = object
    X509_STORE* = object
    X509_STORE_CTX* = object
    OPENSSL_STACK* = object

  proc OpenSSL_version_num*(): culong =
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc EVP_PKEY_new_raw_private_key*(typ: cint, engine: pointer, priv: ptr uint8, len: csize_t): ptr EVP_PKEY =
    discard typ
    discard engine
    discard priv
    discard len
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc EVP_PKEY_new_raw_public_key*(typ: cint, engine: pointer, pub: ptr uint8, len: csize_t): ptr EVP_PKEY =
    discard typ
    discard engine
    discard pub
    discard len
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc EVP_PKEY_get_raw_public_key*(pkey: ptr EVP_PKEY, pub: ptr uint8, len: ptr csize_t): cint =
    discard pkey
    discard pub
    discard len
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc EVP_PKEY_free*(pkey: ptr EVP_PKEY) =
    discard pkey
    raiseUnavailable("OpenSSL", "hasOpenSSL3")

  proc EVP_MD_CTX_new*(): ptr EVP_MD_CTX =
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc EVP_MD_CTX_free*(ctx: ptr EVP_MD_CTX) =
    discard ctx
    raiseUnavailable("OpenSSL", "hasOpenSSL3")

  proc EVP_DigestSignInit_ex*(ctx: ptr EVP_MD_CTX, pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, propq: cstring, pkey: ptr EVP_PKEY): cint =
    discard ctx
    discard pctx
    discard mdname
    discard propq
    discard pkey
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc EVP_DigestSign*(ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: ptr csize_t, data: ptr uint8, datalen: csize_t): cint =
    discard ctx
    discard sig
    discard siglen
    discard data
    discard datalen
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc EVP_DigestVerifyInit_ex*(ctx: ptr EVP_MD_CTX, pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, propq: cstring, pkey: ptr EVP_PKEY): cint =
    discard ctx
    discard pctx
    discard mdname
    discard propq
    discard pkey
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc EVP_DigestVerify*(ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: csize_t, data: ptr uint8, datalen: csize_t): cint =
    discard ctx
    discard sig
    discard siglen
    discard data
    discard datalen
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc EVP_PKEY_CTX_free*(ctx: ptr EVP_PKEY_CTX) =
    discard ctx
    raiseUnavailable("OpenSSL", "hasOpenSSL3")

  proc BIO_new_mem_buf*(buf: pointer, len: cint): ptr BIO =
    discard buf
    discard len
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc BIO_free*(bio: ptr BIO): cint =
    discard bio
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc PEM_read_bio_PUBKEY*(bio: ptr BIO, key: ptr ptr EVP_PKEY,
      cb: pointer, u: pointer): ptr EVP_PKEY =
    discard bio
    discard key
    discard cb
    discard u
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc d2i_PUBKEY*(key: ptr ptr EVP_PKEY, data: ptr ptr uint8,
      len: clong): ptr EVP_PKEY =
    discard key
    discard data
    discard len
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc i2d_PUBKEY*(key: ptr EVP_PKEY, data: ptr ptr uint8): cint =
    discard key
    discard data
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc PEM_read_bio_X509*(bio: ptr BIO, cert: ptr ptr X509,
      cb: pointer, u: pointer): ptr X509 =
    discard bio
    discard cert
    discard cb
    discard u
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc d2i_X509*(cert: ptr ptr X509, data: ptr ptr uint8,
      len: clong): ptr X509 =
    discard cert
    discard data
    discard len
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc X509_free*(cert: ptr X509) =
    discard cert
    raiseUnavailable("OpenSSL", "hasOpenSSL3")

  proc X509_get_pubkey*(cert: ptr X509): ptr EVP_PKEY =
    discard cert
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc X509_STORE_new*(): ptr X509_STORE =
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc X509_STORE_free*(store: ptr X509_STORE) =
    discard store
    raiseUnavailable("OpenSSL", "hasOpenSSL3")

  proc X509_STORE_add_cert*(store: ptr X509_STORE, cert: ptr X509): cint =
    discard store
    discard cert
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc X509_STORE_set_default_paths*(store: ptr X509_STORE): cint =
    discard store
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc X509_STORE_CTX_new*(): ptr X509_STORE_CTX =
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc X509_STORE_CTX_free*(ctx: ptr X509_STORE_CTX) =
    discard ctx
    raiseUnavailable("OpenSSL", "hasOpenSSL3")

  proc X509_STORE_CTX_init*(ctx: ptr X509_STORE_CTX, store: ptr X509_STORE,
      cert: ptr X509, chain: ptr OPENSSL_STACK): cint =
    discard ctx
    discard store
    discard cert
    discard chain
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc X509_verify_cert*(ctx: ptr X509_STORE_CTX): cint =
    discard ctx
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc X509_STORE_CTX_get_error*(ctx: ptr X509_STORE_CTX): cint =
    discard ctx
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc X509_verify_cert_error_string*(err: clong): cstring =
    discard err
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc OPENSSL_sk_new_null*(): ptr OPENSSL_STACK =
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return nil

  proc OPENSSL_sk_push*(stack: ptr OPENSSL_STACK, data: pointer): cint =
    discard stack
    discard data
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
    return 0

  proc OPENSSL_sk_free*(stack: ptr OPENSSL_STACK) =
    discard stack
    raiseUnavailable("OpenSSL", "hasOpenSSL3")

proc requireOk*(status: cint, action: string) =
  if status != cint(1):
    raiseOperation("OpenSSL", action & " failed")
