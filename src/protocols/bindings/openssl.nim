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

    OpenSslVersionNumProc = proc (): culong {.cdecl.}
    EvpPkeyNewRawPrivateKeyProc = proc (typ: cint, engine: pointer, priv: ptr uint8, len: csize_t): ptr EVP_PKEY {.cdecl.}
    EvpPkeyNewRawPublicKeyProc = proc (typ: cint, engine: pointer, pub: ptr uint8, len: csize_t): ptr EVP_PKEY {.cdecl.}
    EvpPkeyGetRawPublicKeyProc = proc (pkey: ptr EVP_PKEY, pub: ptr uint8, len: ptr csize_t): cint {.cdecl.}
    EvpPkeyFreeProc = proc (pkey: ptr EVP_PKEY) {.cdecl.}
    EvpMdCtxNewProc = proc (): ptr EVP_MD_CTX {.cdecl.}
    EvpMdCtxFreeProc = proc (ctx: ptr EVP_MD_CTX) {.cdecl.}
    EvpDigestSignInitExProc = proc (ctx: ptr EVP_MD_CTX, pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, propq: cstring, pkey: ptr EVP_PKEY): cint {.cdecl.}
    EvpDigestSignProc = proc (ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: ptr csize_t, data: ptr uint8, datalen: csize_t): cint {.cdecl.}
    EvpDigestVerifyInitExProc = proc (ctx: ptr EVP_MD_CTX, pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, propq: cstring, pkey: ptr EVP_PKEY): cint {.cdecl.}
    EvpDigestVerifyProc = proc (ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: csize_t, data: ptr uint8, datalen: csize_t): cint {.cdecl.}
    EvpPkeyCtxFreeProc = proc (ctx: ptr EVP_PKEY_CTX) {.cdecl.}

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
    osslDigestSignInit(ctx, pctx, mdname, propq, pkey)

  proc EVP_DigestSign*(ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: ptr csize_t, data: ptr uint8, datalen: csize_t): cint =
    requireOpenSsl()
    osslDigestSign(ctx, sig, siglen, data, datalen)

  proc EVP_DigestVerifyInit_ex*(ctx: ptr EVP_MD_CTX, pctx: ptr ptr EVP_PKEY_CTX, mdname: cstring, propq: cstring, pkey: ptr EVP_PKEY): cint =
    requireOpenSsl()
    osslDigestVerifyInit(ctx, pctx, mdname, propq, pkey)

  proc EVP_DigestVerify*(ctx: ptr EVP_MD_CTX, sig: ptr uint8, siglen: csize_t, data: ptr uint8, datalen: csize_t): cint =
    requireOpenSsl()
    osslDigestVerify(ctx, sig, siglen, data, datalen)

  proc EVP_PKEY_CTX_free*(ctx: ptr EVP_PKEY_CTX) =
    requireOpenSsl()
    osslPkeyCtxFree(ctx)

else:
  proc ensureOpenSslLoaded*(): bool =
    false

  type
    EVP_PKEY* = object
    EVP_MD_CTX* = object
    EVP_PKEY_CTX* = object

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

proc requireOk*(status: cint, action: string) =
  if status != cint(1):
    raiseOperation("OpenSSL", action & " failed")
