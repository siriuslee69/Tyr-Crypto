import ../common

const
  sodiumLibNames* = when defined(windows):
                      @["libsodium.dll"]
                    elif defined(macosx):
                      @["libsodium.dylib"]
                    else:
                      @["libsodium.so", "libsodium.so.23", "libsodium.so.24"]
  sodiumLib* = when defined(windows):
                 "libsodium.dll"
               elif defined(macosx):
                 "libsodium.dylib"
               else:
                 "libsodium.so(|.23|.24)"

when defined(hasLibsodium):
  import std/[dynlib, os, strutils]
  import ../builders/libsodium_builder

  const
    moduleDir = splitFile(currentSourcePath()).dir

  proc repoRoot(): string =
    absolutePath(joinPath(moduleDir, "..", "..", ".."))

  type
    SodiumInitProc = proc (): cint {.cdecl.}
    CryptoAeadSizeProc = proc (): csize_t {.cdecl.}
    CryptoAeadMessageMaxProc = proc (): culonglong {.cdecl.}
    CryptoAeadEncryptProc = proc (
      c: ptr uint8,
      clen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      nsec: pointer,
      npub: ptr uint8,
      k: ptr uint8
    ): cint {.cdecl.}
    CryptoAeadDecryptProc = proc (
      m: ptr uint8,
      mlen: ptr culonglong,
      nsec: pointer,
      c: ptr uint8,
      clen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint {.cdecl.}
    CryptoKxKeypairProc = proc (pk: ptr uint8, sk: ptr uint8): cint {.cdecl.}
    CryptoKxSeedKeypairProc = proc (pk: ptr uint8, sk: ptr uint8, seed: ptr uint8): cint {.cdecl.}
    CryptoKxSeedBytesProc = proc (): csize_t {.cdecl.}
    CryptoScalarBaseProc = proc (q: ptr uint8, n: ptr uint8): cint {.cdecl.}
    CryptoScalarMultProc = proc (q: ptr uint8, n: ptr uint8, p: ptr uint8): cint {.cdecl.}
    CryptoSignKeypairProc = proc (pk: ptr uint8, sk: ptr uint8): cint {.cdecl.}
    CryptoSignDetachedProc = proc (
      sig: ptr uint8,
      siglen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      sk: ptr uint8
    ): cint {.cdecl.}
    CryptoSignVerifyDetachedProc = proc (
      sig: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      pk: ptr uint8
    ): cint {.cdecl.}
    CryptoOnetimeAuthSizeProc = proc (): csize_t {.cdecl.}
    CryptoOnetimeAuthProc = proc (
      outBuf: ptr uint8,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8
    ): cint {.cdecl.}
    CryptoOnetimeAuthVerifyProc = proc (
      tag: ptr uint8,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8
    ): cint {.cdecl.}
    CryptoGenericHashProc = proc (
      outBuf: ptr uint8,
      outLen: csize_t,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8,
      keyLen: csize_t
    ): cint {.cdecl.}
    CryptoAeadAvailableProc = proc (): cint {.cdecl.}
    CryptoStreamProc = proc (
      c: ptr uint8,
      clen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint {.cdecl.}
    CryptoStreamXorProc = proc (
      c: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint {.cdecl.}
    CryptoStreamXorIcProc = proc (
      c: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      npub: ptr uint8,
      ic: uint64,
      k: ptr uint8
    ): cint {.cdecl.}
    CryptoPwhashSizeProc = proc (): csize_t {.cdecl.}
    CryptoPwhashOpsProc = proc (): culonglong {.cdecl.}
    CryptoPwhashAlgProc = proc (): cint {.cdecl.}
    CryptoPwhashProc = proc (
      outBuf: ptr uint8,
      outLen: culonglong,
      passwd: cstring,
      passwdLen: culonglong,
      salt: ptr uint8,
      opslimit: culonglong,
      memlimit: csize_t,
      alg: cint
    ): cint {.cdecl.}
    CryptoPwhashStrProc = proc (
      outBuf: ptr char,
      passwd: cstring,
      passwdLen: culonglong,
      opslimit: culonglong,
      memlimit: csize_t
    ): cint {.cdecl.}
    CryptoPwhashStrAlgProc = proc (
      outBuf: ptr char,
      passwd: cstring,
      passwdLen: culonglong,
      opslimit: culonglong,
      memlimit: csize_t,
      alg: cint
    ): cint {.cdecl.}
    SodiumMemzeroProc = proc (pnt: pointer, len: csize_t) {.cdecl.}
    CryptoPwhashStrVerifyProc = proc (
      str: cstring,
      passwd: cstring,
      passwdLen: culonglong
    ): cint {.cdecl.}
    CryptoPwhashStrNeedsRehashProc = proc (
      str: cstring,
      opslimit: culonglong,
      memlimit: csize_t
    ): cint {.cdecl.}
    CryptoPwhashStrPrefixProc = proc (): cstring {.cdecl.}
    CryptoPwhashPrimitiveProc = proc (): cstring {.cdecl.}

  var
    sodiumHandle: LibHandle
    fnSodiumInit: SodiumInitProc
    fnSodiumKeybytes: CryptoAeadSizeProc
    fnSodiumNpubbytes: CryptoAeadSizeProc
    fnSodiumNsecbytes: CryptoAeadSizeProc
    fnSodiumMessageBytesMax: CryptoAeadMessageMaxProc
    fnSodiumEncrypt: CryptoAeadEncryptProc
    fnSodiumDecrypt: CryptoAeadDecryptProc
    fnSodiumKxKeypair: CryptoKxKeypairProc
    fnSodiumKxSeedKeypair: CryptoKxSeedKeypairProc
    fnSodiumKxSeedbytes: CryptoKxSeedBytesProc
    fnSodiumScalarBase: CryptoScalarBaseProc
    fnSodiumScalarMult: CryptoScalarMultProc
    fnSodiumSignKeypair: CryptoSignKeypairProc
    fnSodiumSignDetached: CryptoSignDetachedProc
    fnSodiumVerifyDetached: CryptoSignVerifyDetachedProc
    fnSodiumPoly1305Bytes: CryptoOnetimeAuthSizeProc
    fnSodiumPoly1305Keybytes: CryptoOnetimeAuthSizeProc
    fnSodiumPoly1305: CryptoOnetimeAuthProc
    fnSodiumPoly1305Verify: CryptoOnetimeAuthVerifyProc
    fnSodiumBlake2b: CryptoGenericHashProc
    fnSodiumAesAvailable: CryptoAeadAvailableProc
    fnSodiumAesKeybytes: CryptoAeadSizeProc
    fnSodiumAesNpubbytes: CryptoAeadSizeProc
    fnSodiumAesNsecbytes: CryptoAeadSizeProc
    fnSodiumAesMessageBytesMax: CryptoAeadMessageMaxProc
    fnSodiumAesEncrypt: CryptoAeadEncryptProc
    fnSodiumAesDecrypt: CryptoAeadDecryptProc
    fnSodiumXChaKeybytes: CryptoAeadSizeProc
    fnSodiumXChaNoncebytes: CryptoAeadSizeProc
    fnSodiumXChaStream: CryptoStreamProc
    fnSodiumXChaStreamXor: CryptoStreamXorProc
    fnSodiumXChaStreamXorIc: CryptoStreamXorIcProc
    fnSodiumPwhashAlgDefault: CryptoPwhashAlgProc
    fnSodiumPwhashAlgArgon2i13: CryptoPwhashAlgProc
    fnSodiumPwhashAlgArgon2id13: CryptoPwhashAlgProc
    fnSodiumPwhashBytesMin: CryptoPwhashSizeProc
    fnSodiumPwhashBytesMax: CryptoPwhashSizeProc
    fnSodiumPwhashPasswdMin: CryptoPwhashSizeProc
    fnSodiumPwhashPasswdMax: CryptoPwhashSizeProc
    fnSodiumPwhashSaltbytes: CryptoPwhashSizeProc
    fnSodiumPwhashStrbytes: CryptoPwhashSizeProc
    fnSodiumPwhashStrprefix: CryptoPwhashStrPrefixProc
    fnSodiumPwhashOpsMin: CryptoPwhashOpsProc
    fnSodiumPwhashOpsMax: CryptoPwhashOpsProc
    fnSodiumPwhashMemMin: CryptoPwhashSizeProc
    fnSodiumPwhashMemMax: CryptoPwhashSizeProc
    fnSodiumPwhashOpsInteractive: CryptoPwhashOpsProc
    fnSodiumPwhashMemInteractive: CryptoPwhashSizeProc
    fnSodiumPwhashOpsModerate: CryptoPwhashOpsProc
    fnSodiumPwhashMemModerate: CryptoPwhashSizeProc
    fnSodiumPwhashOpsSensitive: CryptoPwhashOpsProc
    fnSodiumPwhashMemSensitive: CryptoPwhashSizeProc
    fnSodiumPwhash: CryptoPwhashProc
    fnSodiumPwhashStr: CryptoPwhashStrProc
    fnSodiumPwhashStrAlg: CryptoPwhashStrAlgProc
    fnSodiumPwhashStrVerify: CryptoPwhashStrVerifyProc
    fnSodiumPwhashStrNeedsRehash: CryptoPwhashStrNeedsRehashProc
    fnSodiumPwhashPrimitive: CryptoPwhashPrimitiveProc
    fnSodiumMemzero: SodiumMemzeroProc
    extraLibCandidates: seq[string] = @[]
    builderAttempted: bool = false

  proc appendLibCandidates(candidates: var seq[string], dirPath: string) =
    for name in sodiumLibNames:
      let candidate = joinPath(dirPath, name)
      if fileExists(candidate) or symlinkExists(candidate):
        candidates.add(candidate)

  proc envLibCandidates(): seq[string] =
    let envLibDirs = getEnv("LIBSODIUM_LIB_DIRS").strip()
    if envLibDirs.len == 0:
      return @[]
    var candidates: seq[string] = @[]
    for dir in envLibDirs.split({';', ':'}):
      let trimmed = dir.strip()
      if trimmed.len > 0:
        appendLibCandidates(candidates, trimmed)
    candidates

  proc defaultSourceDir(): string =
    let envSource = getEnv("LIBSODIUM_SOURCE").strip()
    if envSource.len > 0:
      return envSource
    let submoduleDir = joinPath(repoRoot(), "submodules", "libsodium")
    if dirExists(submoduleDir):
      return submoduleDir
    joinPath(parentDir(repoRoot()), "libsodium")

  proc defaultBuildRoot(): string =
    let envBuild = getEnv("LIBSODIUM_BUILD_ROOT").strip()
    if envBuild.len > 0:
      return envBuild
    joinPath(repoRoot(), "build", "libsodium")

  proc defaultLibCandidates(): seq[string] =
    var candidates = envLibCandidates()
    let
      absSource = absolutePath(defaultSourceDir())
      buildRoot = defaultBuildRoot()
    appendLibCandidates(candidates, joinPath(absSource, "build", "install", "lib"))
    appendLibCandidates(candidates, joinPath(absSource, "build", "lib"))
    appendLibCandidates(candidates, joinPath(absSource, "build"))
    appendLibCandidates(candidates, joinPath(absSource, "zig-out", "lib"))
    appendLibCandidates(candidates, joinPath(absSource, "zig-out", "bin"))
    appendLibCandidates(candidates, joinPath(buildRoot, "install", "lib"))
    appendLibCandidates(candidates, joinPath(buildRoot, "install", "bin"))
    appendLibCandidates(candidates, joinPath(buildRoot, "build"))
    candidates

  proc unloadSodium() =
    if sodiumHandle != nil:
      unloadLib(sodiumHandle)
      sodiumHandle = nil
    builderAttempted = false

  proc loadSymbol[T](symName: string, target: var T): bool =
    let addrSym = symAddr(sodiumHandle, symName)
    if addrSym.isNil:
      unloadSodium()
      return false
    target = cast[T](addrSym)
    true

  proc tryLoadFrom(candidates: seq[string]): LibHandle =
    for candidate in candidates:
      let handle = loadLib(candidate)
      if handle != nil:
        return handle
    nil

  proc attemptBuildAndReload(): bool =
    if builderAttempted:
      return false
    builderAttempted = true
    let sourceDir = defaultSourceDir()
    let buildRoot = defaultBuildRoot()
    promptAndBuildLibsodium(extraLibCandidates, sourceDir, buildRoot)

  proc ensureSodiumHandle(): bool =
    if sodiumHandle != nil:
      return true
    if extraLibCandidates.len == 0:
      extraLibCandidates = defaultLibCandidates()
    sodiumHandle = tryLoadFrom(extraLibCandidates)
    if sodiumHandle != nil:
      return true
    sodiumHandle = tryLoadFrom(sodiumLibNames)
    if sodiumHandle != nil:
      return true
    if attemptBuildAndReload():
      return ensureSodiumHandle()
    false

  proc loadSodiumSymbols(): bool =
    if not ensureSodiumHandle():
      return false
    if not loadSymbol("sodium_init", fnSodiumInit): return false
    if not loadSymbol("crypto_aead_xchacha20poly1305_ietf_keybytes", fnSodiumKeybytes): return false
    if not loadSymbol("crypto_aead_xchacha20poly1305_ietf_npubbytes", fnSodiumNpubbytes): return false
    if not loadSymbol("crypto_aead_xchacha20poly1305_ietf_nsecbytes", fnSodiumNsecbytes): return false
    if not loadSymbol("crypto_aead_xchacha20poly1305_ietf_messagebytes_max", fnSodiumMessageBytesMax): return false
    if not loadSymbol("crypto_aead_xchacha20poly1305_ietf_encrypt", fnSodiumEncrypt): return false
    if not loadSymbol("crypto_aead_xchacha20poly1305_ietf_decrypt", fnSodiumDecrypt): return false
    if not loadSymbol("crypto_kx_keypair", fnSodiumKxKeypair): return false
    if not loadSymbol("crypto_kx_seed_keypair", fnSodiumKxSeedKeypair): return false
    if not loadSymbol("crypto_kx_seedbytes", fnSodiumKxSeedbytes): return false
    if not loadSymbol("crypto_scalarmult_curve25519_base", fnSodiumScalarBase): return false
    if not loadSymbol("crypto_scalarmult_curve25519", fnSodiumScalarMult): return false
    if not loadSymbol("crypto_sign_ed25519_keypair", fnSodiumSignKeypair): return false
    if not loadSymbol("crypto_sign_ed25519_detached", fnSodiumSignDetached): return false
    if not loadSymbol("crypto_sign_ed25519_verify_detached", fnSodiumVerifyDetached): return false
    if not loadSymbol("crypto_onetimeauth_poly1305_bytes", fnSodiumPoly1305Bytes): return false
    if not loadSymbol("crypto_onetimeauth_poly1305_keybytes", fnSodiumPoly1305Keybytes): return false
    if not loadSymbol("crypto_onetimeauth_poly1305", fnSodiumPoly1305): return false
    if not loadSymbol("crypto_onetimeauth_poly1305_verify", fnSodiumPoly1305Verify): return false
    if not loadSymbol("crypto_generichash_blake2b", fnSodiumBlake2b): return false
    if not loadSymbol("crypto_aead_aes256gcm_is_available", fnSodiumAesAvailable): return false
    if not loadSymbol("crypto_aead_aes256gcm_keybytes", fnSodiumAesKeybytes): return false
    if not loadSymbol("crypto_aead_aes256gcm_npubbytes", fnSodiumAesNpubbytes): return false
    if not loadSymbol("crypto_aead_aes256gcm_nsecbytes", fnSodiumAesNsecbytes): return false
    if not loadSymbol("crypto_aead_aes256gcm_messagebytes_max", fnSodiumAesMessageBytesMax): return false
    if not loadSymbol("crypto_aead_aes256gcm_encrypt", fnSodiumAesEncrypt): return false
    if not loadSymbol("crypto_aead_aes256gcm_decrypt", fnSodiumAesDecrypt): return false
    if not loadSymbol("crypto_stream_xchacha20_keybytes", fnSodiumXChaKeybytes): return false
    if not loadSymbol("crypto_stream_xchacha20_noncebytes", fnSodiumXChaNoncebytes): return false
    if not loadSymbol("crypto_stream_xchacha20", fnSodiumXChaStream): return false
    if not loadSymbol("crypto_stream_xchacha20_xor", fnSodiumXChaStreamXor): return false
    if not loadSymbol("crypto_stream_xchacha20_xor_ic", fnSodiumXChaStreamXorIc): return false
    if not loadSymbol("crypto_pwhash_alg_default", fnSodiumPwhashAlgDefault): return false
    if not loadSymbol("crypto_pwhash_alg_argon2i13", fnSodiumPwhashAlgArgon2i13): return false
    if not loadSymbol("crypto_pwhash_alg_argon2id13", fnSodiumPwhashAlgArgon2id13): return false
    if not loadSymbol("crypto_pwhash_bytes_min", fnSodiumPwhashBytesMin): return false
    if not loadSymbol("crypto_pwhash_bytes_max", fnSodiumPwhashBytesMax): return false
    if not loadSymbol("crypto_pwhash_passwd_min", fnSodiumPwhashPasswdMin): return false
    if not loadSymbol("crypto_pwhash_passwd_max", fnSodiumPwhashPasswdMax): return false
    if not loadSymbol("crypto_pwhash_saltbytes", fnSodiumPwhashSaltbytes): return false
    if not loadSymbol("crypto_pwhash_strbytes", fnSodiumPwhashStrbytes): return false
    if not loadSymbol("crypto_pwhash_strprefix", fnSodiumPwhashStrprefix): return false
    if not loadSymbol("crypto_pwhash_opslimit_min", fnSodiumPwhashOpsMin): return false
    if not loadSymbol("crypto_pwhash_opslimit_max", fnSodiumPwhashOpsMax): return false
    if not loadSymbol("crypto_pwhash_memlimit_min", fnSodiumPwhashMemMin): return false
    if not loadSymbol("crypto_pwhash_memlimit_max", fnSodiumPwhashMemMax): return false
    if not loadSymbol("crypto_pwhash_opslimit_interactive", fnSodiumPwhashOpsInteractive): return false
    if not loadSymbol("crypto_pwhash_memlimit_interactive", fnSodiumPwhashMemInteractive): return false
    if not loadSymbol("crypto_pwhash_opslimit_moderate", fnSodiumPwhashOpsModerate): return false
    if not loadSymbol("crypto_pwhash_memlimit_moderate", fnSodiumPwhashMemModerate): return false
    if not loadSymbol("crypto_pwhash_opslimit_sensitive", fnSodiumPwhashOpsSensitive): return false
    if not loadSymbol("crypto_pwhash_memlimit_sensitive", fnSodiumPwhashMemSensitive): return false
    if not loadSymbol("crypto_pwhash", fnSodiumPwhash): return false
    if not loadSymbol("crypto_pwhash_str", fnSodiumPwhashStr): return false
    if not loadSymbol("crypto_pwhash_str_alg", fnSodiumPwhashStrAlg): return false
    if not loadSymbol("crypto_pwhash_str_verify", fnSodiumPwhashStrVerify): return false
    if not loadSymbol("crypto_pwhash_str_needs_rehash", fnSodiumPwhashStrNeedsRehash): return false
    if not loadSymbol("crypto_pwhash_primitive", fnSodiumPwhashPrimitive): return false
    if not loadSymbol("sodium_memzero", fnSodiumMemzero): return false
    true

  proc ensureLibSodiumLoaded*(): bool =
    loadSodiumSymbols()

  proc requireLibSodium() =
    if not loadSodiumSymbols():
      raiseUnavailable("libsodium", "hasLibsodium")

  proc sodium_init*(): cint =
    requireLibSodium()
    fnSodiumInit()

  proc crypto_aead_xchacha20poly1305_ietf_keybytes*(): csize_t =
    requireLibSodium()
    fnSodiumKeybytes()

  proc crypto_aead_xchacha20poly1305_ietf_npubbytes*(): csize_t =
    requireLibSodium()
    fnSodiumNpubbytes()

  proc crypto_aead_xchacha20poly1305_ietf_nsecbytes*(): csize_t =
    requireLibSodium()
    fnSodiumNsecbytes()

  proc crypto_aead_xchacha20poly1305_ietf_messagebytes_max*(): culonglong =
    requireLibSodium()
    fnSodiumMessageBytesMax()

  proc crypto_aead_xchacha20poly1305_ietf_encrypt*(
      c: ptr uint8,
      clen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      nsec: pointer,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumEncrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)

  proc crypto_aead_xchacha20poly1305_ietf_decrypt*(
      m: ptr uint8,
      mlen: ptr culonglong,
      nsec: pointer,
      c: ptr uint8,
      clen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumDecrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k)

  proc crypto_kx_keypair*(pk: ptr uint8, sk: ptr uint8): cint =
    requireLibSodium()
    fnSodiumKxKeypair(pk, sk)

  proc crypto_kx_seedbytes*(): csize_t =
    requireLibSodium()
    fnSodiumKxSeedbytes()

  proc crypto_kx_seed_keypair*(pk: ptr uint8, sk: ptr uint8, seed: ptr uint8): cint =
    requireLibSodium()
    fnSodiumKxSeedKeypair(pk, sk, seed)

  proc crypto_scalarmult_curve25519_base*(q: ptr uint8, n: ptr uint8): cint =
    requireLibSodium()
    fnSodiumScalarBase(q, n)

  proc crypto_scalarmult_curve25519*(q: ptr uint8, n: ptr uint8, p: ptr uint8): cint =
    requireLibSodium()
    fnSodiumScalarMult(q, n, p)

  proc crypto_sign_ed25519_keypair*(pk: ptr uint8, sk: ptr uint8): cint =
    requireLibSodium()
    fnSodiumSignKeypair(pk, sk)

  proc crypto_sign_ed25519_detached*(
      sig: ptr uint8,
      siglen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      sk: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumSignDetached(sig, siglen, m, mlen, sk)

  proc crypto_sign_ed25519_verify_detached*(
      sig: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      pk: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumVerifyDetached(sig, m, mlen, pk)

  proc crypto_onetimeauth_poly1305_bytes*(): csize_t =
    requireLibSodium()
    fnSodiumPoly1305Bytes()

  proc crypto_onetimeauth_poly1305_keybytes*(): csize_t =
    requireLibSodium()
    fnSodiumPoly1305Keybytes()

  proc crypto_onetimeauth_poly1305*(
      outBuf: ptr uint8,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumPoly1305(outBuf, inBuf, inLen, key)

  proc crypto_onetimeauth_poly1305_verify*(
      tag: ptr uint8,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumPoly1305Verify(tag, inBuf, inLen, key)

  proc crypto_generichash_blake2b*(
      outBuf: ptr uint8,
      outLen: csize_t,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8,
      keyLen: csize_t
    ): cint =
    requireLibSodium()
    fnSodiumBlake2b(outBuf, outLen, inBuf, inLen, key, keyLen)

  proc crypto_aead_aes256gcm_is_available*(): cint =
    requireLibSodium()
    fnSodiumAesAvailable()

  proc crypto_aead_aes256gcm_keybytes*(): csize_t =
    requireLibSodium()
    fnSodiumAesKeybytes()

  proc crypto_aead_aes256gcm_npubbytes*(): csize_t =
    requireLibSodium()
    fnSodiumAesNpubbytes()

  proc crypto_aead_aes256gcm_nsecbytes*(): csize_t =
    requireLibSodium()
    fnSodiumAesNsecbytes()

  proc crypto_aead_aes256gcm_messagebytes_max*(): culonglong =
    requireLibSodium()
    fnSodiumAesMessageBytesMax()

  proc crypto_aead_aes256gcm_encrypt*(
      c: ptr uint8,
      clen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      nsec: pointer,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumAesEncrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)

  proc crypto_aead_aes256gcm_decrypt*(
      m: ptr uint8,
      mlen: ptr culonglong,
      nsec: pointer,
      c: ptr uint8,
      clen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumAesDecrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k)

  proc crypto_stream_xchacha20_keybytes*(): csize_t =
    requireLibSodium()
    fnSodiumXChaKeybytes()

  proc crypto_stream_xchacha20_noncebytes*(): csize_t =
    requireLibSodium()
    fnSodiumXChaNoncebytes()

  proc crypto_stream_xchacha20*(
      c: ptr uint8,
      clen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumXChaStream(c, clen, npub, k)

  proc crypto_stream_xchacha20_xor*(
      c: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumXChaStreamXor(c, m, mlen, npub, k)

  proc crypto_stream_xchacha20_xor_ic*(
      c: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      npub: ptr uint8,
      ic: uint64,
      k: ptr uint8
    ): cint =
    requireLibSodium()
    fnSodiumXChaStreamXorIc(c, m, mlen, npub, ic, k)

  proc crypto_pwhash_alg_default*(): cint =
    requireLibSodium()
    fnSodiumPwhashAlgDefault()

  proc crypto_pwhash_alg_argon2i13*(): cint =
    requireLibSodium()
    fnSodiumPwhashAlgArgon2i13()

  proc crypto_pwhash_alg_argon2id13*(): cint =
    requireLibSodium()
    fnSodiumPwhashAlgArgon2id13()

  proc crypto_pwhash_bytes_min*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashBytesMin()

  proc crypto_pwhash_bytes_max*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashBytesMax()

  proc crypto_pwhash_passwd_min*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashPasswdMin()

  proc crypto_pwhash_passwd_max*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashPasswdMax()

  proc crypto_pwhash_saltbytes*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashSaltbytes()

  proc crypto_pwhash_strbytes*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashStrbytes()

  proc crypto_pwhash_strprefix*(): cstring =
    requireLibSodium()
    fnSodiumPwhashStrprefix()

  proc crypto_pwhash_opslimit_min*(): culonglong =
    requireLibSodium()
    fnSodiumPwhashOpsMin()

  proc crypto_pwhash_opslimit_max*(): culonglong =
    requireLibSodium()
    fnSodiumPwhashOpsMax()

  proc crypto_pwhash_memlimit_min*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashMemMin()

  proc crypto_pwhash_memlimit_max*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashMemMax()

  proc crypto_pwhash_opslimit_interactive*(): culonglong =
    requireLibSodium()
    fnSodiumPwhashOpsInteractive()

  proc crypto_pwhash_memlimit_interactive*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashMemInteractive()

  proc crypto_pwhash_opslimit_moderate*(): culonglong =
    requireLibSodium()
    fnSodiumPwhashOpsModerate()

  proc crypto_pwhash_memlimit_moderate*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashMemModerate()

  proc crypto_pwhash_opslimit_sensitive*(): culonglong =
    requireLibSodium()
    fnSodiumPwhashOpsSensitive()

  proc crypto_pwhash_memlimit_sensitive*(): csize_t =
    requireLibSodium()
    fnSodiumPwhashMemSensitive()

  proc crypto_pwhash*(
      outBuf: ptr uint8,
      outLen: culonglong,
      passwd: cstring,
      passwdLen: culonglong,
      salt: ptr uint8,
      opslimit: culonglong,
      memlimit: csize_t,
      alg: cint
    ): cint =
    requireLibSodium()
    fnSodiumPwhash(outBuf, outLen, passwd, passwdLen, salt, opslimit, memlimit, alg)

  proc crypto_pwhash_str*(
      outBuf: ptr char,
      passwd: cstring,
      passwdLen: culonglong,
      opslimit: culonglong,
      memlimit: csize_t
    ): cint =
    requireLibSodium()
    fnSodiumPwhashStr(outBuf, passwd, passwdLen, opslimit, memlimit)

  proc crypto_pwhash_str_alg*(
      outBuf: ptr char,
      passwd: cstring,
      passwdLen: culonglong,
      opslimit: culonglong,
      memlimit: csize_t,
      alg: cint
    ): cint =
    requireLibSodium()
    fnSodiumPwhashStrAlg(outBuf, passwd, passwdLen, opslimit, memlimit, alg)

  proc crypto_pwhash_str_verify*(
      str: cstring,
      passwd: cstring,
      passwdLen: culonglong
    ): cint =
    requireLibSodium()
    fnSodiumPwhashStrVerify(str, passwd, passwdLen)

  proc crypto_pwhash_str_needs_rehash*(
      str: cstring,
      opslimit: culonglong,
      memlimit: csize_t
    ): cint =
    requireLibSodium()
    fnSodiumPwhashStrNeedsRehash(str, opslimit, memlimit)

  proc crypto_pwhash_primitive*(): cstring =
    requireLibSodium()
    fnSodiumPwhashPrimitive()

  proc sodium_memzero*(pnt: pointer, len: csize_t) =
    requireLibSodium()
    fnSodiumMemzero(pnt, len)

  proc ensureSodiumInitialised*() =
    if sodium_init() == -1:
      raiseOperation("libsodium", "sodium_init failed")

else:
  proc ensureLibSodiumLoaded*(): bool =
    false

  proc sodium_init*(): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_aead_xchacha20poly1305_ietf_keybytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_xchacha20poly1305_ietf_npubbytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_xchacha20poly1305_ietf_nsecbytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_xchacha20poly1305_ietf_messagebytes_max*(): culonglong =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_xchacha20poly1305_ietf_encrypt*(
      c: ptr uint8,
      clen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      nsec: pointer,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_aead_xchacha20poly1305_ietf_decrypt*(
      m: ptr uint8,
      mlen: ptr culonglong,
      nsec: pointer,
      c: ptr uint8,
      clen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_kx_keypair*(pk: ptr uint8, sk: ptr uint8): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_kx_seedbytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_kx_seed_keypair*(pk: ptr uint8, sk: ptr uint8, seed: ptr uint8): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_scalarmult_curve25519_base*(q: ptr uint8, n: ptr uint8): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_scalarmult_curve25519*(q: ptr uint8, n: ptr uint8, p: ptr uint8): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_sign_ed25519_keypair*(pk: ptr uint8, sk: ptr uint8): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_sign_ed25519_detached*(
      sig: ptr uint8,
      siglen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      sk: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_sign_ed25519_verify_detached*(sig: ptr uint8, m: ptr uint8, mlen: culonglong, pk: ptr uint8): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_onetimeauth_poly1305_bytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_onetimeauth_poly1305_keybytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_onetimeauth_poly1305*(
      outBuf: ptr uint8,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_onetimeauth_poly1305_verify*(
      tag: ptr uint8,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_generichash_blake2b*(
      outBuf: ptr uint8,
      outLen: csize_t,
      inBuf: ptr uint8,
      inLen: culonglong,
      key: ptr uint8,
      keyLen: csize_t
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_aead_aes256gcm_is_available*(): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_aead_aes256gcm_keybytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_aes256gcm_npubbytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_aes256gcm_nsecbytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_aes256gcm_messagebytes_max*(): culonglong =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_aead_aes256gcm_encrypt*(
      c: ptr uint8,
      clen: ptr culonglong,
      m: ptr uint8,
      mlen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      nsec: pointer,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_aead_aes256gcm_decrypt*(
      m: ptr uint8,
      mlen: ptr culonglong,
      nsec: pointer,
      c: ptr uint8,
      clen: culonglong,
      ad: ptr uint8,
      adlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_stream_xchacha20_keybytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_stream_xchacha20_noncebytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_stream_xchacha20*(
      c: ptr uint8,
      clen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_stream_xchacha20_xor*(
      c: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      npub: ptr uint8,
      k: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_stream_xchacha20_xor_ic*(
      c: ptr uint8,
      m: ptr uint8,
      mlen: culonglong,
      npub: ptr uint8,
      ic: uint64,
      k: ptr uint8
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_alg_default*(): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_alg_argon2i13*(): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_alg_argon2id13*(): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_bytes_min*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_bytes_max*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_passwd_min*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_passwd_max*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_saltbytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_strbytes*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_strprefix*(): cstring =
    raiseUnavailable("libsodium", "hasLibsodium")
    return ""

  proc crypto_pwhash_opslimit_min*(): culonglong =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_opslimit_max*(): culonglong =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_memlimit_min*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_memlimit_max*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_opslimit_interactive*(): culonglong =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_memlimit_interactive*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_opslimit_moderate*(): culonglong =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_memlimit_moderate*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_opslimit_sensitive*(): culonglong =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash_memlimit_sensitive*(): csize_t =
    raiseUnavailable("libsodium", "hasLibsodium")
    return 0

  proc crypto_pwhash*(
      outBuf: ptr uint8,
      outLen: culonglong,
      passwd: cstring,
      passwdLen: culonglong,
      salt: ptr uint8,
      opslimit: culonglong,
      memlimit: csize_t,
      alg: cint
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_str*(
      outBuf: ptr char,
      passwd: cstring,
      passwdLen: culonglong,
      opslimit: culonglong,
      memlimit: csize_t
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_str_alg*(
      outBuf: ptr char,
      passwd: cstring,
      passwdLen: culonglong,
      opslimit: culonglong,
      memlimit: csize_t,
      alg: cint
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_str_verify*(
      str: cstring,
      passwd: cstring,
      passwdLen: culonglong
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_str_needs_rehash*(
      str: cstring,
      opslimit: culonglong,
      memlimit: csize_t
    ): cint =
    raiseUnavailable("libsodium", "hasLibsodium")
    return -1

  proc crypto_pwhash_primitive*(): cstring =
    raiseUnavailable("libsodium", "hasLibsodium")
    return ""

  proc ensureSodiumInitialised*() =
    raiseUnavailable("libsodium", "hasLibsodium")
