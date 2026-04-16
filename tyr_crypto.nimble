import std/[os, strutils]

# Package descriptor for the crypto bindings sub-project.

import std/os

version       = "0.1.0"
author        = "siriuslee69"
description   = "Bindings for classical and post-quantum cryptographic primitives."
license       = "Unlicense"
srcDir        = "src"
bin           = @[]
requires "nim >= 1.6.0", "owlkettle >= 3.0.0", "illwill >= 0.4.0", "nimsimd >= 0.4.0"

proc repoNimbleDir(): string =
  result = joinPath(getCurrentDir(), ".nimble_cache")

proc repoNimcacheDir(name: string): string =
  result = joinPath(getCurrentDir(), "build", name)

proc withRepoCaches(cmd: string): string =
  putEnv("NIMBLE_DIR", repoNimbleDir().replace('\\', '/'))
  result = cmd

task check, "Run nim check on core modules":
  exec withRepoCaches("nim check .iron/meta/registry.nim")

task test, "Run the crypto bindings test suite":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test").replace('\\', '/') & " -r tests/test_all.nim")

task test_all, "Run the full crypto bindings test suite with libsodium, liboqs, and OpenSSL":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_all").replace('\\', '/') & " -d:hasLiboqs -d:hasLibsodium -d:hasOpenSSL3 -r tests/test_all.nim")

task test_all_threads_on, "Run test_all with threads enabled":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_all_threads_on").replace('\\', '/') & " --gc:orc --threads:on -d:hasLiboqs -d:hasLibsodium -d:hasOpenSSL3 -r tests/test_all.nim")

task test_all_threads_off, "Run test_all with threads disabled":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_all_threads_off").replace('\\', '/') & " --gc:orc --threads:off -d:hasLiboqs -d:hasLibsodium -d:hasOpenSSL3 -r tests/test_all.nim")

task test_gimli, "Run Gimli SSE tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli").replace('\\', '/') & " -r tests/test_gimli_sse.nim")

task test_gimli_avx, "Run Gimli AVX tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_gimli_avx").replace('\\', '/') & " --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r tests/test_gimli_sse.nim")

task test_blake3_simd, "Run Blake3 SIMD tests":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_blake3_simd").replace('\\', '/') & " --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r tests/test_blake3_simd.nim")

task test_wasm, "Run wasm bridge regression tests":
  exec withRepoCaches("nim c -r --nimcache:" & repoNimcacheDir("nimcache_wasm_test").replace('\\', '/') & " tests/test_wasm_bridge.nim")

task test_pin, "Run interactive pin + key unwrap test.":
  exec withRepoCaches("nim c --nimcache:" & repoNimcacheDir("nimcache_test_pin").replace('\\', '/') & " -d:hasLibsodium -r tests/test_pin_key_interactive.nim")

task perf_sigma, "Benchmark custom crypto with Sigma helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma").replace('\\', '/') & " --path:src --path:submodules/sigma_bench_and_eval/src --path:submodules/sigma_bench_and_eval/submodules/fylgia/src -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf.nim")

task perf_sigma_pq, "Benchmark Tyr PQ backends against liboqs with Sigma helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_pq").replace('\\', '/') & " --path:src --path:submodules/sigma_bench_and_eval/src --path:submodules/sigma_bench_and_eval/submodules/fylgia/src -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_pq.nim")

task perf_sigma_kyber, "Benchmark Tyr Kyber against liboqs with Sigma helpers":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_kyber").replace('\\', '/') & " --path:src --path:submodules/sigma_bench_and_eval/src --path:submodules/sigma_bench_and_eval/submodules/fylgia/src -d:release -d:hasLibOqs -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_kyber_only.nim")

task perf_sigma_pq_aesni, "Benchmark Tyr PQ backends against liboqs with Sigma helpers and AES-NI enabled":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_pq_aesni").replace('\\', '/') & " --path:src --path:submodules/sigma_bench_and_eval/src --path:submodules/sigma_bench_and_eval/submodules/fylgia/src -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_pq.nim")

task perf_sigma_frodo_portable, "Benchmark Tyr Frodo against the portable Frodo-focused liboqs build":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_portable"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_frodo_portable").replace('\\', '/') & " --path:src --path:submodules/sigma_bench_and_eval/src --path:submodules/sigma_bench_and_eval/submodules/fylgia/src -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_frodo_profile.nim")

task perf_sigma_frodo_ossl, "Benchmark Tyr Frodo against the OpenSSL-backed Frodo-focused liboqs build":
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_ossl"))
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_sigma_frodo_ossl").replace('\\', '/') & " --path:src --path:submodules/sigma_bench_and_eval/src --path:submodules/sigma_bench_and_eval/submodules/fylgia/src -d:release -d:hasLibOqs -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf_frodo_profile.nim")

task perf_otter_pq, "Profile Tyr PQ functions with Otter timing instrumentation":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_otter_pq").replace('\\', '/') & " --path:src --path:../Otter-RepoEvaluation/src -d:release -d:otterTiming -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_otter_perf_pq.nim")

task perf_otter_kyber, "Profile Tyr Kyber functions with Otter timing instrumentation":
  exec withRepoCaches("nim c --threads:on --nimcache:" & repoNimcacheDir("nimcache_perf_otter_kyber").replace('\\', '/') & " --path:src --path:../Otter-RepoEvaluation/src -d:release -d:otterTiming -d:sse2 -d:avx2 -d:aesni --passC:\"-msse4.1 -mavx2 -maes\" --passL:\"-msse4.1 -mavx2\" -r tests/test_otter_perf_kyber_only.nim")


task build_libsodium, "Build libsodium and prepare combined headers":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_libsodium.nim"
  exec "nim r tools/prepare_libsodium_header.nim"

task build_liboqs, "Build liboqs and prepare combined headers":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_liboqs_frodo_portable, "Build a portable Frodo-focused liboqs profile with OpenSSL disabled":
  putEnv("LIBOQS_PROFILE_NAME", "frodo_portable")
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_portable"))
  putEnv("LIBOQS_USE_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_AES_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA2_OPENSSL", "OFF")
  putEnv("LIBOQS_USE_SHA3_OPENSSL", "OFF")
  putEnv("LIBOQS_DIST_BUILD", "OFF")
  putEnv("LIBOQS_OPT_TARGET", "generic")
  putEnv("LIBOQS_MINIMAL_BUILD", "KEM_frodokem_976_aes")
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_liboqs_frodo_ossl, "Build an OpenSSL-backed Frodo-focused liboqs profile":
  putEnv("LIBOQS_PROFILE_NAME", "frodo_ossl")
  putEnv("LIBOQS_BUILD_ROOT", joinPath(getCurrentDir(), "build", "liboqs_frodo_ossl"))
  putEnv("LIBOQS_USE_OPENSSL", "ON")
  putEnv("LIBOQS_USE_AES_OPENSSL", "ON")
  putEnv("LIBOQS_USE_SHA2_OPENSSL", "ON")
  putEnv("LIBOQS_USE_SHA3_OPENSSL", "OFF")
  putEnv("LIBOQS_DIST_BUILD", "ON")
  putEnv("LIBOQS_OPT_TARGET", "auto")
  putEnv("LIBOQS_MINIMAL_BUILD", "KEM_frodokem_976_aes")
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_openssl, "Build OpenSSL":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_openssl.nim"

task build_wasm, "Build JS/TS wasm bindings with Emscripten":
  exec "nim r --nimcache:build/nimcache_build_wasm tools/build_wasm.nim"

task build_wasm_debug, "Build debug JS/TS wasm bindings with Emscripten":
  exec "nim r --nimcache:build/nimcache_build_wasm tools/build_wasm.nim -- --debug"

task autopush, "Add, commit, and push with message from .iron/PROGRESS.md":
  let candidatePaths = @[".iron/PROGRESS.md", ".iron/progress.md", "iron/progress.md"]
  var path = ""
  var msg = ""
  var i = 0
  var l = candidatePaths.len
  while i < l:
    if fileExists(candidatePaths[i]):
      path = candidatePaths[i]
      break
    inc i
  if path.len > 0:
    let content = readFile(path)
    for line in content.splitLines:
      if line.startsWith("Commit Message:"):
        msg = line["Commit Message:".len .. ^1].strip()
        break
  if msg.len == 0:
    msg = "No specific commit message given."
  exec "git add -A ."
  exec "git commit -m \"" & msg & "\""
  exec "git push"

task find, "Use local clones for submodules in parent folder":
  let modulesPath = ".gitmodules"
  if not fileExists(modulesPath):
    echo "No .gitmodules found."
  else:
    let root = parentDir(getCurrentDir())
    var current = ""
    for line in readFile(modulesPath).splitLines:
      let s = line.strip()
      if s.startsWith("[submodule"):
        let start = s.find('"')
        let stop = s.rfind('"')
        if start >= 0 and stop > start:
          current = s[start + 1 .. stop - 1]
      elif current.len > 0 and s.startsWith("path"):
        let parts = s.split("=", maxsplit = 1)
        if parts.len == 2:
          let subPath = parts[1].strip()
          let tail = splitPath(subPath).tail
          let localDir = joinPath(root, tail)
          if dirExists(localDir):
            let localUrl = localDir.replace('\\', '/')
            exec "git config -f .gitmodules submodule." & current & ".url " & localUrl
            exec "git config submodule." & current & ".url " & localUrl
    exec "git submodule sync --recursive"



