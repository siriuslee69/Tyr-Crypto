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

task check, "Run nim check on core modules":
  exec "nim check src/tyr_crypto/registry.nim"

task test, "Run the crypto bindings test suite":
  exec "nim c -r tests/test_all.nim"

task test_all, "Run the full crypto bindings test suite with libsodium, liboqs, and OpenSSL":
  exec "nim c -d:hasLiboqs -d:hasLibsodium -d:hasOpenSSL3 -r tests/test_all.nim"

task test_all_threads_on, "Run test_all with threads enabled":
  exec "nim c --gc:orc --threads:on -d:hasLiboqs -d:hasLibsodium -d:hasOpenSSL3 -r tests/test_all.nim"

task test_all_threads_off, "Run test_all with threads disabled":
  exec "nim c --gc:orc --threads:off -d:hasLiboqs -d:hasLibsodium -d:hasOpenSSL3 -r tests/test_all.nim"

task test_gimli, "Run Gimli SSE tests":
  exec "nim c -r tests/test_gimli_sse.nim"

task test_gimli_avx, "Run Gimli AVX tests":
  exec "nim c --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r tests/test_gimli_sse.nim"

task test_blake3_simd, "Run Blake3 SIMD tests":
  exec "nim c --passC:\"-mavx2\" --passL:\"-mavx2\" -d:avx2 -r tests/test_blake3_simd.nim"

task test_pin, "Run interactive pin + key unwrap test.":
  exec "nim c -d:hasLibsodium -r tests/test_pin_key_interactive.nim"

task perf_sigma, "Benchmark custom crypto with Sigma helpers":
  exec "nim c --threads:on --path:src --path:submodules/sigma_bench_and_eval/src --path:submodules/sigma_bench_and_eval/fylgia/src -d:release -d:sse2 -d:avx2 --passC:\"-msse4.1 -mavx2\" --passL:\"-msse4.1 -mavx2\" -r tests/test_sigma_perf.nim"


task build_libsodium, "Build libsodium and prepare combined headers":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_libsodium.nim"
  exec "nim r tools/prepare_libsodium_header.nim"

task build_liboqs, "Build liboqs and prepare combined headers":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_liboqs.nim"
  exec "nim r tools/prepare_liboqs_header.nim"

task build_openssl, "Build OpenSSL":
  exec "nim r tools/ensure_env.nim -- --submodules --builddirs"
  exec "nim r tools/build_openssl.nim"

task autopush, "Add, commit, and push with message from iron/progress.md":
  let path = "iron/progress.md"
  var msg = ""
  if fileExists(path):
    let content = readFile(path)
    for line in content.splitLines:
      if line.startsWith("Commit Message:"):
        msg = line["Commit Message:".len .. ^1].strip()
        break
  if msg.len == 0:
    msg = "No specific commit message given."
  exec "git add -A ."
  exec "git commit -m \" " & msg & "\""
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



