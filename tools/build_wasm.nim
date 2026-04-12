## ---------------------------------------------------------
## Wasm Builder <- Nim C generation + Emscripten link stage
## ---------------------------------------------------------

import std/[algorithm, os, osproc, sequtils, strutils]

const
  wasmSource = "src/tyr_crypto/wasm/exports.nim"
  wasmBuildDir = "build/wasm"
  wasmNimcacheDir = "build/wasm/nimcache"
  wasmOutputDir = "bindings/js/dist"
  wasmOutputFile = "bindings/js/dist/tyr_crypto_wasm.mjs"

type
  BuildOptions = object
    release: bool
    nimFlags: seq[string]
    emccFlags: seq[string]

proc quoted(args: seq[string]): string =
  result = args.mapIt(quoteShell(it)).join(" ")

proc runStep(exe: string, args: seq[string]) =
  let cmd = quoteShell(exe) & " " & quoted(args)
  echo cmd
  let run = execCmdEx(cmd,
    options = {poStdErrToStdOut, poUsePath},
    workingDir = getCurrentDir())
  if run.output.len > 0:
    echo run.output
  if run.exitCode != 0:
    quit("command failed: " & cmd)

proc parseArgs(): BuildOptions =
  var
    args = commandLineParams()
    i: int = 0
  result.release = true
  i = 0
  while i < args.len:
    case args[i]
    of "--debug":
      result.release = false
    of "--nim-flag":
      if i + 1 >= args.len:
        quit("missing value after --nim-flag")
      result.nimFlags.add(args[i + 1])
      i = i + 1
    of "--emcc-flag":
      if i + 1 >= args.len:
        quit("missing value after --emcc-flag")
      result.emccFlags.add(args[i + 1])
      i = i + 1
    else:
      if args[i].startsWith("--nim-flag:"):
        result.nimFlags.add(args[i]["--nim-flag:".len .. ^1])
      elif args[i].startsWith("--emcc-flag:"):
        result.emccFlags.add(args[i]["--emcc-flag:".len .. ^1])
      else:
        quit("unsupported argument: " & args[i])
    i = i + 1

proc nimLibDir(): string =
  var
    envLibDir = getEnv("NIM_LIB_DIR")
    nimExe = ""
    nimBinDir = ""
    nimRootDir = ""
  if envLibDir.len > 0 and dirExists(envLibDir):
    return envLibDir
  nimExe = findExe("nim")
  if nimExe.len == 0:
    quit("nim was not found on PATH")
  nimBinDir = parentDir(nimExe)
  nimRootDir = parentDir(nimBinDir)
  result = joinPath(nimRootDir, "lib")
  if not dirExists(result):
    quit("could not locate Nim lib directory; set NIM_LIB_DIR")

proc collectGeneratedCFiles(dir: string): seq[string] =
  for path in walkFiles(joinPath(dir, "*.c")):
    result.add(path)
  result.sort()
  if result.len == 0:
    quit("no generated C files found under " & dir)

proc exportedFunctionsArg(): string =
  let funcs = @[
    "_tyr_wasm_abi_version",
    "_tyr_wasm_capabilities_json",
    "_tyr_wasm_encrypt_json",
    "_tyr_wasm_decrypt_json",
    "_tyr_wasm_blake3_hash_json",
    "_tyr_wasm_blake3_keyed_hash_json"
  ]
  result = "['" & funcs.join("','") & "']"

proc runtimeMethodsArg(): string =
  result = "['ccall']"

proc ensureTooling() =
  if findExe("emcc").len == 0:
    quit("emcc was not found on PATH. Install emsdk and expose emcc before running build_wasm.")

proc main() =
  let options = parseArgs()
  ensureTooling()
  createDir(wasmBuildDir)
  createDir(wasmNimcacheDir)
  createDir(wasmOutputDir)

  var
    nimArgs: seq[string] = @[
      "c",
      "--compileOnly",
      "--noMain",
      "--app:lib",
      "--gc:orc",
      "--threads:off",
      "--nimcache:" & wasmNimcacheDir
    ]
  if options.release:
    nimArgs.add("-d:release")
  nimArgs.add(options.nimFlags)
  nimArgs.add(wasmSource)
  runStep("nim", nimArgs)

  let cFiles = collectGeneratedCFiles(wasmNimcacheDir)
  let libDir = nimLibDir()
  var
    emccArgs: seq[string] = @[]
  emccArgs.add(cFiles)
  emccArgs.add("-I" & wasmNimcacheDir)
  emccArgs.add("-I" & libDir)
  if options.release:
    emccArgs.add("-O3")
  else:
    emccArgs.add("-O0")
    emccArgs.add("-g")
    emccArgs.add("-sASSERTIONS=1")
  emccArgs.add(@[
    "-sWASM=1",
    "-sMODULARIZE=1",
    "-sEXPORT_ES6=1",
    "-sALLOW_MEMORY_GROWTH=1",
    "-sFILESYSTEM=0",
    "-sNO_EXIT_RUNTIME=1",
    "-sENVIRONMENT=web,worker,node",
    "-sEXPORTED_FUNCTIONS=" & exportedFunctionsArg(),
    "-sEXPORTED_RUNTIME_METHODS=" & runtimeMethodsArg()
  ])
  emccArgs.add(options.emccFlags)
  emccArgs.add(@["-o", wasmOutputFile])
  runStep("emcc", emccArgs)

when isMainModule:
  main()
