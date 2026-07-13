## ---------------------------------------------------------
## WebUI Wasm Stager <- copies the generated bridge to tests
## ---------------------------------------------------------

import std/[os, strutils]

import ../.iron/meta/metaPragmas

const
  sourceDir = "bindings/js"
  targetDir = "tests/webui_interop/web/wasm"

proc copyDirectoryContents(source, target: string) {.role: {dataWriter}.} =
  ## Copies one generated bridge directory into the WebUI asset root.
  var name: string = ""
  if not dirExists(source):
    raise newException(IOError, "missing generated WASM bridge directory: " & source)
  createDir(target)
  for path in walkDirRec(source):
    name = relativePath(path, source)
    if dirExists(path):
      createDir(target / name)
    else:
      createDir((target / name).parentDir)
      copyFile(path, target / name)

proc writeBrowserModuleAliases(target: string) {.role: {dataWriter}.} =
  ## Writes .js aliases because WebUI serves .mjs files as generic binary data.
  var
    loader: string = readFile(target / "tyr_crypto.mjs")
  loader = loader.replace("./dist/tyr_crypto_wasm.mjs", "./dist/tyr_crypto_wasm.js")
  writeFile(target / "tyr_crypto.js", loader)
  copyFile(target / "dist" / "tyr_crypto_wasm.mjs",
    target / "dist" / "tyr_crypto_wasm.js")

proc main() {.role: {orchestrator}.} =
  ## Refreshes the dashboard-local bridge with the newly built WASM output.
  copyDirectoryContents(sourceDir, targetDir)
  writeBrowserModuleAliases(targetDir)

when isMainModule:
  main()
