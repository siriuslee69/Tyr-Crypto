# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
import std/[os, strutils]

let repoRoot = thisDir()

proc addPathIfExists(pathArg: string) =
  if dirExists(pathArg):
    switch("path", pathArg.replace('\\', '/'))

addPathIfExists(joinPath(repoRoot, "src"))
addPathIfExists(joinPath(repoRoot, ".iron", "meta"))
addPathIfExists(joinPath(repoRoot, "submodules", "simd_nexus", "src"))
addPathIfExists(joinPath(repoRoot, "..", "SIMD-Nexus", "src"))
addPathIfExists(joinPath(repoRoot, "..", "Fylgia-Utils", "src"))
addPathIfExists(joinPath(repoRoot, "..", "Otter-RepoEvaluation", "src"))
addPathIfExists(joinPath(repoRoot, "..", "Sigma-BenchAndEval", "src"))

let nimblePkgs = joinPath(getHomeDir(), ".nimble", "pkgs2")
if dirExists(nimblePkgs):
  for kind, path in walkDir(nimblePkgs):
    if kind == pcDir and path.contains("nimsimd-"):
      let candidate = joinPath(path, "nimsimd")
      if dirExists(candidate):
        switch("path", path.replace('\\', '/'))
        break
