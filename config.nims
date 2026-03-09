# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
import std/[os, strutils]

switch("path", "src")

if dirExists("submodules/simd_nexus/src"):
  switch("path", "submodules/simd_nexus/src")

let nimblePkgs = joinPath(getHomeDir(), ".nimble", "pkgs2")
if dirExists(nimblePkgs):
  for kind, path in walkDir(nimblePkgs):
    if kind == pcDir and path.contains("nimsimd-"):
      let candidate = joinPath(path, "nimsimd")
      if dirExists(candidate):
        switch("path", path.replace('\\', '/'))
        break
