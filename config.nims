# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
import std/[os, strutils]

const
  tyrCapabilityOverride = "tyrExplicitCapabilities"

var
  repoRoot: string = thisDir()

proc addPathIfExists(pathArg: string) =
  if dirExists(pathArg):
    switch("path", pathArg.replace('\\', '/'))

include "tyr_simd.nims"

proc applyTyrBuildDefaults() =
  ## Tyr on its own defaults to `native`: its tests and benchmarks run on
  ## the machine that builds them. -d:tyrExplicitCapabilities (or an Otter
  ## UI target) means "I pass the capability defines myself" and makes the
  ## default `scalar`. An explicit -d:tyrSimd= always wins; see tyr_simd.nims.
  var
    fallback: string = "native"
  if tyrSimdOption("opt").len == 0:
    switch("opt", "speed")
  if tyrSimdDefine(tyrCapabilityOverride).len > 0 or
      tyrSimdDefine("OtterUiTarget").len > 0:
    fallback = "scalar"
  applyTyrSimd(fallback)

addPathIfExists(joinPath(repoRoot, "src"))
addPathIfExists(joinPath(repoRoot, "tools", "meta"))
addPathIfExists(joinPath(repoRoot, "tools"))
addPathIfExists(joinPath(repoRoot, "submodules", "simd_nexus", "src"))
addPathIfExists(joinPath(repoRoot, "..", "SIMD-Nexus", "src"))
addPathIfExists(joinPath(repoRoot, "..", "Fylgia-Utils", "src"))
if dirExists(joinPath(repoRoot, "..", "Otter-RepoEvaluation", "src")):
  addPathIfExists(joinPath(repoRoot, "..", "Otter-RepoEvaluation", "src"))
else:
  addPathIfExists(joinPath(repoRoot, "submodules", "otter_repo_evaluation", "src"))

var nimblePkgs: string = joinPath(getHomeDir(), ".nimble", "pkgs2")
if dirExists(nimblePkgs):
  for kind, path in walkDir(nimblePkgs):
    if kind == pcDir and path.contains("nimsimd-"):
      var candidate: string = joinPath(path, "nimsimd")
      if dirExists(candidate):
        switch("path", path.replace('\\', '/'))
        break

applyTyrBuildDefaults()

## Shared pragma module: one file for the whole workspace, so there is no
## per-repository copy to drift or to collide on the Nim path.
if dirExists(thisDir() & "/../Rune-Pragmas/meta"):
  switch("path", thisDir() & "/../Rune-Pragmas/meta")
if dirExists(thisDir() & "/submodules/Rune-Pragmas/meta"):
  switch("path", thisDir() & "/submodules/Rune-Pragmas/meta")
