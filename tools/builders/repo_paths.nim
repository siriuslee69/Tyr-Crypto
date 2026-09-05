## ------------------------------------------------------------------
## | Builder Paths <- find the repository without counting folders   |
## ------------------------------------------------------------------
##
## Each native-library builder needs the repository root, so it can find
## the pinned source under `submodules/` instead of downloading a fresh
## copy of its own.
##
## Counting folders upwards from the builder's own file is how that used
## to be answered, and it was one short:
##
##   tools/builders/  ->  ..  ->  ..  ->  ..
##      tools/builders    tools    <repo>    <the folder holding the repo>
##                                             ^ answer landed here
##
## Nothing failed. `submodules/libsodium` simply was not found in the
## wrong folder, the builder concluded there was no pinned source, and
## quietly fetched its own - defeating the point of pinning it.
##
## So look instead of counting: walk upwards until a folder holds the
## package file `tyr.nimble`, which sits at the root and nowhere else.

import std/os

const
  packageMarker = "tyr.nimble"
    ## The one file that exists at the repository root and nowhere else.

proc builderRepoRoot*(p: string): string =
  ## p: any path inside the repository, usually `currentSourcePath()`.
  ## Returns the repository root, or an empty string when the caller sits
  ## outside a checkout. Callers treat empty as "no pinned source here"
  ## and fall back to their own fetch, which is the safe direction.
  var
    dir: string = normalizedPath(absolutePath(p))
    parent: string = ""
  if not dirExists(dir):
    dir = parentDir(dir)
  while dir.len > 0:
    if fileExists(joinPath(dir, packageMarker)):
      return dir
    parent = parentDir(dir)
    if parent == dir:
      break
    dir = parent
  result = ""
