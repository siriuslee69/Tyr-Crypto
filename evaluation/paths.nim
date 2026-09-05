## -------------------------------------------------------------------
## | Evaluation Paths <- find the repository without counting folders |
## -------------------------------------------------------------------
##
## Every test, benchmark, and statistic needs to know two places: where
## the repository starts, and where its own results belong.
##
## The old way of answering the first question was to count folders
## upwards from the source file:
##
##   parentDir(parentDir(currentSourcePath()))
##                ^          ^
##                |          +-- one folder up
##                +------------- two folders up
##
## That answer is only right for a file sitting at one exact depth. Move
## the file one folder deeper and the count silently points at the wrong
## place - it does not fail, it just starts describing a folder that is
## not the repository. This repository has already been bitten by that:
## a check walked a folder that no longer existed and reported success
## on nothing at all.
##
## So instead of counting, we look. Walk upwards until a folder holds
## the package file `tyr.nimble`, which by definition sits at the root
## and nowhere else:
##
##   evaluation/tests/webui_interop/test_jobs.nim
##   evaluation/tests/webui_interop/          no tyr.nimble -> keep going
##   evaluation/tests/                        no tyr.nimble -> keep going
##   evaluation/                              no tyr.nimble -> keep going
##   <repository root>                        tyr.nimble    -> stop
##
## A file can now be moved anywhere below the root and still find it.

import std/os

import metaPragmas

const
  packageMarker = "tyr.nimble"
    ## The one file that exists at the repository root and nowhere else.

proc repoRootFrom*(p: string): string {.role: {parser}.} =
  ## p: any path inside the repository, usually `currentSourcePath()`.
  ## Returns the repository root. Raises when called from outside it,
  ## because every caller here uses the answer to open a file and a
  ## wrong-but-plausible folder is worse than a stop.
  var
    dir: string = p
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
  raise newException(IOError,
    "no " & packageMarker & " above " & p & "; not inside the repository")

proc evaluationRoot*(p: string): string {.role: {parser}.} =
  ## p: any path inside the repository, usually `currentSourcePath()`.
  ## Returns `evaluation/`, where tests, benchmarks, and statistics live.
  result = joinPath(repoRootFrom(p), "evaluation")

proc testsRootFrom*(p: string): string {.role: {parser}.} =
  ## p: any path inside the repository, usually `currentSourcePath()`.
  ## Returns `evaluation/tests/`. Run output goes somewhere below here,
  ## never beside the source it was produced from.
  result = joinPath(evaluationRoot(p), "tests")
