## ---------------------------------------------------------------------
## | Example Tests <- every file in examples/ must actually compile      |
## ---------------------------------------------------------------------
##
## The examples are the first Tyr code anyone reads, and nothing else in
## the suite touches them. Every one of them was broken at some point
## without a single test noticing: they imported a module that had been
## renamed, called procs that no longer existed, and used a byte-literal
## form that never compiled at all.
##
## This walks `examples/` rather than listing files, so a new example is
## covered the moment it is added.

import std/[algorithm, os, osproc, strutils, unittest]

proc repoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc exampleFiles(): seq[string] =
  var dir: string = joinPath(repoRoot(), "examples")
  result = @[]
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".nim"):
      result.add(path)
  result.sort()

suite "examples":

  test "the examples directory is not empty":
    ## Guards against this whole suite silently passing because a path
    ## changed and the walk found nothing.
    check exampleFiles().len > 0

  test "every example compiles against the current API":
    var
      failures: seq[string] = @[]
      res: tuple[output: string, exitCode: int]
      cache: string = ""
    for path in exampleFiles():
      cache = joinPath(repoRoot(), "build",
        "nimcache_example_" & splitFile(path).name)
      res = execCmdEx("nim check --hints:off --path:" &
        quoteShell(joinPath(repoRoot(), "src")) &
        " --nimcache:" & quoteShell(cache) & " " & quoteShell(path))
      if res.exitCode != 0:
        failures.add(extractFilename(path) & ":\n" & res.output.strip())
    if failures.len > 0:
      checkpoint("examples that do not compile:\n" & failures.join("\n\n"))
    check failures.len == 0
