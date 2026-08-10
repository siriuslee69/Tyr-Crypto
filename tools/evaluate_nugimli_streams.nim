## ----------------------------------------------------------------------
## NuGimli Stream Evaluation <- threaded entropy and cross-width campaign
## ----------------------------------------------------------------------

import std/[cpuinfo, os, parseutils, strutils]
import metaPragmas
import ./nugimli_analysis/stream_types
import ./nugimli_analysis/stream_campaign
import ./nugimli_analysis/stream_report

type
  CampaignConfig = object
    threads: int
    baseBlocks: uint64
    routeBlocks: uint64
    quiet: bool

proc parseUintArg(value, label: string): uint64 {.role: {parser}.} =
  ## value/label: unsigned command argument and diagnostic name.
  var
    parsed: BiggestUInt = 0
    consumed: int = 0
  consumed = parseBiggestUInt(value, parsed)
  if consumed != value.len or parsed == 0'u64:
    raise newException(ValueError, label & " must be a positive integer")
  result = uint64(parsed)

proc parseConfig(): CampaignConfig {.role: {parser}.} =
  ## Parse optional quick/block/thread campaign controls.
  var
    i: int = 1
    arg: string = ""
  result.threads = countProcessors()
  result.baseBlocks = defaultBaseBlocks
  result.routeBlocks = defaultRouteBlocks
  while i <= paramCount():
    arg = paramStr(i)
    if arg == "--":
      discard
    elif arg == "--quiet":
      result.quiet = true
    elif arg == "--quick":
      result.baseBlocks = 4_096'u64
      result.routeBlocks = 1_024'u64
    elif arg.startsWith("--threads:"):
      result.threads = int(parseUintArg(arg[10 .. ^1], "threads"))
    elif arg.startsWith("--base-blocks:"):
      result.baseBlocks = parseUintArg(arg[14 .. ^1], "base blocks")
    elif arg.startsWith("--route-blocks:"):
      result.routeBlocks = parseUintArg(arg[15 .. ^1], "route blocks")
    else:
      raise newException(ValueError, "unknown stream campaign argument: " & arg)
    i = i + 1

proc runStreamEvaluation*() {.role: {metaOrchestrator}.} =
  var
    C: CampaignConfig = parseConfig()
    R: StreamCampaignResult
    markdown, csv: string = ""
    markdownPath: string = joinPath("build", "nugimli_stream_campaign.md")
    csvPath: string = joinPath("build", "nugimli_stream_campaign.csv")
  stdout.write("NuGimli stream campaign: threads=" & $C.threads &
    " base_blocks=" & $C.baseBlocks & " route_blocks=" & $C.routeBlocks & "\n")
  R = runStreamCampaign(C.threads, C.baseBlocks, C.routeBlocks)
  markdown = formatStreamReport(R)
  csv = formatStreamCsv(R)
  createDir("build")
  writeFile(markdownPath, markdown)
  writeFile(csvPath, csv)
  if not C.quiet:
    stdout.write(markdown)
  stdout.write("\nMarkdown: " & absolutePath(markdownPath) & "\n")
  stdout.write("CSV: " & absolutePath(csvPath) & "\n")

when isMainModule:
  runStreamEvaluation()
