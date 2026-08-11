## --------------------------------------------------------------------
## NuGimli Stream Campaign Tests <- route matrix and threaded quick run
## --------------------------------------------------------------------

import std/unittest
import ./nugimli_analysis/stream_types
import ./nugimli_analysis/stream_campaign

suite "nugimli stream campaign":
  test "builds every direct and three-width route combination":
    var
      J: seq[StreamJob] = buildStreamJobs(64'u64, 64'u64)
      direct, routes: int = 0
    check J.len == 1_008
    for job in J:
      if job.mode == smCrossWidth:
        routes = routes + 1
      else:
        direct = direct + 1
    check direct == 36
    check routes == 972

  test "width adapters preserve their declared behavior":
    var
      source, zeroPad, repeated, folded: WideState
      i: int = 0
    source.wordCount = 16
    i = 0
    while i < source.wordCount:
      source.words[i] = uint32(i + 1)
      i = i + 1
    zeroPad = adaptState(source, 64, amZeroPadTruncate, 1'u32)
    repeated = adaptState(source, 64, amRepeat, 1'u32)
    folded = adaptState(source, 64, amXorFoldDomain, 1'u32)
    check zeroPad.words[15] == 16'u32
    check zeroPad.words[16] == 0'u32
    check repeated.words[16] == 1'u32
    check folded.words[16] != 0'u32

  test "threaded quick matrix returns every checkpoint":
    var
      R: StreamCampaignResult = runStreamCampaign(4, 64'u64, 64'u64)
      i, finalRows: int = 0
    check R.threads == 4
    check R.checkpoints.len == 5_940
    i = 0
    while i < R.checkpoints.len:
      if R.checkpoints[i].intervalEnd == 64'u64:
        finalRows = finalRows + 1
        check R.checkpoints[i].sampledBytes > 0'u64
        check R.checkpoints[i].shannonEntropy > 0.0
      i = i + 1
    check finalRows == 2_952
