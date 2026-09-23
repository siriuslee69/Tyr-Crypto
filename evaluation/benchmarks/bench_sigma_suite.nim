suite "Sigma performance":
  test "compare crypto throughput over several thousand loops":
    initBenchData()

    when compileOption("threads"):
      var
        jobs = makeJobs()
        threads: seq[Thread[ptr BenchJob]] = @[]
      threads.setLen(jobs.len)
      var i: int = 0
      i = 0
      while i < jobs.len:
        createThread(threads[i], benchThread, addr jobs[i])
        i = i + 1
      i = 0
      while i < threads.len:
        joinThread(threads[i])
        i = i + 1

      var results: seq[BenchResult] = @[]
      results.setLen(jobs.len)
      i = 0
      while i < jobs.len:
        results[i] = BenchResult(
          name: algoNames[jobs[i].algo],
          loops: loops,
          totalTicks: jobs[i].totalTicks,
          avgTicks: jobs[i].avgTicks
        )
        i = i + 1
      check results.len == jobs.len
      for r in results:
        check r.loops == loops
        check r.totalTicks > 0
        check r.avgTicks >= 0
      echo formatBenchResults(results)
    else:
      var algos: seq[BenchAlgo] = @[]
      for job in makeJobs():
        var k = job.algo
        algos.add(BenchAlgo(name: algoNames[k], run: proc() =
          runAlgo(k)
        ))
      var results = compareAlgorithms(algos, loops = loops, warmup = 100)
      check results.len == algos.len
      for r in results:
        check r.loops == loops
        check r.totalTicks > 0
        check r.avgTicks >= 0
      echo formatBenchResults(results)
