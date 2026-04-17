## ---------------------------------------------------------
## Otter Support <- optional no-op bridge to Otter timings
## ---------------------------------------------------------

when defined(otterTiming):
  import otter_repo_evaluation
  export otter_repo_evaluation
else:
  template otterSpan*(n: string, body: untyped): untyped =
    body

  macro otterTimed*(body: untyped): untyped =
    result = body

  macro otterInstrument*(body: untyped): untyped =
    result = body

  macro otterBench*(body: untyped): untyped =
    result = body
