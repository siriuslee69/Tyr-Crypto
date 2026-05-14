## -----------------------------------------------------
## Zig CC Wrapper <- generic Nim Zig C compiler launcher
## -----------------------------------------------------

import ./zigcc_driver

when isMainModule:
  runZigCc(mode = zigPathCompiler, cacheSuffix = "")
