## -------------------------------------------------------
## Zig CC Linux x86_64 <- Nim cross compiler wrapper
## -------------------------------------------------------

import ./zigcc_driver

when isMainModule:
  when defined(windows):
    runZigCc(target = "x86_64-linux-musl", staticLink = true,
      cacheSuffix = "-x86_64")
  else:
    runZigCc(target = "x86_64-linux-musl", staticLink = true,
      cacheSuffix = "-x86_64", mode = zigPathCompiler)
