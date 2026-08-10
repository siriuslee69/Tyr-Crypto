## --------------------------------------------------------
## Zig CC Linux AArch64 <- Nim cross compiler wrapper
## --------------------------------------------------------

import ./zigcc_driver

when isMainModule:
  when defined(windows):
    runZigCc(target = "aarch64-linux-musl", staticLink = true,
      cacheSuffix = "-aarch64")
  else:
    runZigCc(target = "aarch64-linux-musl", staticLink = true,
      cacheSuffix = "-aarch64", mode = zigPathCompiler)
