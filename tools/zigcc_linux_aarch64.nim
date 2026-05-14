## --------------------------------------------------------
## Zig CC Linux AArch64 <- Nim cross compiler wrapper
## --------------------------------------------------------

import ./zigcc_driver

when isMainModule:
  runZigCc(target = "aarch64-linux-musl", staticLink = true, cacheSuffix = "-aarch64")
