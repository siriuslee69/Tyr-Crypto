## ----------------------------------------------------------
## Zig CC Android AArch64 <- Nim cross compiler wrapper
## ----------------------------------------------------------

import ./zigcc_driver

when isMainModule:
  runZigCc(target = "aarch64-linux-android.24", cacheSuffix = "-android-aarch64")
