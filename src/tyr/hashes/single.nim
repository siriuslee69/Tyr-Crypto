## ---------------------------------------------------------------------
## | Hash Single <- compile exactly ONE hash family, by build flag      |
## ---------------------------------------------------------------------
##
##   -d:tyrHashBlake3   ->  blake3Hash(data, outLen)
##   -d:tyrHashSha256   ->  sha256Hash(data)
##   -d:tyrHashSha512   ->  sha512Hash(data)
##   -d:tyrHashSha3     ->  sha3Hash(data, outLen)

import ./types
export types

when defined(tyrHashBlake3):
  when defined(tyrHashSha256) or defined(tyrHashSha512) or defined(tyrHashSha3):
    {.error: "pick only one -d:tyrHash... flag".}
  import ./blake3
  export blake3
elif defined(tyrHashSha256):
  when defined(tyrHashSha512) or defined(tyrHashSha3):
    {.error: "pick only one -d:tyrHash... flag".}
  import ./sha256
  export sha256
elif defined(tyrHashSha512):
  when defined(tyrHashSha3):
    {.error: "pick only one -d:tyrHash... flag".}
  import ./sha512
  export sha512
elif defined(tyrHashSha3):
  import ./sha3
  export sha3
else:
  {.error: "tyr/hashes/single needs one -d:tyrHash... flag " &
    "(tyrHashBlake3, tyrHashSha256, tyrHashSha512, tyrHashSha3). " &
    "For every family at once use `import tyr/hashes` instead.".}
