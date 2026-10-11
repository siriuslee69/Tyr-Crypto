## --------------------------------------------------------------------
## NuGimli Types <- the three widths and contiguous 128-bit chunk swaps
## --------------------------------------------------------------------
##
##   state      bits   32-bit words (N)   chunks (4 words)   rounds
##   ---------  -----  -----------------  -----------------  ------
##   NuGimli512   512   16                 4                  24
##   NuGimli1024 1024   32                 8                  28
##   NuGimli2048 2048   64                 16                 32
##
## Every routine is generic over N, so one name serves all three widths
## and a fourth width fails to compile instead of failing at run time.

import runePragmas

const
  nugimliChunkWords* = 4
  cascadeRoundDomain* = 0x43415343'u32

type
  NuGimli512* = array[16, uint32]
  NuGimli1024* = array[32, uint32]
  NuGimli2048* = array[64, uint32]

func cascadeRounds*(N: int): int {.role: {parser}.} =
  ## N: state width in 32-bit words. Returns its round count, or 0 for a
  ## width Cascade does not define.
  case N
  of 16: 24
  of 32: 28
  of 64: 32
  else: 0

template requireCascadeWidth*(N: static[int]) =
  ## Stops the build for a state that is not 512, 1024 or 2048 bits.
  when cascadeRounds(N) == 0:
    {.error: "Cascade state must be 512, 1024, or 2048 bits".}

proc swapChunkBlocks*[N: static[int]](S: var array[N, uint32], a, b,
    c: int) {.role: {helper}.} =
  ## S: state whose contiguous 128-bit chunks are exchanged.
  ## a/b: first chunk index of each block. c: chunks in each block.
  var
    i: int = 0
  if a == b:
    return
  if c <= 0 or a < 0 or b < 0 or a + c > N div nugimliChunkWords or
      b + c > N div nugimliChunkWords:
    raise newException(ValueError, "NuGimli chunk swap is outside the state")
  if a < b + c and b < a + c:
    raise newException(ValueError, "NuGimli chunk swap blocks overlap")
  while i < c * nugimliChunkWords:
    swap(S[a * nugimliChunkWords + i], S[b * nugimliChunkWords + i])
    i = i + 1
